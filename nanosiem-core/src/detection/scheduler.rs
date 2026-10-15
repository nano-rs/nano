// SPDX-License-Identifier: AGPL-3.0-or-later

//! Detection Rule Scheduling Utilities
//!
//! Provides cron expression parsing, validation, and the deterministic per-rule
//! phase offset
//! used by the distributed detection scheduler.

use chrono::{DateTime, Duration, Utc};
use cron::Schedule;
use std::str::FromStr;
use tracing::{debug, warn};
use uuid::Uuid;

use super::error::DetectionError;

/// Calculate the next run time based on a cron expression
///
/// Supports both 5-field (min hour day month weekday) and 6-field (sec min hour day month weekday) formats.
/// 5-field expressions are automatically converted to 6-field by prepending "0 ".
fn calculate_next_run(cron: &str, from: DateTime<Utc>) -> DateTime<Utc> {
    // Normalize to 6-field format if needed
    let normalized = normalize_cron_expression(cron);

    match Schedule::from_str(&normalized) {
        Ok(schedule) => {
            // Get the next occurrence after 'from'
            schedule
                .after(&from)
                .next()
                .unwrap_or_else(|| from + Duration::hours(1))
        }
        Err(e) => {
            warn!(
                "Failed to parse cron expression '{}': {}. Defaulting to 1 hour.",
                cron, e
            );
            from + Duration::hours(1)
        }
    }
}

/// Default hard cap on a rule's phase offset (seconds). Override with
/// `NRT_PHASE_MAX_SECS`. A daily 09:00 rule therefore runs by ~09:05: the cron
/// keeps both the cadence and the approximate wall-clock time; the offset only
/// spreads load.
pub const DEFAULT_PHASE_CAP_SECS: u64 = 300;

/// Process-wide phase cap: `NRT_PHASE_MAX_SECS`, else [`DEFAULT_PHASE_CAP_SECS`].
/// Rule create/update paths use this so a rule's first run lands on the same
/// phase grid the scheduler keeps it on afterwards.
pub fn configured_phase_cap_secs() -> u64 {
    static CAP: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *CAP.get_or_init(|| {
        std::env::var("NRT_PHASE_MAX_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_PHASE_CAP_SECS)
    })
}

/// Fraction of the schedule interval a phase offset may occupy (50%).
const PHASE_INTERVAL_FRACTION_DIVISOR: i64 = 2;

/// Smallest gap between consecutive ticks of `cron` near `from`, if the cron
/// parses and has at least two upcoming ticks. Regular crons (`*/5`) return the
/// exact period; irregular ones (`0 9,17 * * *`) return their tightest gap so
/// the offset can never push a run into the next tick.
pub fn schedule_interval(cron: &str, from: DateTime<Utc>) -> Option<Duration> {
    let schedule = Schedule::from_str(&normalize_cron_expression(cron)).ok()?;
    let ticks: Vec<DateTime<Utc>> = schedule.after(&from).take(8).collect();
    ticks
        .windows(2)
        .map(|pair| pair[1] - pair[0])
        .filter(|gap| *gap > Duration::zero())
        .min()
}

/// Stable 64-bit mix of the whole rule id (splitmix64 finalizer over both
/// halves). The previous jitter used only the first 8 bytes, which for UUIDv7
/// are the creation timestamp — a bulk import minted in one burst clustered.
fn rule_phase_hash(rule_id: Uuid) -> u64 {
    let v = rule_id.as_u128();
    let mut z = (v as u64) ^ ((v >> 64) as u64).rotate_left(29);
    z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// The rule's deterministic phase offset inside its schedule interval:
/// `hash(rule_id) mod min(interval / 2, cap)` in milliseconds. Returns zero
/// when `phase_cap_secs` is 0 (real-time micro-batches) or the cron is invalid.
pub fn rule_phase_offset(
    cron: &str,
    from: DateTime<Utc>,
    rule_id: Uuid,
    phase_cap_secs: u64,
) -> Duration {
    if phase_cap_secs == 0 {
        return Duration::zero();
    }
    let Some(interval) = schedule_interval(cron, from) else {
        return Duration::zero();
    };
    let half_ms = interval.num_milliseconds() / PHASE_INTERVAL_FRACTION_DIVISOR;
    let cap_ms = i64::try_from(phase_cap_secs.saturating_mul(1000)).unwrap_or(i64::MAX);
    let max_ms = half_ms.min(cap_ms);
    if max_ms <= 0 {
        return Duration::zero();
    }
    Duration::milliseconds((rule_phase_hash(rule_id) % max_ms as u64) as i64)
}

/// Next run time on the rule's phase-shifted cron grid: the first
/// `tick + offset` strictly after `from`, where `offset` is
/// [`rule_phase_offset`]. The offset is constant per rule, so consecutive runs
/// stay exactly one interval apart; window bounds come from the `last_run_at`
/// high-water mark (audit D1/D2), not from the fire time, so the offset never
/// opens a gap or an overlap.
pub fn calculate_next_run_phased(
    cron: &str,
    from: DateTime<Utc>,
    rule_id: Uuid,
    phase_cap_secs: u64,
) -> DateTime<Utc> {
    let offset = rule_phase_offset(cron, from, rule_id, phase_cap_secs);
    let next = calculate_next_run(cron, from - offset) + offset;
    debug!(
        %rule_id,
        offset_ms = offset.num_milliseconds(),
        next = %next,
        "Rule phase-shifted next run"
    );
    next
}

/// Cron a scheduled rule runs on when it is saved without one: every minute,
/// the documented default for scheduled rules.
///
/// NAN-3468: a scheduled rule saved with no `schedule_cron` (API or editor)
/// was accepted and then never claimed; the scheduler only logged "it will
/// never run". Every create/update path (dedicated `DetectionService` and the
/// hosted-shared authoring path) now fills this in instead.
pub const DEFAULT_SCHEDULE_CRON: &str = "* * * * *";

/// Normalize a cron expression to 6-field format
///
/// The `cron` crate requires 6 fields (sec min hour day month weekday).
/// This function converts 5-field expressions by prepending "0 " for seconds.
pub(crate) fn normalize_cron_expression(cron: &str) -> String {
    let fields: Vec<&str> = cron.split_whitespace().collect();
    if fields.len() == 5 {
        // 5-field format: prepend "0" for seconds
        format!("0 {}", cron)
    } else {
        // Already 6 fields or invalid (let the parser handle it)
        cron.to_string()
    }
}

/// Validate a cron expression
///
/// Returns Ok(()) if the expression is valid, or an error with details.
pub fn validate_cron_expression(cron: &str) -> Result<(), DetectionError> {
    let normalized = normalize_cron_expression(cron);
    let schedule = Schedule::from_str(&normalized)
        .map_err(|e| DetectionError::InvalidCronExpression(format!("{}: {}", cron, e)))?;

    // Enforce minimum 5-second interval to prevent resource abuse
    let upcoming: Vec<_> = schedule.upcoming(chrono::Utc).take(2).collect();
    if upcoming.len() == 2 {
        let interval = upcoming[1] - upcoming[0];
        if interval < Duration::seconds(5) {
            return Err(DetectionError::InvalidCronExpression(format!(
                "{}: schedule interval must be at least 5 seconds",
                cron
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_cron_expression() {
        // 5-field should get "0 " prepended
        assert_eq!(normalize_cron_expression("*/5 * * * *"), "0 */5 * * * *");
        assert_eq!(normalize_cron_expression("0 0 * * *"), "0 0 0 * * *");

        // 6-field should stay the same
        assert_eq!(normalize_cron_expression("0 */5 * * * *"), "0 */5 * * * *");
    }

    #[test]
    fn test_validate_cron_expression() {
        // Valid 5-field expressions (>= 5 minute intervals)
        assert!(validate_cron_expression("*/5 * * * *").is_ok());
        assert!(validate_cron_expression("0 0 * * *").is_ok());
        assert!(validate_cron_expression("0 9 * * MON-FRI").is_ok());

        // Valid 6-field expressions
        assert!(validate_cron_expression("0 */5 * * * *").is_ok());
        assert!(validate_cron_expression("0 0 0 * * *").is_ok());

        // Invalid expressions
        assert!(validate_cron_expression("invalid").is_err());
        assert!(validate_cron_expression("* * * *").is_err()); // Too few fields

        // Every minute is allowed for continuous scheduled detections
        assert!(validate_cron_expression("* * * * *").is_ok());
        assert!(validate_cron_expression("*/2 * * * *").is_ok());
    }

    #[test]
    fn test_calculate_next_run() {
        let now = Utc::now();

        // Every 5 minutes (5-field)
        let next = calculate_next_run("*/5 * * * *", now);
        assert!(next > now);

        // Every 5 minutes (6-field)
        let next = calculate_next_run("0 */5 * * * *", now);
        assert!(next > now);

        // Daily at midnight
        let next = calculate_next_run("0 0 * * *", now);
        assert!(next > now);
    }

    fn t(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    /// Deterministic UUIDv7 ids minted in one burst, like a bulk rule import:
    /// same-millisecond timestamps, pseudo-random tails.
    pub(crate) fn burst_rule_ids(n: usize, seed: u64) -> Vec<Uuid> {
        let mut state = seed;
        (0..n)
            .map(|i| {
                let mut bytes = [0u8; 10];
                for b in bytes.iter_mut() {
                    state = state
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1_442_695_040_888_963_407);
                    *b = (state >> 56) as u8;
                }
                uuid::Builder::from_unix_timestamp_millis(1_790_000_000_000 + (i / 20) as u64, &bytes)
                    .into_uuid()
            })
            .collect()
    }

    #[test]
    fn phase_offset_is_deterministic_per_rule() {
        let now = t("2026-07-05T12:00:30Z");
        let id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        assert_eq!(
            calculate_next_run_phased("*/5 * * * *", now, id, DEFAULT_PHASE_CAP_SECS),
            calculate_next_run_phased("*/5 * * * *", now, id, DEFAULT_PHASE_CAP_SECS),
        );
        // Stable across evaluation instants, so consecutive runs stay one
        // interval apart.
        assert_eq!(
            rule_phase_offset("*/5 * * * *", now, id, DEFAULT_PHASE_CAP_SECS),
            rule_phase_offset("*/5 * * * *", now + Duration::hours(7), id, DEFAULT_PHASE_CAP_SECS),
        );
    }

    fn max_offset(cron: &str, ids: &[Uuid]) -> Duration {
        let now = t("2026-07-05T12:00:30Z");
        ids.iter()
            .map(|id| rule_phase_offset(cron, now, *id, DEFAULT_PHASE_CAP_SECS))
            .max()
            .unwrap()
    }

    #[test]
    fn phase_offset_bounds_every_minute_under_30s() {
        let ids = burst_rule_ids(500, 1);
        assert!(max_offset("*/1 * * * *", &ids) < Duration::seconds(30));
        assert!(max_offset("* * * * *", &ids) < Duration::seconds(30));
    }

    #[test]
    fn phase_offset_bounds_every_five_minutes_under_150s() {
        let ids = burst_rule_ids(500, 2);
        let max = max_offset("*/5 * * * *", &ids);
        assert!(max < Duration::seconds(150), "{max}");
        // And it actually uses the room (spread, not a 30 s pile-up).
        assert!(max > Duration::seconds(120), "{max}");
    }

    #[test]
    fn phase_offset_bounds_hourly_at_the_cap() {
        let ids = burst_rule_ids(500, 3);
        let max = max_offset("0 * * * *", &ids);
        assert!(max <= Duration::seconds(300), "{max}");
        assert!(max > Duration::seconds(240), "{max}");
    }

    #[test]
    fn daily_rule_runs_within_five_minutes_of_its_wall_clock_time() {
        let ids = burst_rule_ids(500, 4);
        assert!(max_offset("0 9 * * *", &ids) <= Duration::seconds(300));
        let from = t("2026-07-05T08:00:00Z");
        for id in &ids {
            let next = calculate_next_run_phased("0 9 * * *", from, *id, DEFAULT_PHASE_CAP_SECS);
            assert!(
                next >= t("2026-07-05T09:00:00Z") && next <= t("2026-07-05T09:05:00Z"),
                "daily 09:00 rule scheduled at {next}"
            );
        }
    }

    #[test]
    fn phase_cap_is_configurable_and_zero_disables() {
        let ids = burst_rule_ids(200, 5);
        let now = t("2026-07-05T12:00:30Z");
        for id in &ids {
            assert!(rule_phase_offset("0 * * * *", now, *id, 60) < Duration::seconds(60));
            assert_eq!(rule_phase_offset("*/5 * * * *", now, *id, 0), Duration::zero());
            assert_eq!(
                calculate_next_run_phased("*/5 * * * *", now, *id, 0),
                calculate_next_run("*/5 * * * *", now)
            );
        }
    }

    #[test]
    fn next_run_is_strictly_after_from_and_on_the_shifted_grid() {
        let ids = burst_rule_ids(200, 6);
        let from = t("2026-07-05T12:03:17Z");
        for id in &ids {
            let offset = rule_phase_offset("*/5 * * * *", from, *id, DEFAULT_PHASE_CAP_SECS);
            let next = calculate_next_run_phased("*/5 * * * *", from, *id, DEFAULT_PHASE_CAP_SECS);
            assert!(next > from);
            assert!(next - from <= Duration::minutes(5));
            let base = next - offset;
            assert_eq!(base.timestamp() % 300, 0, "base tick {base} not on */5 grid");
        }
    }

    /// 200 rules each on */1, */5 and */15, fired for an hour on their phased
    /// schedules: every rule fires once per interval, and the firings are flat
    /// across the phase range instead of piling into the first 30 s.
    #[test]
    fn two_hundred_rules_fire_on_a_flat_histogram() {
        let anchor = t("2026-07-05T12:00:00Z");
        let horizon = anchor + Duration::hours(1);
        let mut per_second = vec![0u32; 3600];
        for (seed, cron, interval_s, phase_s) in [
            (11u64, "*/1 * * * *", 60i64, 30i64),
            (12, "*/5 * * * *", 300, 150),
            (13, "*/15 * * * *", 900, 300),
        ] {
            let ids = burst_rule_ids(200, seed);
            let mut buckets = vec![0u32; 10];
            let mut fires = 0usize;
            for id in &ids {
                let mut at = calculate_next_run_phased(cron, anchor - Duration::milliseconds(1), *id, DEFAULT_PHASE_CAP_SECS);
                let mut prev: Option<DateTime<Utc>> = None;
                while at < horizon {
                    if let Some(p) = prev {
                        assert_eq!(at - p, Duration::seconds(interval_s), "{cron}: uneven cadence");
                    }
                    let into = (at - anchor).num_milliseconds();
                    per_second[(into / 1000) as usize] += 1;
                    let phase_ms = into % (interval_s * 1000);
                    assert!(phase_ms < phase_s * 1000, "{cron}: phase {phase_ms} ms");
                    buckets[(phase_ms * 10 / (phase_s * 1000)) as usize] += 1;
                    fires += 1;
                    prev = Some(at);
                    // The executor re-schedules from its completion time.
                    at = calculate_next_run_phased(cron, at + Duration::seconds(2), *id, DEFAULT_PHASE_CAP_SECS);
                }
            }
            assert_eq!(fires, 200 * (3600 / interval_s) as usize, "{cron}: missed or double runs");
            // Per rule (not per firing): each rule lands in one phase bucket.
            let per_rule: Vec<f64> = buckets.iter().map(|b| f64::from(*b) * interval_s as f64 / 3600.0).collect();
            let mean = 200.0 / 10.0;
            // Pearson chi-square against uniform, 9 degrees of freedom:
            // 27.88 is the p = 0.001 critical value. A hash-derived offset
            // is uniform in distribution, so this is the honest "flat" test
            // (exact equality per bucket is not achievable without
            // coordinating rules).
            let chi2: f64 = per_rule.iter().map(|o| (o - mean).powi(2) / mean).sum();
            assert!(chi2 < 27.88, "{cron}: phase histogram not flat, chi2 {chi2:.1}, per-rule buckets {per_rule:?}");
            let (lo, hi) = (per_rule.iter().cloned().fold(f64::MAX, f64::min), per_rule.iter().cloned().fold(0.0, f64::max));
            assert!(lo >= mean * 0.3 && hi <= mean * 2.0, "{cron}: phase buckets {per_rule:?} (mean {mean})");
            println!("{cron}: per-rule phase buckets {per_rule:?}, chi2 {chi2:.1}");
        }
        // Per-second view across all 600 rules. With the old 30 s jitter the
        // */5 and */15 cohorts all landed in the first 30 s of their window:
        // ~13 firings/s at :00-:30 of each quarter hour. Phased, the peak
        // second stays a small multiple of the */1 floor (200/30 ≈ 6.7/s).
        let peak = *per_second.iter().max().unwrap();
        println!("peak firings in one second: {peak}");
        assert!(peak <= 20, "peak {peak} firings in one second");
    }
}
