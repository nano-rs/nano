// SPDX-License-Identifier: AGPL-3.0-or-later

//! Detection Rule Scheduling Utilities
//!
//! Provides cron expression parsing, validation, and jitter computation
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

/// Calculate the next run time with deterministic jitter based on rule ID
///
/// Jitter prevents thundering herd when many rules have the same schedule.
/// The jitter is deterministic per rule ID, so the same rule always gets
/// the same offset, making scheduling predictable.
pub fn calculate_next_run_with_jitter(
    cron: &str,
    from: DateTime<Utc>,
    rule_id: Uuid,
    jitter_max_secs: u64,
) -> DateTime<Utc> {
    let base_next_run = calculate_next_run(cron, from);

    if jitter_max_secs == 0 {
        return base_next_run;
    }

    // Calculate deterministic jitter from rule UUID
    // Use the first 8 bytes of the UUID as a u64 for consistent hashing
    let uuid_bytes = rule_id.as_bytes();
    let hash_value = u64::from_le_bytes([
        uuid_bytes[0],
        uuid_bytes[1],
        uuid_bytes[2],
        uuid_bytes[3],
        uuid_bytes[4],
        uuid_bytes[5],
        uuid_bytes[6],
        uuid_bytes[7],
    ]);

    // Map to jitter range [0, jitter_max_secs)
    let jitter_secs = (hash_value % jitter_max_secs) as i64;

    debug!(
        "Rule {} gets jitter offset of {}s (max: {}s)",
        rule_id, jitter_secs, jitter_max_secs
    );

    base_next_run + Duration::seconds(jitter_secs)
}

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

/// Get a human-readable description of a cron expression
pub fn describe_cron_expression(cron: &str) -> Result<String, DetectionError> {
    // Validate first
    validate_cron_expression(cron)?;

    let fields: Vec<&str> = cron.split_whitespace().collect();

    // Handle common patterns for 5-field format
    if fields.len() == 5 {
        let (min, hour, day, month, weekday) =
            (fields[0], fields[1], fields[2], fields[3], fields[4]);

        return Ok(match (min, hour, day, month, weekday) {
            ("0", "0", "*", "*", "*") => "Daily at midnight".to_string(),
            ("0", h, "*", "*", "*") if h != "*" => format!("Daily at {}:00", h),
            (m, "*", "*", "*", "*") if m.starts_with("*/") => {
                let interval = m.trim_start_matches("*/");
                format!("Every {} minutes", interval)
            }
            ("0", "0", "1", "*", "*") => "Monthly on the 1st at midnight".to_string(),
            ("0", "0", "*", "*", "0") | ("0", "0", "*", "*", "SUN") => {
                "Weekly on Sunday at midnight".to_string()
            }
            ("0", "0", "*", "*", "1") | ("0", "0", "*", "*", "MON") => {
                "Weekly on Monday at midnight".to_string()
            }
            _ => format!("Custom schedule: {}", cron),
        });
    }

    // 6-field format
    if fields.len() == 6 {
        let (sec, min, hour, day, month, weekday) = (
            fields[0], fields[1], fields[2], fields[3], fields[4], fields[5],
        );

        return Ok(match (sec, min, hour, day, month, weekday) {
            ("0", "0", "0", "*", "*", "*") => "Daily at midnight".to_string(),
            ("0", "0", h, "*", "*", "*") if h != "*" => format!("Daily at {}:00", h),
            ("0", m, "*", "*", "*", "*") if m.starts_with("*/") => {
                let interval = m.trim_start_matches("*/");
                format!("Every {} minutes", interval)
            }
            _ => format!("Custom schedule: {}", cron),
        });
    }

    Ok(format!("Custom schedule: {}", cron))
}

/// Calculate the next N run times for a cron expression
pub fn calculate_next_runs(cron: &str, count: usize) -> Result<Vec<DateTime<Utc>>, DetectionError> {
    let normalized = normalize_cron_expression(cron);
    let schedule = Schedule::from_str(&normalized)
        .map_err(|e| DetectionError::InvalidCronExpression(format!("{}: {}", cron, e)))?;

    Ok(schedule.upcoming(Utc).take(count).collect())
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

    #[test]
    fn test_calculate_next_runs() {
        let runs = calculate_next_runs("*/5 * * * *", 5).unwrap();
        assert_eq!(runs.len(), 5);

        // Verify they are in order
        for i in 1..runs.len() {
            assert!(runs[i] > runs[i - 1]);
        }
    }

    #[test]
    fn test_describe_cron_expression() {
        assert_eq!(
            describe_cron_expression("0 0 * * *").unwrap(),
            "Daily at midnight"
        );
        assert_eq!(
            describe_cron_expression("0 12 * * *").unwrap(),
            "Daily at 12:00"
        );
        assert_eq!(
            describe_cron_expression("*/5 * * * *").unwrap(),
            "Every 5 minutes"
        );
        assert_eq!(
            describe_cron_expression("*/2 * * * *").unwrap(),
            "Every 2 minutes"
        );
    }

    #[test]
    fn test_jitter_is_deterministic() {
        let now = Utc::now();
        let rule_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();

        // Same rule ID should always get the same jitter
        let next1 = calculate_next_run_with_jitter("*/30 * * * * *", now, rule_id, 30);
        let next2 = calculate_next_run_with_jitter("*/30 * * * * *", now, rule_id, 30);
        assert_eq!(next1, next2, "Jitter should be deterministic for same rule");
    }

    #[test]
    fn test_jitter_spreads_rules() {
        let now = Utc::now();
        let rule_id_a = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let rule_id_b = Uuid::parse_str("660e8400-e29b-41d4-a716-446655440000").unwrap();
        let rule_id_c = Uuid::parse_str("770e8400-e29b-41d4-a716-446655440000").unwrap();

        let next_a = calculate_next_run_with_jitter("*/30 * * * * *", now, rule_id_a, 30);
        let next_b = calculate_next_run_with_jitter("*/30 * * * * *", now, rule_id_b, 30);
        let next_c = calculate_next_run_with_jitter("*/30 * * * * *", now, rule_id_c, 30);

        // At least some rules should have different next run times
        // (statistically very unlikely all 3 UUIDs hash to same offset)
        let all_same = next_a == next_b && next_b == next_c;
        assert!(
            !all_same,
            "Different rule IDs should (usually) get different jitter offsets"
        );
    }

    #[test]
    fn test_jitter_within_bounds() {
        let now = Utc::now();
        let base_next = calculate_next_run("*/30 * * * * *", now);
        let jitter_max = 30u64;

        // Test with multiple random UUIDs
        for _ in 0..100 {
            let rule_id = Uuid::now_v7();
            let jittered =
                calculate_next_run_with_jitter("*/30 * * * * *", now, rule_id, jitter_max);

            let diff = (jittered - base_next).num_seconds();
            assert!(
                diff >= 0 && diff < jitter_max as i64,
                "Jitter {} should be in range [0, {})",
                diff,
                jitter_max
            );
        }
    }

    #[test]
    fn test_jitter_disabled_when_zero() {
        let now = Utc::now();
        let rule_id = Uuid::now_v7();

        let base_next = calculate_next_run("*/30 * * * * *", now);
        let jittered = calculate_next_run_with_jitter("*/30 * * * * *", now, rule_id, 0);

        assert_eq!(
            base_next, jittered,
            "Jitter should be disabled when max is 0"
        );
    }
}
