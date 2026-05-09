// SPDX-License-Identifier: AGPL-3.0-or-later

//! Timezone utilities for per-source timestamp conversion
//!
//! Provides timezone offset data, VRL codegen for deployment-time timezone
//! injection, smart detection from sample timestamps, and validation.

use chrono::{DateTime, NaiveDateTime, Utc};

/// Information about a timezone for VRL code generation
pub struct TimezoneInfo {
    pub iana_name: &'static str,
    /// Standard time offset, e.g. "-0500"
    pub std_offset: &'static str,
    /// DST offset if applicable, e.g. "-0400"
    pub dst_offset: Option<&'static str>,
    /// Month DST starts (3 = March for Northern Hemisphere)
    pub dst_start_month: u32,
    /// Month DST ends (11 = November for Northern Hemisphere)
    pub dst_end_month: u32,
    /// Human-readable label
    pub label: &'static str,
    /// Region grouping for UI
    pub region: &'static str,
}

/// A candidate timezone from detection
#[derive(Debug, Clone)]
pub struct TimezoneCandidate {
    pub iana_name: String,
    pub label: String,
    pub offset_hours: f64,
    pub confidence: f64,
}

/// Common enterprise timezones with DST boundaries (month-level precision)
pub static TIMEZONES: &[TimezoneInfo] = &[
    // Americas
    TimezoneInfo {
        iana_name: "America/New_York",
        std_offset: "-0500",
        dst_offset: Some("-0400"),
        dst_start_month: 3,
        dst_end_month: 11,
        label: "Eastern Time (ET)",
        region: "Americas",
    },
    TimezoneInfo {
        iana_name: "America/Chicago",
        std_offset: "-0600",
        dst_offset: Some("-0500"),
        dst_start_month: 3,
        dst_end_month: 11,
        label: "Central Time (CT)",
        region: "Americas",
    },
    TimezoneInfo {
        iana_name: "America/Denver",
        std_offset: "-0700",
        dst_offset: Some("-0600"),
        dst_start_month: 3,
        dst_end_month: 11,
        label: "Mountain Time (MT)",
        region: "Americas",
    },
    TimezoneInfo {
        iana_name: "America/Los_Angeles",
        std_offset: "-0800",
        dst_offset: Some("-0700"),
        dst_start_month: 3,
        dst_end_month: 11,
        label: "Pacific Time (PT)",
        region: "Americas",
    },
    TimezoneInfo {
        iana_name: "America/Anchorage",
        std_offset: "-0900",
        dst_offset: Some("-0800"),
        dst_start_month: 3,
        dst_end_month: 11,
        label: "Alaska Time (AKT)",
        region: "Americas",
    },
    TimezoneInfo {
        iana_name: "Pacific/Honolulu",
        std_offset: "-1000",
        dst_offset: None,
        dst_start_month: 0,
        dst_end_month: 0,
        label: "Hawaii Time (HST)",
        region: "Americas",
    },
    TimezoneInfo {
        iana_name: "America/Phoenix",
        std_offset: "-0700",
        dst_offset: None,
        dst_start_month: 0,
        dst_end_month: 0,
        label: "Arizona (MST, no DST)",
        region: "Americas",
    },
    TimezoneInfo {
        iana_name: "America/Toronto",
        std_offset: "-0500",
        dst_offset: Some("-0400"),
        dst_start_month: 3,
        dst_end_month: 11,
        label: "Eastern Time - Canada (ET)",
        region: "Americas",
    },
    TimezoneInfo {
        iana_name: "America/Vancouver",
        std_offset: "-0800",
        dst_offset: Some("-0700"),
        dst_start_month: 3,
        dst_end_month: 11,
        label: "Pacific Time - Canada (PT)",
        region: "Americas",
    },
    TimezoneInfo {
        iana_name: "America/Sao_Paulo",
        std_offset: "-0300",
        dst_offset: None,
        dst_start_month: 0,
        dst_end_month: 0,
        label: "Brasilia Time (BRT)",
        region: "Americas",
    },
    TimezoneInfo {
        iana_name: "America/Mexico_City",
        std_offset: "-0600",
        dst_offset: None,
        dst_start_month: 0,
        dst_end_month: 0,
        label: "Central Time - Mexico (CST)",
        region: "Americas",
    },
    // Europe
    TimezoneInfo {
        iana_name: "Europe/London",
        std_offset: "+0000",
        dst_offset: Some("+0100"),
        dst_start_month: 3,
        dst_end_month: 10,
        label: "Greenwich Mean Time (GMT/BST)",
        region: "Europe",
    },
    TimezoneInfo {
        iana_name: "Europe/Berlin",
        std_offset: "+0100",
        dst_offset: Some("+0200"),
        dst_start_month: 3,
        dst_end_month: 10,
        label: "Central European Time (CET)",
        region: "Europe",
    },
    TimezoneInfo {
        iana_name: "Europe/Paris",
        std_offset: "+0100",
        dst_offset: Some("+0200"),
        dst_start_month: 3,
        dst_end_month: 10,
        label: "Central European Time (CET)",
        region: "Europe",
    },
    TimezoneInfo {
        iana_name: "Europe/Amsterdam",
        std_offset: "+0100",
        dst_offset: Some("+0200"),
        dst_start_month: 3,
        dst_end_month: 10,
        label: "Central European Time (CET)",
        region: "Europe",
    },
    TimezoneInfo {
        iana_name: "Europe/Zurich",
        std_offset: "+0100",
        dst_offset: Some("+0200"),
        dst_start_month: 3,
        dst_end_month: 10,
        label: "Central European Time (CET)",
        region: "Europe",
    },
    TimezoneInfo {
        iana_name: "Europe/Helsinki",
        std_offset: "+0200",
        dst_offset: Some("+0300"),
        dst_start_month: 3,
        dst_end_month: 10,
        label: "Eastern European Time (EET)",
        region: "Europe",
    },
    TimezoneInfo {
        iana_name: "Europe/Moscow",
        std_offset: "+0300",
        dst_offset: None,
        dst_start_month: 0,
        dst_end_month: 0,
        label: "Moscow Time (MSK)",
        region: "Europe",
    },
    TimezoneInfo {
        iana_name: "Europe/Istanbul",
        std_offset: "+0300",
        dst_offset: None,
        dst_start_month: 0,
        dst_end_month: 0,
        label: "Turkey Time (TRT)",
        region: "Europe",
    },
    // Asia-Pacific
    TimezoneInfo {
        iana_name: "Asia/Dubai",
        std_offset: "+0400",
        dst_offset: None,
        dst_start_month: 0,
        dst_end_month: 0,
        label: "Gulf Standard Time (GST)",
        region: "Asia",
    },
    TimezoneInfo {
        iana_name: "Asia/Kolkata",
        std_offset: "+0530",
        dst_offset: None,
        dst_start_month: 0,
        dst_end_month: 0,
        label: "India Standard Time (IST)",
        region: "Asia",
    },
    TimezoneInfo {
        iana_name: "Asia/Singapore",
        std_offset: "+0800",
        dst_offset: None,
        dst_start_month: 0,
        dst_end_month: 0,
        label: "Singapore Time (SGT)",
        region: "Asia",
    },
    TimezoneInfo {
        iana_name: "Asia/Hong_Kong",
        std_offset: "+0800",
        dst_offset: None,
        dst_start_month: 0,
        dst_end_month: 0,
        label: "Hong Kong Time (HKT)",
        region: "Asia",
    },
    TimezoneInfo {
        iana_name: "Asia/Shanghai",
        std_offset: "+0800",
        dst_offset: None,
        dst_start_month: 0,
        dst_end_month: 0,
        label: "China Standard Time (CST)",
        region: "Asia",
    },
    TimezoneInfo {
        iana_name: "Asia/Tokyo",
        std_offset: "+0900",
        dst_offset: None,
        dst_start_month: 0,
        dst_end_month: 0,
        label: "Japan Standard Time (JST)",
        region: "Asia",
    },
    TimezoneInfo {
        iana_name: "Asia/Seoul",
        std_offset: "+0900",
        dst_offset: None,
        dst_start_month: 0,
        dst_end_month: 0,
        label: "Korea Standard Time (KST)",
        region: "Asia",
    },
    // Australia / Pacific
    TimezoneInfo {
        iana_name: "Australia/Sydney",
        std_offset: "+1100",
        dst_offset: Some("+1000"),
        dst_start_month: 4,
        dst_end_month: 10,
        label: "Australian Eastern Time (AEST/AEDT)",
        region: "Australia",
    },
    TimezoneInfo {
        iana_name: "Australia/Melbourne",
        std_offset: "+1100",
        dst_offset: Some("+1000"),
        dst_start_month: 4,
        dst_end_month: 10,
        label: "Australian Eastern Time (AEST/AEDT)",
        region: "Australia",
    },
    TimezoneInfo {
        iana_name: "Australia/Perth",
        std_offset: "+0800",
        dst_offset: None,
        dst_start_month: 0,
        dst_end_month: 0,
        label: "Australian Western Time (AWST)",
        region: "Australia",
    },
    TimezoneInfo {
        iana_name: "Pacific/Auckland",
        std_offset: "+1300",
        dst_offset: Some("+1200"),
        dst_start_month: 4,
        dst_end_month: 9,
        label: "New Zealand Time (NZST/NZDT)",
        region: "Australia",
    },
];

/// Look up a timezone by IANA name
pub fn find_timezone(iana_name: &str) -> Option<&'static TimezoneInfo> {
    TIMEZONES.iter().find(|tz| tz.iana_name == iana_name)
}

/// Check if a timezone name is valid (known to us)
pub fn is_valid_timezone(tz: &str) -> bool {
    tz == "UTC" || TIMEZONES.iter().any(|t| t.iana_name == tz)
}

/// Generate VRL code for timezone conversion at deploy time.
///
/// Returns `None` for UTC (no conversion needed).
/// The returned VRL is injected into the output transform before timestamp flattening.
pub fn generate_timezone_vrl(iana_timezone: &str) -> Option<String> {
    if iana_timezone == "UTC" || iana_timezone.is_empty() {
        return None;
    }

    let tz = find_timezone(iana_timezone)?;

    let std_offset = tz.std_offset;

    // If no DST, always use standard offset
    // NOTE: This VRL operates on an existing `ts_val` variable that is already set
    // by the output transform (from .udm.timestamp or now()). It does NOT re-read
    // .udm.timestamp, to avoid overwriting a now() fallback.
    if tz.dst_offset.is_none() {
        return Some(format!(
            r#"# --- Timezone: {iana} ---
if is_string(ts_val) {{
    ts_str = string!(ts_val)
    has_tz = match(ts_str, r'[+-]\d{{2}}:?\d{{2}}\s*$') ?? false
    if !has_tz && !ends_with(ts_str, "Z") {{
        parsed, err = parse_timestamp(ts_str + " {offset}", "%Y-%m-%d %H:%M:%S %z")
        if err == null {{
            ts_val = format_timestamp!(parsed, format: "%+")
        }}
    }}
}}"#,
            iana = iana_timezone,
            offset = std_offset,
        ));
    }

    let dst_offset = tz.dst_offset.unwrap();
    let dst_start = tz.dst_start_month;
    let dst_end = tz.dst_end_month;

    // Southern hemisphere DST: start > end (e.g., April to October for Australia)
    let dst_condition = if dst_start < dst_end {
        // Northern hemisphere: DST active between start and end
        format!("month >= {} && month < {}", dst_start, dst_end)
    } else {
        // Southern hemisphere: DST active outside the range
        format!("month >= {} || month < {}", dst_start, dst_end)
    };

    Some(format!(
        r#"# --- Timezone: {iana} ---
if is_string(ts_val) {{
    ts_str = string!(ts_val)
    has_tz = match(ts_str, r'[+-]\d{{2}}:?\d{{2}}\s*$') ?? false
    if !has_tz && !ends_with(ts_str, "Z") {{
        month = to_int(slice(ts_str, 5, 7) ?? "01") ?? 1
        offset = if {dst_condition} {{ " {dst}" }} else {{ " {std}" }}
        parsed, err = parse_timestamp(ts_str + offset, "%Y-%m-%d %H:%M:%S %z")
        if err == null {{
            ts_val = format_timestamp!(parsed, format: "%+")
        }}
    }}
}}"#,
        iana = iana_timezone,
        dst_condition = dst_condition,
        dst = dst_offset,
        std = std_offset,
    ))
}

/// Detect likely timezone from sample timestamps by comparing to current UTC.
///
/// Parses sample timestamps as naive datetimes and computes the offset
/// from current UTC. Returns ranked candidates with confidence scores.
pub fn detect_timezone_from_samples(
    sample_timestamps: &[&str],
    current_utc: DateTime<Utc>,
) -> Vec<TimezoneCandidate> {
    let mut offsets: Vec<f64> = Vec::new();

    // Common timestamp formats to try
    let formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%d/%b/%Y:%H:%M:%S",
        "%b %d %H:%M:%S",
    ];

    for ts_str in sample_timestamps {
        for fmt in &formats {
            if let Ok(naive) = NaiveDateTime::parse_from_str(ts_str, fmt) {
                let diff_hours = (current_utc.naive_utc() - naive).num_minutes() as f64 / 60.0;
                // Only consider reasonable offsets (-12 to +14)
                if diff_hours > -13.0 && diff_hours < 15.0 {
                    offsets.push(diff_hours);
                    break;
                }
            }
        }
    }

    if offsets.is_empty() {
        return vec![];
    }

    // Average offset
    let avg_offset: f64 = offsets.iter().sum::<f64>() / offsets.len() as f64;

    // Find matching timezones (within 1 hour tolerance)
    let mut candidates = Vec::new();
    let current_month = current_utc
        .format("%m")
        .to_string()
        .parse::<u32>()
        .unwrap_or(1);

    for tz in TIMEZONES {
        let tz_offset_str = if let Some(dst) = tz.dst_offset {
            let is_dst = if tz.dst_start_month < tz.dst_end_month {
                current_month >= tz.dst_start_month && current_month < tz.dst_end_month
            } else {
                current_month >= tz.dst_start_month || current_month < tz.dst_end_month
            };
            if is_dst {
                dst
            } else {
                tz.std_offset
            }
        } else {
            tz.std_offset
        };

        let tz_offset_hours = parse_offset_to_hours(tz_offset_str);
        let diff = (avg_offset - tz_offset_hours).abs();

        if diff < 1.0 {
            let confidence = 1.0 - (diff / 1.0);
            candidates.push(TimezoneCandidate {
                iana_name: tz.iana_name.to_string(),
                label: tz.label.to_string(),
                offset_hours: tz_offset_hours,
                confidence,
            });
        }
    }

    // Sort by confidence descending
    candidates.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    candidates
}

/// Parse an offset string like "-0500" or "+0530" to hours
fn parse_offset_to_hours(offset: &str) -> f64 {
    if offset.len() < 5 {
        return 0.0;
    }
    let sign: f64 = if offset.starts_with('-') { -1.0 } else { 1.0 };
    let hours: f64 = offset[1..3].parse().unwrap_or(0.0);
    let minutes: f64 = offset[3..5].parse().unwrap_or(0.0);
    sign * (hours + minutes / 60.0)
}

/// Get all timezone options grouped by region for the UI
pub fn get_timezone_options() -> Vec<(&'static str, Vec<(&'static str, &'static str)>)> {
    let mut regions: std::collections::BTreeMap<&str, Vec<(&str, &str)>> =
        std::collections::BTreeMap::new();

    for tz in TIMEZONES {
        regions
            .entry(tz.region)
            .or_default()
            .push((tz.iana_name, tz.label));
    }

    regions.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_timezone() {
        assert!(is_valid_timezone("UTC"));
        assert!(is_valid_timezone("America/New_York"));
        assert!(is_valid_timezone("Asia/Tokyo"));
        assert!(!is_valid_timezone("Mars/Olympus_Mons"));
        assert!(!is_valid_timezone("EST"));
        assert!(!is_valid_timezone(""));
    }

    #[test]
    fn test_generate_timezone_vrl_utc_returns_none() {
        assert!(generate_timezone_vrl("UTC").is_none());
        assert!(generate_timezone_vrl("").is_none());
    }

    #[test]
    fn test_generate_timezone_vrl_eastern() {
        let vrl = generate_timezone_vrl("America/New_York");
        assert!(vrl.is_some());
        let code = vrl.unwrap();
        assert!(code.contains("Timezone: America/New_York"));
        assert!(code.contains("-0500"));
        assert!(code.contains("-0400"));
        // DST condition for Northern hemisphere
        assert!(code.contains("month >= 3 && month < 11"));
    }

    #[test]
    fn test_generate_timezone_vrl_no_dst() {
        let vrl = generate_timezone_vrl("Asia/Tokyo");
        assert!(vrl.is_some());
        let code = vrl.unwrap();
        assert!(code.contains("Timezone: Asia/Tokyo"));
        assert!(code.contains("+0900"));
        // No DST logic
        assert!(!code.contains("month"));
    }

    #[test]
    fn test_generate_timezone_vrl_southern_hemisphere() {
        let vrl = generate_timezone_vrl("Australia/Sydney");
        assert!(vrl.is_some());
        let code = vrl.unwrap();
        assert!(code.contains("Timezone: Australia/Sydney"));
        assert!(code.contains("Australia/Sydney"));
    }

    #[test]
    fn test_generate_timezone_vrl_unknown_returns_none() {
        assert!(generate_timezone_vrl("Invalid/Zone").is_none());
    }

    #[test]
    fn test_parse_offset_to_hours() {
        assert!((parse_offset_to_hours("-0500") - (-5.0)).abs() < 0.01);
        assert!((parse_offset_to_hours("+0530") - 5.5).abs() < 0.01);
        assert!((parse_offset_to_hours("+0000") - 0.0).abs() < 0.01);
        assert!((parse_offset_to_hours("+1300") - 13.0).abs() < 0.01);
    }
}
