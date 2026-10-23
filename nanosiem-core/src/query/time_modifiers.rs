// SPDX-License-Identifier: AGPL-3.0-or-later
//! UTC time controls shared by parsing and search execution.
use chrono::{DateTime, Datelike, Duration, TimeZone, Timelike, Utc};

pub(crate) fn resolve(token: &str, now: DateTime<Utc>) -> Result<DateTime<Utc>, String> {
    let invalid = || {
        format!("Invalid time modifier `{token}`: expected now, a relative time, or a UTC snap such as -7d@d or @w1")
    };
    let (_, value) = token.split_once('=').ok_or_else(invalid)?;
    let (relative, snap) = match value.split_once('@') {
        Some((relative, snap)) => (relative, Some(snap.to_ascii_lowercase())),
        None => (value, None),
    };
    let seconds = if relative.eq_ignore_ascii_case("now") || (relative.is_empty() && snap.is_some())
    {
        0
    } else {
        let (number, unit) = relative
            .split_at_checked(relative.len().checked_sub(1).ok_or_else(invalid)?)
            .ok_or_else(invalid)?;
        let number: i64 = number.parse().map_err(|_| invalid())?;
        let multiplier = match unit {
            "s" | "S" => 1,
            "m" => 60,
            "h" | "H" => 3600,
            "d" | "D" => 86400,
            "w" | "W" => 604800,
            "M" => 2592000,
            "y" | "Y" => 31536000,
            _ => return Err(invalid()),
        };
        number.checked_mul(multiplier).ok_or_else(invalid)?
    };
    let time = now
        .checked_add_signed(Duration::try_seconds(seconds).ok_or_else(invalid)?)
        .ok_or_else(invalid)?;
    let Some(snap) = snap else {
        return Ok(time);
    };
    let date = time.date_naive();
    let midnight = || date.and_hms_opt(0, 0, 0).ok_or_else(invalid);
    let snapped = match snap.as_str() {
        "s" => time.with_nanosecond(0).ok_or_else(invalid)?,
        "m" => time
            .with_second(0)
            .and_then(|t| t.with_nanosecond(0))
            .ok_or_else(invalid)?,
        "h" => time
            .with_minute(0)
            .and_then(|t| t.with_second(0))
            .and_then(|t| t.with_nanosecond(0))
            .ok_or_else(invalid)?,
        "d" => Utc.from_utc_datetime(&midnight()?),
        "mon" => Utc.from_utc_datetime(
            &date
                .with_day(1)
                .and_then(|d| d.and_hms_opt(0, 0, 0))
                .ok_or_else(invalid)?,
        ),
        "y" => Utc
            .with_ymd_and_hms(time.year(), 1, 1, 0, 0, 0)
            .single()
            .ok_or_else(invalid)?,
        "w" | "w0" | "w1" | "w2" | "w3" | "w4" | "w5" | "w6" => {
            let target = snap.as_bytes().get(1).map_or(0, |b| (b - b'0') as i64);
            let days = (time.weekday().num_days_from_sunday() as i64 - target).rem_euclid(7);
            Utc.from_utc_datetime(&midnight()?)
                .checked_sub_signed(Duration::days(days))
                .ok_or_else(invalid)?
        }
        _ => return Err(invalid()),
    };
    Ok(snapped)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn utc_snaps_and_invalid_modifiers() {
        let now = Utc.with_ymd_and_hms(2026, 10, 17, 21, 35, 42).unwrap();
        for (value, expected) in [
            ("-7d@d", "2026-10-10T00:00:00Z"),
            ("@d", "2026-10-17T00:00:00Z"),
            ("@s", "2026-10-17T21:35:42Z"),
            ("@m", "2026-10-17T21:35:00Z"),
            ("-1h@h", "2026-10-17T20:00:00Z"),
            ("@w0", "2026-10-11T00:00:00Z"),
            ("@w1", "2026-10-12T00:00:00Z"),
            ("@w6", "2026-10-17T00:00:00Z"),
            ("@mon", "2026-10-01T00:00:00Z"),
            ("@y", "2026-01-01T00:00:00Z"),
        ] {
            let bound = resolve(&format!("earliest={value}"), now).unwrap();
            assert_eq!(
                bound.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                expected
            );
            assert!(crate::query::parse_query(&format!(
                "sourcetype=windows_event earliest={value} | stats count"
            ))
            .is_ok());
        }
        for value in [
            "",
            "-7d@oops",
            "@w7",
            "-7dgarbage",
            "999999999999999999d",
            "@d@h",
            "yesterday",
        ] {
            assert!(
                crate::query::parse_query(&format!("error earliest={value}")).is_err(),
                "{value}"
            );
        }
    }
}
