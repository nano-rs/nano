// SPDX-License-Identifier: AGPL-3.0-or-later
//! Absolute half-open bounds; counts use whole parts with separately echoed coverage.
//! Legacy preset lookbacks remain unchanged.
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ExactPrevalenceWindow {
    pub start: String,
    pub end: String,
}
impl ExactPrevalenceWindow {
    pub fn parse(start: Option<&str>, end: Option<&str>) -> Result<Option<Self>, String> {
        match (start, end) {
            (None, None) => Ok(None),
            (Some(start), Some(end)) => {
                let parse = |s| {
                    DateTime::parse_from_rfc3339(s)
                        .map(|dt| dt.with_timezone(&Utc))
                        .map_err(|_| {
                            "prevalence bounds require RFC3339 instants with offsets".to_string()
                        })
                };
                let (start, end) = (parse(start)?, parse(end)?);
                let span = end.signed_duration_since(start);
                if span <= chrono::Duration::zero()
                    || span > chrono::Duration::days(30)
                    || start.timestamp_subsec_nanos() % 1_000_000 != 0
                    || end.timestamp_subsec_nanos() % 1_000_000 != 0
                {
                    return Err(
                        "prevalence bounds require 0 < span <= 30 days and millisecond precision"
                            .into(),
                    );
                }
                Ok(Some(Self {
                    start: start.to_rfc3339_opts(SecondsFormat::Millis, true),
                    end: end.to_rfc3339_opts(SecondsFormat::Millis, true),
                }))
            }
            _ => Err("prevalence requires both start and end".into()),
        }
    }
    pub fn from_micros(start: i64, end: i64) -> Result<Self, String> {
        if start >= end {
            return Err("reversed prevalence coverage".into());
        }
        let format = |us| {
            DateTime::<Utc>::from_timestamp_micros(us)
                .map(|dt| dt.to_rfc3339_opts(SecondsFormat::Micros, true))
                .ok_or("invalid prevalence coverage".to_string())
        };
        Ok(Self {
            start: format(start)?,
            end: format(end)?,
        })
    }
    pub fn micros(&self) -> Result<(i64, i64), String> {
        let parse = |s: &str| {
            DateTime::parse_from_rfc3339(s)
                .map(|dt| dt.timestamp_micros())
                .map_err(|e| e.to_string())
        };
        let (start, end) = (parse(&self.start)?, parse(&self.end)?);
        if start >= end {
            return Err("reversed prevalence coverage".into());
        }
        Ok((start, end))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_bounds_require_paired_absolute_increasing_dates_and_preserve_offsets() {
        for (start, end) in [
            (Some("2026-10-16T00:00:00Z"), None),
            (Some("10/16"), Some("10/17")),
            (Some("2026-10-17T00:00:00Z"), Some("2026-10-16T00:00:00Z")),
            (Some("2026-01-01T00:00:00Z"), Some("2026-10-16T00:00:00Z")),
        ] {
            assert!(ExactPrevalenceWindow::parse(start, end).is_err());
        }
        let w = ExactPrevalenceWindow::parse(
            Some("2026-10-16T00:00:00-04:00"),
            Some("2026-10-17T00:00:00-04:00"),
        )
        .unwrap()
        .unwrap();
        assert_eq!(w.start, "2026-10-16T04:00:00.000Z");
        let (start, end) = w.micros().unwrap();
        assert_eq!(end - start, 86_400_000_000);
    }
}
