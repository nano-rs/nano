//! NAN-3697: every collector starts point-forward.
//!
//! A stream with no cursor starts at its activation time minus a fixed
//! overlap, never earlier. There is no backfill option: an operator cannot
//! ask a new collector to read history. An existing cursor is always resumed
//! and never reset by the engine.
//!
//! This is the one rule for the initial cursor. Declarative specs read it as
//! `{{initial_cursor}}` / VRL `.initial_cursor` (and window streams start
//! there); Deno collectors read `ctx.initialCursor`. `backfill_from` /
//! `ctx.backfillFrom` remain as deprecated aliases carrying the same value, so
//! catalog specs written before this rule start point-forward too.

use chrono::{DateTime, Duration, SecondsFormat, Utc};
use serde_json::{Value, json};

/// How far before activation a new stream's first cursor sits.
///
/// Five minutes covers the late-arrival lag of every supported vendor API
/// (Okta System Log ~seconds, Google Workspace reports up to a few minutes,
/// Slack access logs aggregate per minute, Netskope iterator ingestion delay)
/// and one missed or slow scheduler tick, while staying far short of a
/// backlog: a new connector ingests at most five minutes of history.
pub const INITIAL_CURSOR_OVERLAP_SECS: i64 = 300;

/// Checkpoint key the engine writes on a stream's first run (the stream's
/// source status): `{activated_at, initial_cursor, overlap_secs}`.
pub const POINT_FORWARD_KEY: &str = "point_forward";

/// The first cursor of a stream activated at `now`.
pub fn initial_cursor(now: DateTime<Utc>) -> DateTime<Utc> {
    now - Duration::seconds(INITIAL_CURSOR_OVERLAP_SECS)
}

/// RFC 3339 with seconds, UTC (`2026-10-12T14:00:00Z`).
pub fn fmt_rfc3339(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// A stream's initial cursor, from its saved checkpoint slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PointForward {
    pub initial_cursor: DateTime<Utc>,
    /// No cursor was saved: this run activates the stream and must record
    /// the activation before it reads anything.
    pub activating: bool,
}

impl PointForward {
    /// `saved` is the stream's (or fan-out item's) checkpoint slot. A slot
    /// that recorded its activation keeps that initial cursor forever, so a
    /// stream that has not advanced yet never drifts forward run to run.
    pub fn from_saved(saved: &Value, now: DateTime<Utc>) -> Self {
        let recorded = saved
            .get(POINT_FORWARD_KEY)
            .and_then(|p| p.get("initial_cursor"))
            .and_then(Value::as_str)
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&Utc));
        if let Some(initial_cursor) = recorded {
            return Self { initial_cursor, activating: false };
        }
        let has_cursor = saved.get("state").is_some() || saved.get("window").is_some();
        Self { initial_cursor: initial_cursor(now), activating: !has_cursor }
    }

    pub fn initial_cursor_rfc3339(&self) -> String {
        fmt_rfc3339(self.initial_cursor)
    }

    /// The status record written on activation.
    pub fn record(&self, activated_at: DateTime<Utc>) -> Value {
        json!({
            "activated_at": fmt_rfc3339(activated_at),
            "initial_cursor": self.initial_cursor_rfc3339(),
            "overlap_secs": INITIAL_CURSOR_OVERLAP_SECS,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 12, 14, 0, 0).unwrap()
    }

    #[test]
    fn overlap_is_five_minutes() {
        assert_eq!(INITIAL_CURSOR_OVERLAP_SECS, 300);
        assert_eq!(initial_cursor(now()), Utc.with_ymd_and_hms(2026, 10, 12, 13, 55, 0).unwrap());
    }

    #[test]
    fn empty_slot_activates_at_now_minus_overlap() {
        let p = PointForward::from_saved(&json!({}), now());
        assert!(p.activating);
        assert_eq!(p.initial_cursor, initial_cursor(now()));
        assert_eq!(p.record(now())["activated_at"], "2026-10-12T14:00:00Z");
        assert_eq!(p.record(now())["initial_cursor"], "2026-10-12T13:55:00Z");
    }

    #[test]
    fn recorded_activation_is_kept_and_never_moves() {
        let saved = json!({ POINT_FORWARD_KEY: { "initial_cursor": "2026-10-01T00:00:00Z" } });
        let p = PointForward::from_saved(&saved, now());
        assert!(!p.activating);
        assert_eq!(p.initial_cursor_rfc3339(), "2026-10-01T00:00:00Z");
    }

    #[test]
    fn a_legacy_cursor_is_not_an_activation() {
        for saved in [json!({ "state": {"after": "x"} }), json!({ "window": {"watermark": 1} })] {
            assert!(!PointForward::from_saved(&saved, now()).activating);
        }
    }
}
