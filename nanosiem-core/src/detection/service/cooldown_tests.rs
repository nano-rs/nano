// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unit tests for the per-(rule, entity) alert cooldown (NAN-1805) and the
//! dataset=risk feedback-loop guard.
//!
//! The durable end-to-end behavior (fires once → suppressed → re-fires after
//! the window, across a service "restart") is exercised against live PG+CH by
//! `nanosiem-core/tests/detection_alert_cooldown_integration.rs`; these tests
//! pin the pure hysteresis semantics and the save-time guard.

use chrono::{Duration, Utc};

use super::helpers::within_alert_cooldown;
use super::{DetectionError, DetectionService};

// ---------------------------------------------------------------------------
// within_alert_cooldown — time-based, not edge-triggered
// ---------------------------------------------------------------------------

#[test]
fn no_prior_alert_always_fires() {
    let now = Utc::now();
    assert!(!within_alert_cooldown(None, now, 240));
}

#[test]
fn inside_window_suppresses_outside_fires() {
    let now = Utc::now();
    // 239m into a 240m window → suppressed.
    assert!(within_alert_cooldown(
        Some(now - Duration::minutes(239)),
        now,
        240
    ));
    // Exactly at the boundary → the window has elapsed → fires.
    assert!(!within_alert_cooldown(
        Some(now - Duration::minutes(240)),
        now,
        240
    ));
    assert!(!within_alert_cooldown(
        Some(now - Duration::minutes(241)),
        now,
        240
    ));
}

#[test]
fn flap_across_threshold_cannot_re_open_the_window() {
    // The anchor is the LAST ALERT time — nothing about a dip below the
    // rule's threshold (a cycle with no matches) mutates it. Whatever happens
    // to the underlying value at t+10m, t+50m, t+100m, the gate's answer
    // depends only on (now - last_alert_at): every re-cross inside the window
    // is suppressed and the first evaluation after it fires.
    let alert_at = Utc::now();
    for minutes_later in [1, 10, 50, 100, 239] {
        assert!(
            within_alert_cooldown(
                Some(alert_at),
                alert_at + Duration::minutes(minutes_later),
                240
            ),
            "re-cross at +{minutes_later}m must be suppressed"
        );
    }
    assert!(!within_alert_cooldown(
        Some(alert_at),
        alert_at + Duration::minutes(240),
        240
    ));
}

#[test]
fn zero_and_negative_cooldown_never_suppress() {
    let now = Utc::now();
    assert!(!within_alert_cooldown(Some(now), now, 0));
    assert!(!within_alert_cooldown(Some(now), now, -5));
}

// ---------------------------------------------------------------------------
// dataset=risk feedback-loop guard (save-time)
// ---------------------------------------------------------------------------

fn guard(
    dataset: Option<&str>,
    query: &str,
    risk_score: Option<i32>,
    modifiers_empty: bool,
) -> Result<(), DetectionError> {
    DetectionService::validate_risk_dataset_rule(dataset, query, risk_score, modifiers_empty)
}

const NOTABLE_QUERY: &str = "* | where score_24h > 500 or score_7d > 1000";

#[test]
fn non_risk_datasets_are_unconstrained() {
    for ds in [None, Some("logs"), Some("spans"), Some("metrics")] {
        assert!(guard(ds, "error | risk score=50 entity=src_ip", Some(80), false).is_ok());
    }
}

#[test]
fn risk_rule_requires_explicit_zero_score() {
    // Compliant: dataset=risk + risk_score 0 + no modifiers + no `| risk`.
    assert!(guard(Some("risk"), NOTABLE_QUERY, Some(0), true).is_ok());

    // Nonzero score → rejected (its findings would feed its own input).
    assert!(matches!(
        guard(Some("risk"), NOTABLE_QUERY, Some(10), true),
        Err(DetectionError::InvalidQuery(_))
    ));
    // None is NOT zero: scoring falls back to a severity default.
    assert!(matches!(
        guard(Some("risk"), NOTABLE_QUERY, None, true),
        Err(DetectionError::InvalidQuery(_))
    ));
}

#[test]
fn risk_rule_rejects_modifiers_and_risk_command() {
    assert!(matches!(
        guard(Some("risk"), NOTABLE_QUERY, Some(0), false),
        Err(DetectionError::InvalidQuery(_))
    ));
    assert!(matches!(
        guard(
            Some("risk"),
            "* | risk score=50 entity=entity | where score_24h > 500",
            Some(0),
            true
        ),
        Err(DetectionError::InvalidQuery(_))
    ));
}
