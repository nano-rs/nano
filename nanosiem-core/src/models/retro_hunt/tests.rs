// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

fn create_req() -> CreateRetroHuntRequest {
    CreateRetroHuntRequest {
        name: "Retro hunt: ThreatFox".to_string(),
        description: None,
        severity: None,
        mode: None,
        schedule_cron: None,
        folder: None,
        tags: None,
        feeds: vec![],
        artifact_types: vec![],
        lookback_days: None,
        max_indicators_per_run: None,
        risk_score: None,
    }
}

#[test]
fn defaults_are_within_bounds() {
    assert!((1..=MAX_RETRO_HUNT_LOOKBACK_DAYS).contains(&DEFAULT_RETRO_HUNT_LOOKBACK_DAYS));
    assert!((1..=MAX_RETRO_HUNT_MAX_INDICATORS).contains(&DEFAULT_RETRO_HUNT_MAX_INDICATORS));
}

#[test]
fn valid_config_accepted() {
    let mut req = create_req();
    req.lookback_days = Some(90);
    req.max_indicators_per_run = Some(500);
    req.artifact_types = vec!["ip".into(), "hash".into()];
    assert!(req.validate().is_ok());
}

#[test]
fn empty_artifact_types_means_all_and_is_valid() {
    let req = create_req();
    assert!(req.artifact_types.is_empty());
    assert!(req.validate().is_ok());
}

#[test]
fn lookback_out_of_bounds_rejected() {
    for days in [0, -1, MAX_RETRO_HUNT_LOOKBACK_DAYS + 1, 100_000] {
        let mut req = create_req();
        req.lookback_days = Some(days);
        assert!(
            matches!(
                req.validate(),
                Err(RetroHuntConfigValidationError::LookbackOutOfBounds(_))
            ),
            "lookback {days} must be rejected"
        );
    }
}

#[test]
fn max_indicators_out_of_bounds_rejected() {
    for cap in [0, -5, MAX_RETRO_HUNT_MAX_INDICATORS + 1] {
        let mut req = create_req();
        req.max_indicators_per_run = Some(cap);
        assert!(matches!(
            req.validate(),
            Err(RetroHuntConfigValidationError::MaxIndicatorsOutOfBounds(_))
        ));
    }
}

#[test]
fn invalid_artifact_type_rejected() {
    let mut req = create_req();
    req.artifact_types = vec!["ip".into(), "banana".into()];
    assert!(matches!(
        req.validate(),
        Err(RetroHuntConfigValidationError::InvalidArtifactType(t)) if t == "banana"
    ));
}

#[test]
fn update_partial_only_validates_present_fields() {
    // An update touching only max_indicators must not fail on the absent
    // lookback/artifact fields.
    let update = UpdateRetroHuntConfigRequest {
        max_indicators_per_run: Some(200),
        ..Default::default()
    };
    assert!(update.validate().is_ok());

    let bad = UpdateRetroHuntConfigRequest {
        lookback_days: Some(9999),
        ..Default::default()
    };
    assert!(bad.validate().is_err());
}
