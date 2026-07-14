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
fn feed_names_empty_means_all_feeds_and_is_valid() {
    // F-36: no feeds selected = "ALL feeds"; must not require a catalog.
    assert!(validate_feed_names(&[], &[]).is_ok());
    assert!(validate_feed_names(&[], &["ThreatFox".into()]).is_ok());
}

#[test]
fn feed_names_membership_enforced_when_catalog_known() {
    let authorized = vec!["ThreatFox".to_string(), "URLhaus".to_string()];
    // Case-folded membership (matches lower(enrichment_name)).
    assert!(validate_feed_names(&["threatfox".into()], &authorized).is_ok());
    assert!(validate_feed_names(&["URLHAUS".into(), "ThreatFox".into()], &authorized).is_ok());
    // A typo is rejected as an unknown feed.
    assert!(matches!(
        validate_feed_names(&["threatfoxx".into()], &authorized),
        Err(RetroHuntConfigValidationError::UnknownFeed(f)) if f == "threatfoxx"
    ));
}

#[test]
fn feed_names_membership_skipped_when_catalog_unconfirmed() {
    // F-36: an empty catalog (CH unreachable or no feeds synced yet) must not
    // hard-fail rule creation — only the format check applies.
    assert!(validate_feed_names(&["AnythingGoes".into()], &[]).is_ok());
    // ...but a structurally hostile name is still rejected even with no catalog.
    assert!(matches!(
        validate_feed_names(&["evil'|feed".into()], &[]),
        Err(RetroHuntConfigValidationError::MalformedFeedName(_))
    ));
}

#[test]
fn feed_name_format_rejects_hostile_characters() {
    // F-36: quotes, pipes, backslashes, control chars, and empties are rejected.
    for bad in ["", "   ", "a'b", "a\"b", "a|b", "a\\b", "a\tb", "a\nb"] {
        assert!(
            matches!(
                validate_feed_name_format(bad),
                Err(RetroHuntConfigValidationError::MalformedFeedName(_))
            ),
            "expected {bad:?} to be rejected"
        );
    }
    // Ordinary feed names pass.
    for ok in ["ThreatFox", "URLhaus", "abuse.ch Feodo", "my-custom_feed.v2"] {
        assert!(
            validate_feed_name_format(ok).is_ok(),
            "expected {ok:?} to be accepted"
        );
    }
}

#[test]
fn feed_names_hostile_rejected_before_membership_when_catalog_known() {
    // A malformed name is caught by the format check even when a catalog exists.
    let authorized = vec!["ThreatFox".to_string()];
    assert!(matches!(
        validate_feed_names(&["Threat|Fox".into()], &authorized),
        Err(RetroHuntConfigValidationError::MalformedFeedName(_))
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
