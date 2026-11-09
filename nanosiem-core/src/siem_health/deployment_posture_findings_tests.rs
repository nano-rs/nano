// SPDX-License-Identifier: AGPL-3.0-or-later
//! Security review 2026-11-08 (group B): SIEM Health surfaces insecure
//! deployment settings that v2.0.x still accepts.

use super::tests::base_zero_metrics_fixture;
use super::*;
use crate::deployment_posture::PostureInputs;

#[test]
fn public_install_token_surfaces_on_a_fresh_report_and_caps_the_score() {
    let metrics = base_zero_metrics_fixture();
    let mut analysis = fallback_report(&metrics);
    assert!(analysis.recommendations.is_empty(), "fixture is a Fresh deployment");
    let inputs = PostureInputs {
        install_token: Some("nanosiem-default-token".into()),
        ..Default::default()
    };
    ensure_deployment_posture_findings(&mut analysis, &inputs);
    assert_eq!(analysis.recommendations.len(), 2);
    assert!(analysis.recommendations.iter().all(|r| r.priority == "critical"));
    assert_eq!(HealthStatus::from_score(analysis.overall_score), HealthStatus::Critical);
    // Idempotent across report paths.
    ensure_deployment_posture_findings(&mut analysis, &inputs);
    assert_eq!(analysis.recommendations.len(), 2);
}

#[test]
fn provisioned_deployment_adds_nothing() {
    let metrics = base_zero_metrics_fixture();
    let mut analysis = fallback_report(&metrics);
    let before = analysis.overall_score;
    let inputs = PostureInputs {
        install_token: Some("e3b0c44298fc1c149afbf4c8996fb924".into()),
        delivery_token: Some("27ae41e4649b934ca495991b7852b855".into()),
        delivery_strict: true,
        base_url: Some("https://siem.example.com".into()),
        ..Default::default()
    };
    ensure_deployment_posture_findings(&mut analysis, &inputs);
    assert!(analysis.recommendations.is_empty());
    assert_eq!(analysis.overall_score, before);
}
