// SPDX-License-Identifier: AGPL-3.0-or-later

//! V2: `/api/settings/tier` derives SSO from the licensed build, never a plan.

use super::*;
use nanosiem_core::{OrganizationTier, TierLimits};

#[test]
fn tier_sso_enabled_follows_build_availability() {
    let stored = TierLimits::for_tier_unoverridden(OrganizationTier::Unrestricted);
    assert!(stored.sso_enabled, "precondition: unrestricted grants SSO");

    let reported = clamp_to_build(stored);
    assert_eq!(
        reported.sso_enabled,
        crate::handlers::capabilities::SSO_AVAILABLE
    );
    #[cfg(not(feature = "enterprise"))]
    assert!(
        !reported.sso_enabled,
        "open build must report sso_enabled=false"
    );
    #[cfg(feature = "enterprise")]
    assert!(
        reported.sso_enabled,
        "every licensed enterprise build grants SSO"
    );
}

#[test]
fn stale_pre_v2_sso_false_cannot_withhold_a_licensed_feature() {
    let mut stored = TierLimits::for_tier_unoverridden(OrganizationTier::Unrestricted);
    stored.sso_enabled = false;
    assert_eq!(
        clamp_to_build(stored).sso_enabled,
        crate::handlers::capabilities::SSO_AVAILABLE
    );
}

#[test]
fn settings_cannot_change_hosted_operator_to_evade_ai_allowance() {
    assert!(validate_operator_provenance(
        Some(nanosiem_core::EntitlementOperator::SelfRun),
        nanosiem_core::EntitlementOperator::Hosted,
    )
    .is_err());
    assert!(validate_operator_provenance(
        Some(nanosiem_core::EntitlementOperator::Hosted),
        nanosiem_core::EntitlementOperator::Hosted,
    )
    .is_ok());
}

#[test]
fn capabilities_and_tier_agree_on_sso() {
    let caps = crate::handlers::capabilities::capabilities_response(
        crate::handlers::capabilities::SSO_AVAILABLE,
    );
    let tier = clamp_to_build(TierLimits::for_tier_unoverridden(
        OrganizationTier::Unrestricted,
    ));
    assert_eq!(caps.capabilities.sso, tier.sso_enabled);
}
