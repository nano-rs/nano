// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3378: `/api/settings/tier` clamps SSO to the build.

use super::*;
use nanosiem_core::{OrganizationTier, TierLimits};

/// NAN-3378: the tier row grants SSO on `unrestricted`, but an open build
/// has no OIDC handlers. `/api/settings/tier` must agree with
/// `/api/capabilities` instead of advertising a surface that 404s.
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
        "enterprise build keeps the plan grant"
    );
}

#[test]
fn clamp_never_grants_sso_the_plan_withheld() {
    let mut stored = TierLimits::for_tier_unoverridden(OrganizationTier::Unrestricted);
    stored.sso_enabled = false;
    assert!(!clamp_to_build(stored).sso_enabled);
}

#[test]
fn capabilities_and_tier_agree_on_sso() {
    let caps = futures::executor::block_on(crate::handlers::capabilities::get_capabilities());
    let tier = clamp_to_build(TierLimits::for_tier_unoverridden(
        OrganizationTier::Unrestricted,
    ));
    assert_eq!(caps.0.capabilities.sso, tier.sso_enabled);
}
