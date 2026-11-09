// SPDX-License-Identifier: AGPL-3.0-or-later

//! Backward-compatibility scenarios for the online check-in path.
//!
//! nano-main's `GET /api/license/status` answers paid, exempt and legacy
//! managed deployments with `{valid, tier, locked, lockedReason, expiresAt,
//! graceEndsAt}` only. It never sends the v2 edition/operator/capacity tuple
//! on that path, so these payloads must still admit every licensed feature.

use super::*;
use crate::{Entitlement, EntitlementEdition, EntitlementOperator, TierLimits};
use chrono::Duration as ChronoDuration;

fn response(json: serde_json::Value) -> LicenseResponse {
    serde_json::from_value(json).expect("nano-main licence payload deserializes")
}

fn admitted_entitlement(status: &LicenseStatus, operator: EntitlementOperator) -> Entitlement {
    let tier = status.tier.as_deref().map(online_tier_claim).expect("tier");
    Entitlement::from_license_tier_claim(tier, operator).expect("tier claim normalizes")
}

/// The exact shape a frozen managed Compose tenant (DEPLOYMENT_MODE=managed,
/// NANO_TIER=hobby, active Stripe subscription) receives today.
#[test]
fn legacy_managed_hobby_payload_admits_every_licensed_feature() {
    let now = Utc::now();
    let resp = response(serde_json::json!({
        "valid": true,
        "tier": "hobby",
        "locked": false,
        "lockedReason": null,
        "expiresAt": (now + ChronoDuration::days(26)).to_rfc3339(),
        "graceEndsAt": null,
    }));
    let status = LicenseChecker::compute_new_status(&resp);
    assert_eq!(status.state, LicenseState::Active);
    assert!(!status.offline);
    assert!(status.last_checked_at.is_some());
    assert_eq!(status.effective(now).state, LicenseState::Active);
    // A successful observation is a valid bounded-outage cache seed.
    assert_eq!(
        status.for_online_admission().state,
        LicenseState::Active,
        "a restart after this check-in must not lock the tenant"
    );

    // DEPLOYMENT_MODE=managed reconciles the local operator to Hosted.
    let entitlement = admitted_entitlement(&status, EntitlementOperator::Hosted);
    assert_eq!(entitlement.edition, EntitlementEdition::Licensed);
    assert_eq!(entitlement.operator, EntitlementOperator::Hosted);
    assert_eq!(entitlement.capacity_gb_per_day, Some(2.0));
    let limits = TierLimits::for_entitlement_unoverridden(entitlement);
    assert!(limits.sso_enabled);
    assert!(limits.ha_enabled);
    assert_eq!(limits.max_detection_rules, None);
    assert_eq!(limits.max_team_members, None);
}

/// Billing-lock-exempt organizations (internal, demo, org.nano.rs) receive no
/// expiry at all.
#[test]
fn exempt_payload_without_expiry_stays_active() {
    let resp = response(serde_json::json!({
        "valid": true,
        "tier": "starter",
        "locked": false,
        "lockedReason": null,
        "expiresAt": null,
        "graceEndsAt": null,
    }));
    let mut status = LicenseChecker::compute_new_status(&resp);
    // No contract expiry: while it keeps checking in, it stays active
    // indefinitely (the 14-day outage bound still applies between checks).
    let later = Utc::now() + ChronoDuration::days(3650);
    status.last_checked_at = Some(later);
    assert_eq!(status.effective(later).state, LicenseState::Active);
}

/// A past-due/canceled subscription inside its Stripe grace keeps licensed
/// features (with warnings) until the exclusive grace boundary.
#[test]
fn subscription_grace_payload_keeps_licensed_features_until_grace_end() {
    let now = Utc::now();
    let grace_end = now + ChronoDuration::days(5);
    let resp = response(serde_json::json!({
        "valid": false,
        "tier": "hobby",
        "locked": false,
        "lockedReason": null,
        "expiresAt": grace_end.to_rfc3339(),
        "graceEndsAt": grace_end.to_rfc3339(),
    }));
    let status = LicenseChecker::compute_new_status(&resp);
    assert_eq!(status.state, LicenseState::GracePeriod);
    assert_eq!(status.effective(now).state, LicenseState::GracePeriod);
    assert_eq!(status.effective(grace_end).state, LicenseState::Locked);
}

/// Every tier value nano-main can emit for a live deployment (its `tierEnum`
/// plus the self-run `licensed` value) and every retired alias normalizes to
/// the licensed edition, preserving the local operator.
#[test]
fn every_issued_tier_value_normalizes_to_licensed() {
    for tier in [
        "hobby",
        "startup",
        "growth",
        "team",
        "starter",
        "business",
        "pro",
        "enterprise",
        "unrestricted",
        "licensed",
    ] {
        assert_eq!(online_tier_claim(tier), tier, "{tier} is a known claim");
        for operator in [EntitlementOperator::Hosted, EntitlementOperator::SelfRun] {
            let entitlement = Entitlement::from_license_tier_claim(tier, operator)
                .unwrap_or_else(|error| panic!("{tier}: {error}"));
            assert_eq!(entitlement.edition, EntitlementEdition::Licensed, "{tier}");
            assert_eq!(entitlement.operator, operator, "{tier}");
        }
    }
}

/// A tier string this build does not know must not fail the whole check (and
/// with it admission) when nano-main has authenticated the deployment and
/// declared it valid.
#[test]
fn unrecognized_tier_claim_admits_as_licensed() {
    for tier in ["self-run", "hosted", "trial", "Some Future Plan"] {
        assert_eq!(online_tier_claim(tier), "licensed");
        let entitlement =
            Entitlement::from_license_tier_claim(online_tier_claim(tier), EntitlementOperator::Hosted)
                .unwrap();
        assert_eq!(entitlement.edition, EntitlementEdition::Licensed);
        assert_eq!(entitlement.capacity_gb_per_day, None);
    }
}

/// The trial-licence issuer adds an `entitlement` object to the same
/// response. A build that predates it must still deserialize the response and
/// admit on `valid`.
#[test]
fn additive_entitlement_object_is_tolerated() {
    let now = Utc::now();
    let resp = response(serde_json::json!({
        "valid": true,
        "tier": "licensed",
        "locked": false,
        "lockedReason": null,
        "expiresAt": (now + ChronoDuration::days(90)).to_rfc3339(),
        "graceEndsAt": (now + ChronoDuration::days(97)).to_rfc3339(),
        "entitlement": {
            "licenseId": "lic_trial",
            "edition": "licensed",
            "operator": "self-run",
            "kind": "trial",
            "capacityGbPerDay": null,
        },
    }));
    let status = LicenseChecker::compute_new_status(&resp);
    assert_eq!(status.effective(now).state, LicenseState::Active);
}

/// The full trial shape the nano-main issuer emits is carried through so the
/// trial window drives grace and hard stop.
#[test]
fn full_trial_entitlement_is_carried_and_drives_the_window() {
    let now = Utc::now();
    let expires = now + ChronoDuration::days(1);
    let grace = expires + ChronoDuration::days(7);
    let resp = response(serde_json::json!({
        "valid": true,
        "tier": "licensed",
        "locked": false,
        "lockedReason": null,
        "expiresAt": expires.to_rfc3339(),
        "graceEndsAt": grace.to_rfc3339(),
        "entitlement": {
            "licenseId": "lic_trial",
            "edition": "licensed",
            "operator": "self-run",
            "offering": "self-run",
            "kind": "trial",
            "capacityGbPerDay": 5,
            "startsAt": (now - ChronoDuration::days(89)).to_rfc3339(),
            "expiresAt": expires.to_rfc3339(),
            "graceEndsAt": grace.to_rfc3339(),
            "state": "active",
            "daysRemaining": 1,
            "revision": 1,
        },
    }));
    let status = LicenseChecker::compute_new_status(&resp);
    assert!(status.trial_entitlement().is_some());
    assert_eq!(status.effective(now).state, LicenseState::Active);
    assert_eq!(
        status.effective(now + ChronoDuration::days(3)).state,
        LicenseState::GracePeriod
    );
    assert_eq!(status.effective(grace).state, LicenseState::Locked);
}

// ---------------------------------------------------------------------------
// NAN-5055: grandfathered deployment grant on the online check-in.
// ---------------------------------------------------------------------------

fn grant_json(overrides: serde_json::Value) -> serde_json::Value {
    let mut grant = serde_json::json!({
        "licenseId": "egr_fixture",
        "edition": "licensed",
        "operator": "hosted",
        "offering": "hosted",
        "kind": "paid",
        "grant": "grandfathered",
        "aiCreditsPerMonth": 3000,
        "capacityGbPerDay": null,
        "startsAt": "2026-11-08T00:00:00.000Z",
        "expiresAt": null,
        "graceEndsAt": null,
        "state": "active",
        "daysRemaining": null,
        "revision": 1,
    });
    for (key, value) in overrides.as_object().unwrap() {
        grant[key] = value.clone();
    }
    grant
}

fn paid_hobby(entitlement: serde_json::Value) -> LicenseResponse {
    response(serde_json::json!({
        "valid": true,
        "tier": "hobby",
        "locked": false,
        "lockedReason": null,
        "expiresAt": (Utc::now() + ChronoDuration::days(20)).to_rfc3339(),
        "graceEndsAt": null,
        "entitlement": entitlement,
    }))
}

/// The original managed tenant: legacy `hobby` tier, managed (Hosted)
/// operator, grandfathered grant of its pre-v2 3,000 credits/month.
#[test]
fn original_tenant_on_legacy_hobby_gets_licensed_features_and_its_credits() {
    let resp = paid_hobby(grant_json(serde_json::json!({})));
    assert!(resp.entitlement.is_none(), "a grant is not a trial window");
    let status = LicenseChecker::compute_new_status(&resp);
    assert_eq!(status.effective(Utc::now()).state, LicenseState::Active);
    let granted = admitted_grant_ai_credits(&status, &resp);
    assert_eq!(granted, Some(3000));

    let entitlement = admitted_entitlement(&status, EntitlementOperator::Hosted);
    assert_eq!(entitlement.edition, EntitlementEdition::Licensed);
    let limits = TierLimits::for_entitlement_with_granted_ai_credits(entitlement, granted);
    assert_eq!(limits.ai_credits_per_month, Some(3000));
    assert!(limits.sso_enabled && limits.ha_enabled);
    assert_eq!(limits.max_detection_rules, None, "hobby's old 15-rule cap is gone");
    assert_eq!(limits.max_team_members, None);
}

/// A normal hosted tenant (no grant) keeps the provisioned env ceiling.
#[test]
fn normal_hosted_tenant_is_unchanged() {
    for entitlement in [serde_json::Value::Null] {
        let resp = paid_hobby(entitlement);
        let status = LicenseChecker::compute_new_status(&resp);
        let granted = admitted_grant_ai_credits(&status, &resp);
        assert_eq!(granted, None);
        let with = TierLimits::for_entitlement_with_granted_ai_credits(
            admitted_entitlement(&status, EntitlementOperator::Hosted),
            granted,
        );
        let without = TierLimits::for_entitlement(admitted_entitlement(
            &status,
            EntitlementOperator::Hosted,
        ));
        assert_eq!(with.ai_credits_per_month, without.ai_credits_per_month);
    }
}

/// Missing, malformed, unrecognised or out-of-range grants are ignored; the
/// check-in still admits on `valid` but nothing escalates.
#[test]
fn invalid_or_unhonoured_grants_cannot_escalate() {
    for overrides in [
        serde_json::json!({ "kind": "trial" }),
        serde_json::json!({ "grant": "enterprise_forever" }),
        serde_json::json!({ "state": "revoked" }),
        serde_json::json!({ "edition": "open" }),
        serde_json::json!({ "aiCreditsPerMonth": 0 }),
        serde_json::json!({ "aiCreditsPerMonth": -5 }),
        serde_json::json!({ "aiCreditsPerMonth": 2_147_483_648_u64 }),
        serde_json::json!({ "aiCreditsPerMonth": "unlimited" }),
        serde_json::json!({ "aiCreditsPerMonth": null }),
    ] {
        let resp = paid_hobby(grant_json(overrides.clone()));
        assert!(resp.grant.is_none(), "{overrides} must not be honoured");
        let status = LicenseChecker::compute_new_status(&resp);
        assert_eq!(status.state, LicenseState::Active, "{overrides}: admission is unaffected");
        assert_eq!(admitted_grant_ai_credits(&status, &resp), None, "{overrides}");
    }
}

/// A grant never admits: a locked response clears it even if one were sent.
#[test]
fn locked_response_never_honours_a_grant() {
    let resp = response(serde_json::json!({
        "valid": false,
        "tier": "hobby",
        "locked": true,
        "lockedReason": "Subscription canceled",
        "expiresAt": null,
        "graceEndsAt": null,
        "entitlement": grant_json(serde_json::json!({})),
    }));
    let status = LicenseChecker::compute_new_status(&resp);
    assert_eq!(status.state, LicenseState::Locked);
    assert_eq!(admitted_grant_ai_credits(&status, &resp), None);
}

/// During Stripe grace the deployment is still admitted, so its grant holds.
#[test]
fn grace_response_keeps_the_grant() {
    let grace_end = Utc::now() + ChronoDuration::days(5);
    let resp = response(serde_json::json!({
        "valid": false,
        "tier": "hobby",
        "locked": false,
        "lockedReason": null,
        "expiresAt": grace_end.to_rfc3339(),
        "graceEndsAt": grace_end.to_rfc3339(),
        "entitlement": grant_json(serde_json::json!({ "aiCreditsPerMonth": 10000 })),
    }));
    let status = LicenseChecker::compute_new_status(&resp);
    assert_eq!(status.state, LicenseState::GracePeriod);
    assert_eq!(admitted_grant_ai_credits(&status, &resp), Some(10000));
}

/// A grant on a self-run deployment does not impose a cap on customer AI.
#[test]
fn self_run_operator_stays_uncapped_even_with_a_grant() {
    let resp = paid_hobby(grant_json(serde_json::json!({})));
    let status = LicenseChecker::compute_new_status(&resp);
    let limits = TierLimits::for_entitlement_with_granted_ai_credits(
        admitted_entitlement(&status, EntitlementOperator::SelfRun),
        admitted_grant_ai_credits(&status, &resp),
    );
    assert_eq!(limits.ai_credits_per_month, None);
}

/// NAN-5114: nano-main's FRO-940 release fields are additive. An old payload
/// carries none; a Self-run payload carries the newest release; a malformed
/// value drops only the notice, never the check-in.
#[test]
fn release_fields_are_additive_and_never_fail_the_check_in() {
    let base = serde_json::json!({
        "valid": true, "tier": "licensed", "locked": false,
        "lockedReason": null, "expiresAt": null, "graceEndsAt": null,
    });
    assert_eq!(response(base.clone()).release, None);

    let mut selfrun = base.clone();
    selfrun["latestVersion"] = "2.0.1".into();
    selfrun["releaseNotesUrl"] = "https://nano.rs/docs/releases/v2-0-1".into();
    selfrun["upgradeUrl"] = "https://nano.rs/docs/releases/upgrading".into();
    selfrun["securityRelease"] = true.into();
    let resp = response(selfrun.clone());
    let release = resp.release.as_ref().expect("release notice");
    assert_eq!(release.latest_version, "2.0.1");
    assert!(release.security_release);
    assert!(release.is_newer_than("2.0.0"));
    assert_eq!(
        LicenseChecker::compute_new_status(&resp).state,
        LicenseState::Active
    );

    // Non-Self-run deployments get explicit nulls / false.
    let mut nulls = base.clone();
    nulls["latestVersion"] = serde_json::Value::Null;
    nulls["releaseNotesUrl"] = serde_json::Value::Null;
    nulls["upgradeUrl"] = serde_json::Value::Null;
    nulls["securityRelease"] = false.into();
    assert_eq!(response(nulls).release, None);

    // Wrong types or a foreign link: the notice is dropped, admission is not.
    let mut malformed = selfrun.clone();
    malformed["latestVersion"] = 201.into();
    let resp = response(malformed);
    assert_eq!(resp.release, None);
    assert!(resp.valid);
    let mut foreign = selfrun;
    foreign["upgradeUrl"] = "https://evil.example/upgrade".into();
    assert_eq!(response(foreign).release, None);
}
