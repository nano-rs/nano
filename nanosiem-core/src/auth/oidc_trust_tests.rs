// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5238: trust-anchor change detection for OIDC provider updates.

use super::{OidcTrustChange, StoredTrust};
use crate::auth::sso_policy::SsoAccessPolicy;
use crate::auth::types::UpdateOidcProviderRequest;

const ISSUER: &str = "https://idp.example.test";
const CLIENT: &str = "nano-client";

fn empty() -> UpdateOidcProviderRequest {
    UpdateOidcProviderRequest {
        name: None,
        issuer: None,
        client_id: None,
        client_secret: None,
        scopes: None,
        group_claim: None,
        enabled: None,
        access_policy: None,
        google_service_account: None,
        clear_google_service_account: false,
    }
}

fn stored<'a>(
    enabled: bool,
    group_claim: Option<&'static str>,
    policy: &'a SsoAccessPolicy,
) -> StoredTrust<'a> {
    StoredTrust {
        enabled,
        issuer: ISSUER,
        client_id: CLIENT,
        group_claim,
        access_policy: policy,
    }
}

fn change(stored_enabled: bool, request: &UpdateOidcProviderRequest) -> OidcTrustChange {
    let policy = SsoAccessPolicy::default();
    OidcTrustChange::between(stored(stored_enabled, Some("groups"), &policy), request)
}

fn change_with(
    group_claim: Option<&'static str>,
    policy: &SsoAccessPolicy,
    request: &UpdateOidcProviderRequest,
) -> OidcTrustChange {
    OidcTrustChange::between(stored(true, group_claim, policy), request)
}

#[test]
fn settings_only_edits_are_not_trust_changes() {
    let mut request = empty();
    request.name = Some("Renamed".into());
    request.client_secret = Some("rotated".into());
    request.scopes = Some(vec!["openid".into(), "email".into()]);
    request.group_claim = Some("groups".into());
    request.access_policy = Some(Default::default());
    request.clear_google_service_account = true;
    for stored_enabled in [true, false] {
        let c = change(stored_enabled, &request);
        assert!(!c.requires_admin(), "{c:?}");
        assert!(c.changed_fields().is_empty());
    }
}

#[test]
fn resending_the_stored_values_is_not_a_change() {
    // The settings form re-submits client_id and enabled on every save.
    let mut request = empty();
    request.issuer = Some(ISSUER.into());
    request.client_id = Some(CLIENT.into());
    request.enabled = Some(true);
    assert_eq!(change(true, &request), OidcTrustChange::default());
}

#[test]
fn enabling_a_disabled_provider_is_a_trust_change() {
    let mut request = empty();
    request.enabled = Some(true);
    let c = change(false, &request);
    assert!(c.enabling && c.requires_admin());
    assert_eq!(c.changed_fields(), vec!["enabled"]);
}

#[test]
fn disabling_is_never_a_trust_change() {
    let mut request = empty();
    request.enabled = Some(false);
    assert!(!change(true, &request).requires_admin());
    assert!(!change(false, &request).requires_admin());
}

#[test]
fn a_new_issuer_is_a_trust_change() {
    let mut request = empty();
    request.issuer = Some("https://attacker.example.test".into());
    let c = change(true, &request);
    assert!(c.issuer && !c.client_id && !c.enabling);
    assert!(c.requires_admin());
    assert_eq!(c.changed_fields(), vec!["issuer"]);
}

#[test]
fn issuer_comparison_is_exact() {
    // The `iss` claim is compared exactly, so a trailing slash is a different
    // issuer and must be treated as one (fail closed).
    let mut request = empty();
    request.issuer = Some(format!("{ISSUER}/"));
    assert!(change(true, &request).issuer);
}

#[test]
fn a_new_client_id_is_a_trust_change() {
    let mut request = empty();
    request.client_id = Some("other-client".into());
    let c = change(true, &request);
    assert!(c.client_id && !c.issuer);
    assert!(c.requires_admin());
}

#[test]
fn a_disable_does_not_launder_an_issuer_change() {
    let mut request = empty();
    request.enabled = Some(false);
    request.issuer = Some("https://attacker.example.test".into());
    assert!(change(true, &request).requires_admin());
}

// ---- group claim (review follow-up) ----

#[test]
fn a_new_group_claim_is_a_trust_change() {
    // Repointing membership at another claim changes which mapped groups,
    // Admins included, a sign-in receives.
    let mut request = empty();
    request.group_claim = Some("roles".into());
    let c = change(true, &request);
    assert!(c.group_claim && c.requires_admin());
    assert_eq!(c.changed_fields(), vec!["group_claim"]);
    // An unsupported claim name is still a change (fail closed).
    request.group_claim = Some("nickname".into());
    assert!(change(true, &request).group_claim);
}

#[test]
fn resending_the_stored_group_claim_is_not_a_change() {
    let policy = SsoAccessPolicy::default();
    let mut request = empty();
    request.group_claim = Some("roles".into());
    assert!(!change_with(Some("roles"), &policy, &request).requires_admin());
    request.group_claim = Some("groups".into());
    assert!(!change_with(Some("groups"), &policy, &request).requires_admin());
}

#[test]
fn narrowing_an_unset_group_claim_to_groups_is_not_a_change() {
    // The form pre-fills `groups` for a provider stored without a claim.
    let policy = SsoAccessPolicy::default();
    let mut request = empty();
    request.group_claim = Some("groups".into());
    assert!(!change_with(None, &policy, &request).requires_admin());
    request.group_claim = Some("roles".into());
    assert!(change_with(None, &policy, &request).group_claim);
}

#[test]
fn a_disable_does_not_launder_a_group_claim_change() {
    let mut request = empty();
    request.enabled = Some(false);
    request.group_claim = Some("roles".into());
    assert!(change(true, &request).requires_admin());
}

// ---- admission policy and Google Directory credential ----

#[test]
fn widening_admission_is_a_trust_change() {
    let invite_only = SsoAccessPolicy {
        mapped_groups_only: false,
        ..Default::default()
    };
    let mut request = empty();
    request.access_policy = Some(SsoAccessPolicy::default());
    assert!(change_with(Some("groups"), &invite_only, &request).admission);

    let stored = SsoAccessPolicy {
        verified_domains: vec!["corp.example".into()],
        ..Default::default()
    };
    for widened in [
        SsoAccessPolicy {
            verified_domains: vec!["corp.example".into(), "attacker.example".into()],
            ..Default::default()
        },
        SsoAccessPolicy {
            verified_domains: vec!["corp.example".into()],
            entra_tenant_id: Some(uuid::Uuid::new_v4()),
            ..Default::default()
        },
        SsoAccessPolicy {
            verified_domains: vec!["corp.example".into()],
            google_delegated_admin: Some("admin@attacker.example".into()),
            ..Default::default()
        },
    ] {
        request.access_policy = Some(widened.clone());
        let c = change_with(Some("groups"), &stored, &request);
        assert!(c.admission && c.requires_admin(), "{widened:?}");
        assert_eq!(c.changed_fields(), vec!["access_policy"]);
    }
}

#[test]
fn resending_or_narrowing_admission_is_not_a_change() {
    let stored = SsoAccessPolicy {
        mapped_groups_only: true,
        entra_tenant_id: Some(uuid::Uuid::new_v4()),
        verified_domains: vec!["a.example".into(), "b.example".into()],
        google_delegated_admin: Some("admin@a.example".into()),
    };
    let mut request = empty();
    request.access_policy = Some(stored.clone());
    assert!(!change_with(Some("groups"), &stored, &request).requires_admin());
    // Narrowing that keeps the tenant, or clears it along with every domain.
    request.access_policy = Some(SsoAccessPolicy {
        mapped_groups_only: false,
        entra_tenant_id: stored.entra_tenant_id,
        verified_domains: vec!["a.example".into()],
        google_delegated_admin: None,
    });
    assert!(!change_with(Some("groups"), &stored, &request).requires_admin());
    request.access_policy = Some(SsoAccessPolicy {
        mapped_groups_only: false,
        entra_tenant_id: None,
        verified_domains: vec![],
        google_delegated_admin: None,
    });
    assert!(!change_with(Some("groups"), &stored, &request).requires_admin());
}

/// NAN-5266 L1: on a non-Microsoft issuer, verified domains apply only while
/// no Entra tenant is set, so clearing the tenant while keeping a domain
/// switches generic domain trust on: administrator authority.
#[test]
fn clearing_the_tenant_over_kept_domains_is_widening_off_microsoft() {
    let stored_policy = SsoAccessPolicy {
        entra_tenant_id: Some(uuid::Uuid::new_v4()),
        verified_domains: vec!["a.example".into()],
        ..Default::default()
    };
    let cleared = SsoAccessPolicy {
        entra_tenant_id: None,
        verified_domains: vec!["a.example".into()],
        ..Default::default()
    };
    let mut request = empty();
    request.access_policy = Some(cleared.clone());
    let c = change_with(Some("groups"), &stored_policy, &request);
    assert!(c.admission && c.requires_admin());

    // Same edit while the issuer is (or becomes) a Microsoft one: the
    // domains stay inert without a tenant, so it is a narrowing.
    for microsoft in [
        "https://login.microsoftonline.com/11111111-1111-4111-8111-111111111111/v2.0",
        "https://contoso.b2clogin.com/tfp/x/v2.0/",
    ] {
        let stored = StoredTrust {
            enabled: true,
            issuer: microsoft,
            client_id: CLIENT,
            group_claim: Some("groups"),
            access_policy: &stored_policy,
        };
        assert!(!OidcTrustChange::between(stored, &request).admission, "{microsoft}");
    }
    // The issuer moving OFF Microsoft in the same update is judged on the
    // new issuer.
    let stored = StoredTrust {
        enabled: true,
        issuer: "https://login.microsoftonline.com/11111111-1111-4111-8111-111111111111/v2.0",
        client_id: CLIENT,
        group_claim: Some("groups"),
        access_policy: &stored_policy,
    };
    request.issuer = Some(ISSUER.into());
    assert!(OidcTrustChange::between(stored, &request).admission);
}

#[test]
fn a_google_service_account_key_is_a_trust_change_but_clearing_is_not() {
    let mut request = empty();
    request.google_service_account = Some("{}".into());
    let c = change(true, &request);
    assert!(c.google_service_account && c.requires_admin());
    let mut request = empty();
    request.clear_google_service_account = true;
    assert!(!change(true, &request).requires_admin());
}
