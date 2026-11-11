// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5238: which OIDC provider edits change who the tenant trusts.
//!
//! Sign-in resolves an account by `(oidc_provider_id, oidc_subject)`, or by
//! email for an account not yet linked. Whoever controls a provider's trust
//! anchors therefore controls which external identities become which local
//! accounts — including administrators. Those edits need administrator
//! authority, not just `settings:system`:
//!
//! - turning a provider on (`enabled` false -> true);
//! - `issuer` — the IdP whose discovery document, JWKS and `iss` claim are
//!   trusted (there are no separate discovery/JWKS/key URL fields: all of them
//!   are derived from the issuer);
//! - `client_id` — the audience ID tokens must be minted for;
//! - `group_claim` — which token claim (`groups` / `roles`) is read as IdP
//!   group membership, and so which mapped local groups (Admins included) a
//!   sign-in receives. Narrowing an unset claim (groups, falling back to
//!   roles) to exactly `groups` removes a source and is not a change;
//! - admission / account-resolution settings in `access_policy` that WIDEN
//!   who is admitted or linked: turning mapped-group JIT on, a new Entra
//!   tenant ID, a verified domain (Entra or generic OIDC) that was not trusted
//!   before, clearing the Entra tenant while verified domains remain on a
//!   non-Microsoft issuer (they then start to apply; an email in them
//!   links onto an existing local account), or a new Google delegated admin;
//! - a new Google service-account key — the Directory credential that
//!   supplies Google group membership.
//!
//! Everything else stays on `settings:system`: display name, client secret
//! (it must match the unchanged client ID at the IdP), scopes (which claims
//! are requested, not which are trusted), disabling, removing a Google key,
//! and policy edits that only narrow admission (JIT off, a domain removed,
//! the Entra tenant or Google delegated admin cleared).
//!
//! Changes are computed against the STORED row, so re-sending the current
//! value (the settings form re-submits the whole provider) is not a change.

use super::sso_policy::SsoAccessPolicy;
use super::types::{OidcProvider, UpdateOidcProviderRequest};

/// The stored provider settings that [`OidcTrustChange`] compares against.
#[derive(Debug, Clone, Copy)]
pub struct StoredTrust<'a> {
    pub enabled: bool,
    pub issuer: &'a str,
    pub client_id: &'a str,
    pub group_claim: Option<&'a str>,
    pub access_policy: &'a SsoAccessPolicy,
}

impl<'a> StoredTrust<'a> {
    pub fn of(provider: &'a OidcProvider) -> Self {
        Self {
            enabled: provider.enabled,
            issuer: &provider.issuer,
            client_id: &provider.client_id,
            group_claim: provider.group_claim.as_deref(),
            access_policy: &provider.access_policy,
        }
    }
}

/// The trust-anchor changes an update would make to a stored provider.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OidcTrustChange {
    /// `enabled` goes from false to true.
    pub enabling: bool,
    /// `issuer` changes. Existing account links are cleared when this is set.
    pub issuer: bool,
    /// `client_id` changes.
    pub client_id: bool,
    /// `group_claim` changes which claim supplies IdP group membership.
    pub group_claim: bool,
    /// `access_policy` widens admission or email-based account linking.
    pub admission: bool,
    /// A Google service-account key is supplied.
    pub google_service_account: bool,
}

/// Whether `requested` reads group membership from a claim the stored setting
/// does not. An unset claim reads `groups`, falling back to `roles`; asking
/// for exactly `groups` only drops the fallback.
fn group_claim_changes(stored: Option<&str>, requested: Option<&str>) -> bool {
    match (stored, requested) {
        (_, None) => false,
        (None, Some("groups")) => false,
        (stored, Some(requested)) => stored != Some(requested),
    }
}

/// Whether `requested` admits or links anyone the stored policy does not.
/// `issuer` is the issuer the provider will have after the update.
fn admission_widens(
    stored: &SsoAccessPolicy,
    requested: Option<&SsoAccessPolicy>,
    issuer: &str,
) -> bool {
    let Some(requested) = requested else {
        return false;
    };
    // NAN-5266 L1: on a non-Microsoft issuer, verified domains apply only
    // while no Entra tenant is set, so clearing the tenant switches them on.
    let clears_tenant_over_domains = stored.entra_tenant_id.is_some()
        && requested.entra_tenant_id.is_none()
        && !requested.verified_domains.is_empty()
        && !super::sso_policy::is_microsoft_issuer(issuer);
    clears_tenant_over_domains
        || (requested.mapped_groups_only && !stored.mapped_groups_only)
        || (requested.entra_tenant_id.is_some()
            && requested.entra_tenant_id != stored.entra_tenant_id)
        || requested
            .verified_domains
            .iter()
            .any(|domain| !stored.verified_domains.contains(domain))
        || (requested.google_delegated_admin.is_some()
            && requested.google_delegated_admin != stored.google_delegated_admin)
}

impl OidcTrustChange {
    /// Compare an update request against the stored provider it would modify.
    pub fn of_update(existing: &OidcProvider, request: &UpdateOidcProviderRequest) -> Self {
        Self::between(StoredTrust::of(existing), request)
    }

    /// Field-level form of [`Self::of_update`], so the rule is testable without
    /// building a full provider row.
    pub fn between(stored: StoredTrust<'_>, request: &UpdateOidcProviderRequest) -> Self {
        Self {
            enabling: !stored.enabled && request.enabled == Some(true),
            issuer: request
                .issuer
                .as_deref()
                .is_some_and(|issuer| issuer != stored.issuer),
            client_id: request
                .client_id
                .as_deref()
                .is_some_and(|client_id| client_id != stored.client_id),
            group_claim: group_claim_changes(stored.group_claim, request.group_claim.as_deref()),
            admission: admission_widens(
                stored.access_policy,
                request.access_policy.as_ref(),
                request.issuer.as_deref().unwrap_or(stored.issuer),
            ),
            google_service_account: request.google_service_account.is_some(),
        }
    }

    /// True when the update needs administrator authority.
    pub fn requires_admin(&self) -> bool {
        !self.changed_fields().is_empty()
    }

    /// Names of the trust settings that change (for audit details).
    pub fn changed_fields(&self) -> Vec<&'static str> {
        [
            (self.enabling, "enabled"),
            (self.issuer, "issuer"),
            (self.client_id, "client_id"),
            (self.group_claim, "group_claim"),
            (self.admission, "access_policy"),
            (self.google_service_account, "google_service_account"),
        ]
        .into_iter()
        .filter_map(|(changed, name)| changed.then_some(name))
        .collect()
    }
}

#[cfg(test)]
#[path = "oidc_trust_tests.rs"]
mod tests;
