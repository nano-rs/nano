// SPDX-License-Identifier: AGPL-3.0-or-later
//! SSO admission policy (NAN-3904 / NAN-3908 / NAN-3935).
//!
//! Persisted per OIDC provider (`oidc_providers.access_policy`) and evaluated
//! only against IdP membership that came from a validated ID token, a resolved
//! Entra groups overage, or a delegated Google Directory lookup.
//!
//! The IdP-group -> local-group mappings themselves live in
//! `oidc_group_mappings`; this policy carries only the admission switch and
//! the provider-specific verification settings.
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(default)]
pub struct SsoAccessPolicy {
    /// First-time SSO users are created only when the IdP asserts a mapped
    /// group. `false` means invitation-only; it never opens JIT to everyone.
    pub mapped_groups_only: bool,
    /// Microsoft Entra ID directory (tenant) id. Entra tokens carry no
    /// `email_verified`; with this set, an email in an exact
    /// `verified_domains` entry is trusted for account linking.
    pub entra_tenant_id: Option<Uuid>,
    /// Exact lowercase domains the Entra tenant has verified.
    pub verified_domains: Vec<String>,
    /// Google Workspace administrator the service account impersonates to
    /// read group membership (Google ID tokens carry no groups claim).
    pub google_delegated_admin: Option<String>,
}

impl Default for SsoAccessPolicy {
    fn default() -> Self {
        Self {
            mapped_groups_only: true,
            entra_tenant_id: None,
            verified_domains: vec![],
            google_delegated_admin: None,
        }
    }
}

/// Validate one IdP group name as a mapping key (exact match, no trimming).
pub fn validate_idp_group(group: &str) -> Result<(), &'static str> {
    if group.is_empty()
        || group.len() > 512
        || group.trim() != group
        || group.chars().any(char::is_control)
    {
        return Err("Invalid SSO group mapping");
    }
    Ok(())
}

impl SsoAccessPolicy {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.verified_domains.len() > 64 || self.entra_tenant_id.is_some_and(|id| id.is_nil()) {
            return Err("Invalid SSO policy");
        }
        for domain in &self.verified_domains {
            if domain.is_empty()
                || domain.len() > 253
                || domain != &domain.to_ascii_lowercase()
                || domain.split('.').count() < 2
                || domain.split('.').any(|p| {
                    p.is_empty()
                        || p.len() > 63
                        || p.starts_with('-')
                        || p.ends_with('-')
                        || !p
                            .bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                })
            {
                return Err("Use exact lowercase verified domains");
            }
        }
        if self.google_delegated_admin.as_ref().is_some_and(|v| {
            v.len() > 254
                || v.trim() != v
                || v.split('@').count() != 2
                || v.starts_with('@')
                || v.ends_with('@')
                || v.chars().any(|c| c.is_control() || c.is_whitespace())
        }) {
            return Err("Invalid delegated administrator");
        }
        Ok(())
    }

    /// Admission decision for one sign-in.
    ///
    /// * `invited` — the account already exists and was not created by SSO
    ///   JIT (local, invited, or pre-dating group admission): always admitted.
    /// * otherwise the IdP must assert at least one mapped group, membership
    ///   must be known (no unresolved Entra overage, Google lookup configured),
    ///   and the provider must be in mapped-group mode.
    pub fn admits(&self, mapped_groups_asserted: bool, invited: bool, membership_known: bool) -> bool {
        invited || (self.mapped_groups_only && membership_known && mapped_groups_asserted)
    }

    /// Whether the IdP verified this email, for linking onto an existing
    /// local account or creating a new one. Only called after signature,
    /// exact issuer, audience and nonce validation.
    #[cfg(feature = "enterprise")]
    pub fn verifies_email(&self, claims: &super::IdTokenClaims) -> bool {
        if claims.verified_email() {
            return true;
        }
        let Some(tid) = claims.entra_tenant().and_then(|s| Uuid::parse_str(s).ok()) else {
            return false;
        };
        self.entra_tenant_id == Some(tid)
            && claims.email.as_ref().is_some_and(|email| {
                let parts: Vec<_> = email.split('@').collect();
                parts.len() == 2
                    && !parts[0].is_empty()
                    && !email.chars().any(char::is_whitespace)
                    && self
                        .verified_domains
                        .iter()
                        .any(|domain| domain.eq_ignore_ascii_case(parts[1]))
            })
    }
}
