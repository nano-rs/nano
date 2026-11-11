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
    /// Exact lowercase email domains whose addresses this provider is trusted
    /// to have verified.
    ///
    /// * Entra: the domains verified in `entra_tenant_id` (needs the tenant).
    /// * Generic OIDC (Okta, Auth0, Keycloak, ...; NAN-5266): the
    ///   administrator asserts that this IdP only issues addresses in these
    ///   domains to the people who own them (for example, the IdP's email
    ///   attribute is set by the directory, not by users). An address in one
    ///   of them is then treated as verified when the IdP sends no
    ///   `email_verified`; an explicit `false` always wins. Do not list a
    ///   domain for an IdP that lets users register or edit their own email
    ///   address. Free-mail providers and public suffixes are refused, and on
    ///   a Microsoft issuer the tenant ID is required.
    /// * Google: not used (Google always sends `email_verified`).
    ///
    /// Adding a domain widens account linking, so it needs administrator
    /// authority (see `oidc_trust`).
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

/// Google's fixed issuer. Its ID tokens are never a groups source.
pub fn is_google_issuer(issuer: &str) -> bool {
    issuer == "https://accounts.google.com"
}

/// Any Microsoft identity platform issuer: Entra ID in every cloud
/// (public, US Government, China / 21Vianet, legacy Germany), v1
/// (`sts.windows.net`) and v2, and Azure AD B2C / Entra External ID
/// (`*.b2clogin.com`, `*.ciamlogin.com`). Microsoft issuers never get the
/// generic userinfo or verified-domain paths: a multi-tenant or B2C issuer
/// lets anyone mint tokens with an arbitrary, unverified email (nOAuth).
pub fn is_microsoft_issuer(issuer: &str) -> bool {
    let Ok(url) = url::Url::parse(issuer) else {
        return false;
    };
    let Some(host) = url.host_str() else {
        return false;
    };
    let host = host.to_ascii_lowercase();
    matches!(
        host.as_str(),
        "login.microsoftonline.com"
            | "login.microsoftonline.us"
            | "login.partner.microsoftonline.cn"
            | "login.chinacloudapi.cn"
            | "login.microsoftonline.de"
            | "login.microsoft.com"
            | "login.windows.net"
            | "sts.windows.net"
            | "sts.chinacloudapi.cn"
    ) || host.ends_with(".b2clogin.com")
        || host.ends_with(".ciamlogin.com")
        || host.ends_with(".b2clogin.us")
        || host.ends_with(".b2clogin.cn")
}

/// Mailbox providers anyone can sign up to. An address at one of these
/// proves nothing about who owns it, so none can be a verified domain.
const FREE_MAIL_DOMAINS: &[&str] = &[
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com",
    "passport.com", "yahoo.com", "ymail.com", "rocketmail.com", "icloud.com", "me.com",
    "mac.com", "aol.com", "aim.com", "proton.me", "protonmail.com", "protonmail.ch",
    "pm.me", "gmx.com", "gmx.net", "gmx.de", "web.de", "t-online.de", "mail.com",
    "mail.ru", "inbox.ru", "list.ru", "bk.ru", "yandex.com", "yandex.ru", "ya.ru",
    "zoho.com", "zohomail.com", "qq.com", "foxmail.com", "163.com", "126.com",
    "yeah.net", "sina.com", "sina.cn", "sohu.com", "aliyun.com", "naver.com",
    "daum.net", "hanmail.net", "rediffmail.com", "tutanota.com", "tutanota.de",
    "tuta.io", "tuta.com", "fastmail.com", "fastmail.fm", "hey.com", "mailfence.com",
    "posteo.de", "hushmail.com", "inbox.com", "gmx.at", "gmx.ch", "laposte.net",
    "orange.fr", "free.fr", "libero.it", "seznam.cz", "wp.pl", "o2.pl", "interia.pl",
    "duck.com", "skiff.com", "mailinator.com", "guerrillamail.com", "yopmail.com",
];

/// Free-mail brands that also run country domains (`hotmail.fr`,
/// `yahoo.co.uk`, `live.com.au`, ...): refused under any public suffix.
const FREE_MAIL_BRANDS: &[&str] = &[
    "gmail", "googlemail", "hotmail", "outlook", "live", "msn", "yahoo", "ymail", "aol",
    "icloud", "gmx", "yandex", "protonmail", "zoho", "mail",
];

/// Why `domain` cannot be a verified domain, beyond its syntax (NAN-5266).
/// A public suffix (`com`, `co.uk`, `github.io`) or a free-mail provider
/// would make every address there "verified" for account linking.
fn verified_domain_refusal(domain: &str) -> Option<&'static str> {
    if FREE_MAIL_DOMAINS.contains(&domain) {
        return Some("Verified domains cannot be free email providers (for example gmail.com)");
    }
    if domain.split('.').count() == 2 {
        let (first, tld) = domain.split_once('.').unwrap_or_default();
        // Without the bundled list (open build), refuse the common
        // second-level registry shapes: `co.uk`, `com.au`, `ac.jp`, ...
        if tld.len() == 2
            && matches!(
                first,
                "co" | "com" | "net" | "org" | "gov" | "edu" | "ac" | "or" | "ne" | "go"
                    | "gob" | "gouv" | "mil" | "nom" | "ltd" | "plc" | "me" | "info" | "biz"
            )
        {
            return Some("Verified domains cannot be public suffixes (for example co.uk)");
        }
    }
    #[cfg(feature = "enterprise")]
    {
        if psl::suffix(domain.as_bytes())
            .is_some_and(|found| found.is_known() && found.as_bytes() == domain.as_bytes())
        {
            return Some("Verified domains cannot be public suffixes (for example co.uk)");
        }
        if let Some(registrable) = psl::domain_str(domain) {
            let brand = registrable.split('.').next().unwrap_or_default();
            if FREE_MAIL_BRANDS.contains(&brand) || FREE_MAIL_DOMAINS.contains(&registrable) {
                return Some(
                    "Verified domains cannot be free email providers (for example gmail.com)",
                );
            }
        }
    }
    None
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
            if let Some(reason) = verified_domain_refusal(domain) {
                return Err(reason);
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

    /// Settings that are only safe for some issuers (NAN-5266): verified
    /// domains on a Microsoft issuer require the directory (tenant) ID, so a
    /// multi-tenant or B2C issuer can never vouch for an address (nOAuth).
    pub fn validate_for_issuer(&self, issuer: &str) -> Result<(), &'static str> {
        self.validate()?;
        if is_microsoft_issuer(issuer)
            && self.entra_tenant_id.is_none()
            && !self.verified_domains.is_empty()
        {
            return Err(
                "Verified domains on a Microsoft issuer need the directory (tenant) ID",
            );
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
    ///
    /// Always false without a non-empty `email` claim: a verification flag
    /// never vouches for `preferred_username` or any other stand-in.
    ///
    /// Entra: `xms_edov`, or the configured tenant plus a verified domain.
    /// Google: `email_verified` only. Any other issuer: `email_verified`, or
    /// (NAN-5266) an admin-asserted `verified_domains` entry when the IdP sent
    /// NO `email_verified` (an explicit `false` always wins), and only while
    /// no Entra tenant is configured, so domains carried over from an Entra
    /// configuration never start applying to a different issuer.
    #[cfg(feature = "enterprise")]
    pub fn verifies_email(&self, claims: &super::IdTokenClaims) -> bool {
        if !claims
            .email
            .as_deref()
            .is_some_and(|email| !email.trim().is_empty())
        {
            return false;
        }
        if claims.verified_email() {
            return true;
        }
        if let Some(tid) = claims.entra_tenant().and_then(|s| Uuid::parse_str(s).ok()) {
            return self.entra_tenant_id == Some(tid) && self.email_in_verified_domain(claims);
        }
        if is_google_issuer(&claims.iss) || is_microsoft_issuer(&claims.iss) {
            return false;
        }
        claims.email_verified.is_none()
            && self.entra_tenant_id.is_none()
            && self.email_in_verified_domain(claims)
    }

    /// NAN-5274: whether an address pushed by this provider's directory
    /// (SCIM), with no ID token behind it, may link onto an existing local
    /// account that no SSO identity is bound to yet.
    ///
    /// A push carries no `email_verified`, so only the administrator-asserted
    /// verified domains can vouch, under the same issuer rules as a sign-in
    /// that sends no verification flag: Entra needs its tenant ID configured;
    /// any other non-Google issuer needs NO tenant configured (domains carried
    /// over from an Entra setup never apply elsewhere); Google never.
    #[cfg(feature = "enterprise")]
    pub fn trusts_directory_email(&self, issuer: &str, email: &str) -> bool {
        if is_google_issuer(issuer) {
            return false;
        }
        if is_microsoft_issuer(issuer) {
            if self.entra_tenant_id.is_none() {
                return false;
            }
        } else if self.entra_tenant_id.is_some() {
            return false;
        }
        self.domain_is_verified(email)
    }

    #[cfg(feature = "enterprise")]
    fn email_in_verified_domain(&self, claims: &super::IdTokenClaims) -> bool {
        claims
            .email
            .as_ref()
            .is_some_and(|email| self.domain_is_verified(email))
    }

    /// `email` is one `local@domain` address whose domain is an exact,
    /// still-valid verified domain.
    #[cfg(feature = "enterprise")]
    fn domain_is_verified(&self, email: &str) -> bool {
        let parts: Vec<_> = email.split('@').collect();
        parts.len() == 2
            && !parts[0].is_empty()
            && !email.chars().any(char::is_whitespace)
            && self.verified_domains.iter().any(|domain| {
                domain.eq_ignore_ascii_case(parts[1])
                    // A domain stored before free-mail / public-suffix
                    // validation existed is never trusted (NAN-5266 M2).
                    && verified_domain_refusal(&domain.to_ascii_lowercase()).is_none()
            })
    }
}
