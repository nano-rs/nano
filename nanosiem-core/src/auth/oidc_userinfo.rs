// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5266: complete a validated ID token from the provider's userinfo
//! endpoint.
//!
//! In the authorization-code flow, when an access token is issued alongside
//! the ID token, OIDC Core 5.4 lets a provider return the `profile` / `email`
//! scope claims ONLY from userinfo. Okta does exactly that: its ID token then
//! carries base claims (`sub`, `iss`, `aud`, `nonce`, ...) and no `email` or
//! `email_verified`, so a sign-in that never calls userinfo is refused as
//! "email not verified".
//!
//! Rules (all applied after signature, issuer, audience and nonce checks):
//!
//! * **When.** Only for generic OIDC issuers (not Google, not Microsoft),
//!   and only when the ID token lacks `email` or `email_verified`. Google ID
//!   tokens always carry both; Entra keeps its `xms_edov` + tenant-domain
//!   logic and Graph overage path. Their behaviour is unchanged.
//! * **Where.** The endpoint comes from the configured issuer's discovery
//!   document and must be `https` on the issuer's own host and port, with no
//!   credentials or fragment. Okta (org and custom authorization servers),
//!   Auth0, Keycloak, Ping and OneLogin all serve userinfo from the issuer
//!   host. A provider that puts userinfo elsewhere is not followed — the
//!   bearer token is never handed to a host the admin did not configure — and
//!   the sign-in proceeds on ID-token claims alone. The fetch is also
//!   SSRF-validated and pinned to the validated address (shared validator),
//!   follows no redirects, times out after [`USERINFO_TIMEOUT`] and reads at
//!   most [`USERINFO_MAX_BYTES`]. Only a JSON response is accepted; a signed
//!   or encrypted (`application/jwt`) userinfo response is not used.
//! * **Who.** Userinfo `sub` MUST equal the ID token `sub` (OIDC Core
//!   5.3.2), else the sign-in is refused ([`OidcError::UserinfoSubjectMismatch`]).
//! * **What.** Userinfo only fills claims the ID token did not assert; it
//!   never overrides one. `email_verified` is taken from userinfo only when
//!   it describes the same address the sign-in will use, so a verification
//!   flag for one address can never be applied to another. Userinfo never
//!   supplies `preferred_username` while the sign-in has no `email` claim,
//!   and only a real `email` claim can be verified (never a username
//!   stand-in).
//! * **Groups.** Group membership decides privileges, so the ID token is
//!   preferred. A group claim is taken from userinfo only when the ID token
//!   did not carry that claim at all (an explicitly empty array counts as
//!   carried) and userinfo carries it as an array of strings. Only an
//!   explicitly configured `group_claim` is ever read from userinfo; with it
//!   unset, membership comes from the ID token alone. Okta can emit its
//!   groups claim in either place
//!   ("ID Token: Always" vs "Userinfo / id_token request"); both work.
//!   Userinfo is fetched with the access token issued in the same code
//!   exchange, from the same authorization server, for the same `sub`, so
//!   its claims are as authoritative as the ID token's (OIDC Core 5.3.2).
//! * **Failure.** Anything but a `sub` mismatch is
//!   [`OidcError::UserinfoUnavailable`]: logged by the caller, never fatal.
//!   The sign-in then behaves exactly as it did before userinfo was used.

use std::time::Duration;

use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;

use super::oidc::{is_google_issuer, is_microsoft_issuer, IdTokenClaims, OidcError};

/// Upper bound on one userinfo request, connect to last byte.
pub const USERINFO_TIMEOUT: Duration = Duration::from_secs(10);
/// Upper bound on a userinfo body. Real responses are well under 8 KiB.
pub const USERINFO_MAX_BYTES: usize = 64 * 1024;
/// At most this many values are accepted for a userinfo group claim.
const USERINFO_MAX_GROUPS: usize = 2048;

/// Claims read from a userinfo response. Everything except `sub` is optional.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct UserInfoClaims {
    pub sub: String,
    #[serde(default)]
    pub email: Option<String>,
    /// Some providers send `"true"` / `"false"` strings; anything that is
    /// not a boolean or one of those strings is treated as absent.
    #[serde(default, deserialize_with = "lenient_bool")]
    pub email_verified: Option<bool>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub given_name: Option<String>,
    #[serde(default)]
    pub family_name: Option<String>,
    #[serde(default)]
    pub preferred_username: Option<String>,
    /// Raw `groups` / `roles` values; validated in [`merge_userinfo`].
    #[serde(default)]
    pub groups: Option<Value>,
    #[serde(default)]
    pub roles: Option<Value>,
}

fn lenient_bool<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<bool>, D::Error> {
    Ok(match Option::<Value>::deserialize(d)? {
        Some(Value::Bool(b)) => Some(b),
        Some(Value::String(s)) if s.eq_ignore_ascii_case("true") => Some(true),
        Some(Value::String(s)) if s.eq_ignore_ascii_case("false") => Some(false),
        _ => None,
    })
}

/// Whether a validated ID token should be completed from userinfo.
pub fn needs_userinfo(claims: &IdTokenClaims) -> bool {
    !is_google_issuer(&claims.iss)
        && !is_microsoft_issuer(&claims.iss)
        && (claims.email.is_none() || claims.email_verified.is_none())
}

/// Validate a discovery-advertised userinfo endpoint against the configured
/// issuer: `https`, same host and port, no credentials, no fragment.
pub fn userinfo_url(issuer: &str, endpoint: &str) -> Result<url::Url, OidcError> {
    let unavailable = |why: &str| OidcError::UserinfoUnavailable(why.to_string());
    let issuer = url::Url::parse(issuer).map_err(|_| unavailable("issuer is not a URL"))?;
    let url = url::Url::parse(endpoint).map_err(|_| unavailable("endpoint is not a URL"))?;
    if url.scheme() != "https" {
        return Err(unavailable("endpoint is not https"));
    }
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err(unavailable("endpoint carries credentials or a fragment"));
    }
    if url.host_str().is_none()
        || url.host_str() != issuer.host_str()
        || url.port_or_known_default() != issuer.port_or_known_default()
    {
        return Err(unavailable("endpoint is not on the issuer host"));
    }
    Ok(url)
}

/// Fetch userinfo for `issuer` from `endpoint`: URL rules, SSRF validation
/// and address pinning, no redirects, bounded time and size.
pub async fn fetch_userinfo_pinned(
    issuer: &str,
    endpoint: &str,
    access_token: &str,
) -> Result<UserInfoClaims, OidcError> {
    if access_token.is_empty() {
        return Err(OidcError::UserinfoUnavailable("no access token".into()));
    }
    let url = userinfo_url(issuer, endpoint)?;
    let (client, url) = crate::inputlookup::SsrfValidator::default_secure()
        .build_pinned_client(
            url.as_str(),
            Client::builder()
                .timeout(USERINFO_TIMEOUT)
                .redirect(reqwest::redirect::Policy::none()),
            crate::inputlookup::ProxyPolicy::Environment,
        )
        .await
        .map_err(|e| OidcError::UserinfoUnavailable(format!("blocked by security policy: {e}")))?;
    fetch_userinfo(&client, url, access_token).await
}

/// The bounded GET itself. `client` must already enforce the timeout,
/// redirect and SSRF policy ([`fetch_userinfo_pinned`] builds it).
pub async fn fetch_userinfo(
    client: &Client,
    url: url::Url,
    access_token: &str,
) -> Result<UserInfoClaims, OidcError> {
    let unavailable = |why: String| OidcError::UserinfoUnavailable(why);
    let mut response = client
        .get(url)
        .header(reqwest::header::ACCEPT, "application/json")
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| unavailable(format!("request failed: {}", e.without_url())))?;
    if !response.status().is_success() {
        return Err(unavailable(format!("HTTP {}", response.status().as_u16())));
    }
    let is_json = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/json"));
    if !is_json {
        return Err(unavailable("response is not application/json".into()));
    }
    if response
        .content_length()
        .is_some_and(|n| n > USERINFO_MAX_BYTES as u64)
    {
        return Err(unavailable("response too large".into()));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| unavailable(format!("read failed: {}", e.without_url())))?
    {
        if bytes.len() + chunk.len() > USERINFO_MAX_BYTES {
            return Err(unavailable("response too large".into()));
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| unavailable("response is not valid userinfo".into()))
}

/// A userinfo group claim as a bounded list of strings, else `None`.
fn string_list(value: &Value) -> Option<Vec<String>> {
    let items = value.as_array()?;
    if items.len() > USERINFO_MAX_GROUPS {
        return None;
    }
    items.iter().map(|v| v.as_str().map(str::to_string)).collect()
}

/// Merge `info` into validated ID-token `claims` (rules in the module doc).
pub fn merge_userinfo(
    claims: &mut IdTokenClaims,
    info: UserInfoClaims,
    group_claim: Option<&str>,
) -> Result<(), OidcError> {
    if info.sub != claims.sub {
        tracing::warn!(
            issuer = %claims.iss,
            "OIDC userinfo subject does not match the ID token; refusing sign-in"
        );
        return Err(OidcError::UserinfoSubjectMismatch);
    }

    // Names of the claims filled from userinfo, recorded once the borrows end.
    let mut added: Vec<&'static str> = Vec::new();

    if claims.email.is_none() {
        if let Some(email) = info.email.clone() {
            claims.email = Some(email);
            added.push("email");
            // An ID-token `email_verified` asserted without an address is not
            // bound to this one: it counts only if userinfo also verifies it
            // (can only narrow, never widen).
            if let Some(flag) = claims.email_verified {
                claims.email_verified = Some(flag && info.email_verified == Some(true));
            }
        }
    }
    // A verification flag applies only to the address it was issued for.
    if claims.email_verified.is_none() {
        if let (Some(flag), Some(info_email), Some(email)) =
            (info.email_verified, info.email.as_deref(), claims.email.as_deref())
        {
            if info_email.eq_ignore_ascii_case(email) {
                claims.email_verified = Some(flag);
                added.push("email_verified");
            }
        }
    }
    // `preferred_username` stands in for a missing email when the user is
    // matched by address, so userinfo never supplies it unless the sign-in
    // has a real `email` claim (NAN-5266 H1).
    let preferred_username = if claims.email.is_some() {
        info.preferred_username
    } else {
        None
    };
    for (name, slot, value) in [
        ("name", &mut claims.name, info.name),
        ("given_name", &mut claims.given_name, info.given_name),
        ("family_name", &mut claims.family_name, info.family_name),
        (
            "preferred_username",
            &mut claims.preferred_username,
            preferred_username,
        ),
    ] {
        if slot.is_none() {
            if let Some(value) = value {
                *slot = Some(value);
                added.push(name);
            }
        }
    }

    // Groups: only the explicitly configured claim, and only when the ID
    // token did not carry it at all. With no `group_claim` configured,
    // userinfo never supplies membership (NAN-5266 L3).
    let candidates: &[&str] = match group_claim {
        Some("groups") => &["groups"],
        Some("roles") => &["roles"],
        // Unset, or an unsupported name (refused later by the ID-token rule).
        _ => &[],
    };
    for &name in candidates {
        if claims.asserts(name) {
            continue;
        }
        let raw = if name == "groups" { &info.groups } else { &info.roles };
        let Some(raw) = raw else { continue };
        match string_list(raw) {
            Some(values) => {
                if name == "groups" {
                    claims.groups = values;
                } else {
                    claims.roles = values;
                }
                added.push(name);
            }
            None => tracing::warn!(
                issuer = %claims.iss,
                claim = name,
                "OIDC userinfo group claim is not a bounded list of strings; ignored"
            ),
        }
    }

    for name in added {
        claims.asserted_claims.insert(name.to_string());
    }
    Ok(())
}
