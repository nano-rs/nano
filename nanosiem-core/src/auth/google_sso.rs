// SPDX-License-Identifier: AGPL-3.0-or-later
//! Google Workspace group membership for SSO admission (NAN-3904 / NAN-3935).
//!
//! Google ID tokens carry no groups claim, so membership is read with a
//! read-only delegated Directory API call: a service account impersonates the
//! configured Workspace administrator and asks, for each MAPPED group only,
//! whether the signing-in user is a member. Any failure is "membership
//! unknown", which never admits a first-time user.
use super::{OidcError, SsoAccessPolicy};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
#[derive(Deserialize)]
struct ServiceAccount {
    client_email: String,
    private_key: String,
    token_uri: String,
}
pub fn validate_google_service_account(value: &str) -> Result<(), &'static str> {
    if value.len() > 32768 {
        return Err("Invalid Google service account");
    }
    let k: ServiceAccount =
        serde_json::from_str(value).map_err(|_| "Invalid Google service account")?;
    if !k.client_email.ends_with(".iam.gserviceaccount.com")
        || k.token_uri != TOKEN_URL
        || EncodingKey::from_rsa_pem(k.private_key.as_bytes()).is_err()
    {
        return Err("Invalid Google service account");
    }
    Ok(())
}
fn denied() -> OidcError {
    OidcError::GroupMembershipUnknown
}
pub async fn google_workspace_groups(
    policy: &SsoAccessPolicy,
    credential: &str,
    email: &str,
    mapped_groups: &[String],
) -> Result<Vec<String>, OidcError> {
    validate_google_service_account(credential).map_err(|_| denied())?;
    policy.validate().map_err(|_| denied())?;
    if mapped_groups.len() > 64 {
        return Err(denied());
    }
    let key: ServiceAccount = serde_json::from_str(credential).map_err(|_| denied())?;
    let delegate = policy
        .google_delegated_admin
        .as_deref()
        .ok_or_else(denied)?;
    #[derive(Serialize)]
    struct Assertion<'a> {
        iss: &'a str,
        sub: &'a str,
        scope: &'a str,
        aud: &'a str,
        iat: i64,
        exp: i64,
    }
    let now = chrono::Utc::now().timestamp();
    let assertion = encode(
        &Header::new(Algorithm::RS256),
        &Assertion {
            iss: &key.client_email,
            sub: delegate,
            scope: "https://www.googleapis.com/auth/admin.directory.group.member.readonly",
            aud: TOKEN_URL,
            iat: now,
            exp: now + 300,
        },
        &EncodingKey::from_rsa_pem(key.private_key.as_bytes()).map_err(|_| denied())?,
    )
    .map_err(|_| denied())?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| denied())?;
    let response = client
        .post(TOKEN_URL)
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", assertion.as_str()),
        ])
        .send()
        .await
        .map_err(|_| denied())?;
    #[derive(Deserialize)]
    struct Token {
        access_token: String,
    }
    let token: Token = bounded_json(response).await?;
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        lookup_memberships(
            &client,
            "https://admin.googleapis.com/admin/directory/v1/groups/",
            &token.access_token,
            mapped_groups,
            email,
        ),
    )
    .await
    .map_err(|_| denied())?
}

// Test injection is private; the production endpoint is fixed above.
async fn lookup_memberships(
    client: &reqwest::Client,
    endpoint: &str,
    token: &str,
    mapped_groups: &[String],
    email: &str,
) -> Result<Vec<String>, OidcError> {
    let mut groups = vec![];
    for idp_group in mapped_groups {
        let mut url = url::Url::parse(endpoint).map_err(|_| denied())?;
        url.path_segments_mut()
            .map_err(|_| denied())?
            .pop_if_empty()
            .push(idp_group)
            .push("hasMember")
            .push(email);
        let response = client
            .get(url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|_| denied())?;
        #[derive(Deserialize)]
        struct Membership {
            #[serde(rename = "isMember")]
            is_member: bool,
        }
        let member: Membership = bounded_json(response).await?;
        if member.is_member {
            groups.push(idp_group.clone());
        }
    }
    Ok(groups)
}
async fn bounded_json<T: serde::de::DeserializeOwned>(
    mut response: reqwest::Response,
) -> Result<T, OidcError> {
    if !response.status().is_success() || response.content_length().is_some_and(|n| n > 65536) {
        return Err(denied());
    }
    let mut bytes = vec![];
    while let Some(chunk) = response.chunk().await.map_err(|_| denied())? {
        if bytes.len() + chunk.len() > 65536 {
            return Err(denied());
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| denied())
}

#[cfg(test)]
#[path = "google_sso_tests.rs"]
mod tests;
