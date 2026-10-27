// SPDX-License-Identifier: AGPL-3.0-or-later

//! OIDC Service for OpenID Connect authentication
//!
//! Requirements: 3.1, 3.2, 3.3, 3.4, 3.7, 3.8
//!
//! This module provides:
//! - get_auth_url() with PKCE
//! - handle_callback() exchanging code for tokens
//! - validate_id_token() using JWKS
//! - provision_user() for JIT provisioning
//! - sync_groups() from claims

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use thiserror::Error;
use uuid::Uuid;

use crate::auth::repository::{
    GroupRepository, OidcRepository, OidcRepositoryError, UserRepository, UserRepositoryError,
};
use crate::auth::types::{OidcProvider, User};

#[derive(Error, Debug)]
pub enum OidcError {
    #[error("Group membership could not be verified")]
    GroupMembershipUnknown,
    #[error("your account is not in a group allowed to access this tenant")]
    GroupNotAllowed,
    #[error("OIDC provider not found: {0}")]
    ProviderNotFound(String),
    #[error("OIDC provider is disabled: {0}")]
    ProviderDisabled(String),
    #[error("Failed to fetch OIDC discovery document: {0}")]
    DiscoveryError(String),
    #[error("Failed to fetch JWKS: {0}")]
    JwksError(String),
    #[error("Token exchange failed: {0}")]
    TokenExchangeError(String),
    #[error("Invalid ID token: {0}")]
    InvalidIdToken(String),
    #[error("Invalid state parameter")]
    InvalidState,
    #[error("Invalid nonce")]
    InvalidNonce,
    #[error("OIDC authorization transaction not found, already consumed, or expired")]
    InvalidAuthTransaction,
    #[error("Redirect URI mismatch between /authorize and /callback")]
    RedirectUriMismatch,
    #[error("Missing required claim: {0}")]
    MissingClaim(String),
    #[error("User provisioning failed: {0}")]
    ProvisioningError(String),
    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),
    #[error("Invalid OIDC configuration: {0}")]
    InvalidConfig(String),
    #[error("Repository error: {0}")]
    RepositoryError(String),
    #[error("JSON parsing error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("JWT error: {0}")]
    JwtError(String),
}

/// A refused OIDC callback (NAN-4547). `identity` is set only once the ID
/// token has validated, and then holds only what the IdP asserted in it —
/// never raw claims from an unverified token, never tokens or codes.
#[derive(Debug)]
pub struct OidcCallbackError {
    pub error: OidcError,
    pub identity: Option<OidcAssertedIdentity>,
}

/// The IdP-asserted identity of a validated ID token: `sub`, plus `email`
/// (else `preferred_username`, the Entra UPN) when present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcAssertedIdentity {
    pub subject: String,
    pub email: Option<String>,
}

impl OidcAssertedIdentity {
    /// Only for claims returned by [`OidcService::validate_id_token`].
    pub fn from_validated_claims(claims: &IdTokenClaims) -> Self {
        Self {
            subject: claims.sub.clone(),
            email: claims
                .email
                .clone()
                .or_else(|| claims.preferred_username.clone()),
        }
    }
}

impl From<OidcRepositoryError> for OidcError {
    fn from(err: OidcRepositoryError) -> Self {
        OidcError::RepositoryError(err.to_string())
    }
}

impl From<UserRepositoryError> for OidcError {
    fn from(err: UserRepositoryError) -> Self {
        OidcError::ProvisioningError(err.to_string())
    }
}

/// OIDC Discovery Document (OpenID Configuration)
#[derive(Debug, Clone, Deserialize)]
pub struct OidcDiscovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: Option<String>,
    pub jwks_uri: String,
    pub scopes_supported: Option<Vec<String>>,
    pub response_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Option<Vec<String>>,
}

/// JWKS (JSON Web Key Set)
#[derive(Debug, Clone, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

/// JSON Web Key
#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub kid: Option<String>,
    pub alg: Option<String>,
    #[serde(rename = "use")]
    pub key_use: Option<String>,
    pub n: Option<String>,   // RSA modulus
    pub e: Option<String>,   // RSA exponent
    pub x: Option<String>,   // EC x coordinate
    pub y: Option<String>,   // EC y coordinate
    pub crv: Option<String>, // EC curve
}

/// Token response from OIDC provider
#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: Option<i64>,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub scope: Option<String>,
}

/// ID Token claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdTokenClaims {
    /// Issuer
    pub iss: String,
    /// Subject (user ID at the provider)
    pub sub: String,
    /// Audience (client ID)
    pub aud: serde_json::Value, // Can be string or array
    /// Authorized party. OIDC requires this when multiple audiences are
    /// present; shared mode validates it against the bound client ID.
    pub azp: Option<String>,
    /// Expiration time
    pub exp: i64,
    /// Issued at
    pub iat: i64,
    /// Nonce (for replay protection)
    pub nonce: Option<String>,
    /// Email
    pub email: Option<String>,
    /// Email verified
    pub email_verified: Option<bool>,
    /// Entra verified email-domain ownership signal; only trusted for an exact Entra issuer.
    pub xms_edov: Option<bool>,
    /// Entra directory tenant, bound to the validated issuer.
    pub tid: Option<String>,
    pub hasgroups: Option<bool>,
    #[serde(default, rename = "_claim_names")]
    pub claim_names: HashMap<String, String>,
    /// Name
    pub name: Option<String>,
    /// Given name
    pub given_name: Option<String>,
    /// Family name
    pub family_name: Option<String>,
    /// Picture URL
    pub picture: Option<String>,
    /// Groups (custom claim, varies by provider)
    #[serde(default)]
    pub groups: Vec<String>,
    /// Roles (alternative group claim)
    #[serde(default)]
    pub roles: Vec<String>,
    /// Preferred username (UPN in Azure AD, fallback for email)
    pub preferred_username: Option<String>,
}

impl IdTokenClaims {
    pub fn has_group_overage(&self) -> bool {
        self.hasgroups == Some(true) || self.claim_names.contains_key("groups")
    }

    pub fn entra_tenant(&self) -> Option<&str> {
        let tenant = self
            .iss
            .strip_prefix("https://login.microsoftonline.com/")?
            .strip_suffix("/v2.0")?;
        (Uuid::parse_str(tenant).is_ok() && self.tid.as_deref() == Some(tenant)).then_some(tenant)
    }

    /// This method is used only after signature, exact issuer, audience and
    /// nonce validation. An arbitrary issuer cannot opt into Entra semantics.
    pub fn verified_email(&self) -> bool {
        if self.email_verified == Some(true) {
            return true;
        }
        self.entra_tenant().is_some()
            && self
                .email
                .as_ref()
                .is_some_and(|email| !email.trim().is_empty())
            && self.xms_edov == Some(true)
    }
}

/// Shared membership boundary for hosted and dedicated sign-in. Call only after
/// token validation and Entra overage resolution; Google membership is supplied
/// separately by the delegated Directory lookup, never by an ID-token claim.
pub fn groups_from_validated_claims(
    claims: &IdTokenClaims,
    group_claim: Option<&str>,
) -> Result<Vec<String>, OidcError> {
    if claims.iss == "https://accounts.google.com" {
        return Ok(vec![]);
    }
    if claims.has_group_overage() {
        return Err(OidcError::GroupMembershipUnknown);
    }
    if claims.entra_tenant().is_some() {
        return Ok(claims.groups.clone());
    }
    match group_claim {
        Some("groups") => Ok(claims.groups.clone()),
        Some("roles") => Ok(claims.roles.clone()),
        Some(_) => Err(OidcError::InvalidConfig("Unsupported groups claim".into())),
        None if !claims.groups.is_empty() => Ok(claims.groups.clone()),
        None => Ok(claims.roles.clone()),
    }
}

/// Resolve overage only through a fixed Microsoft Graph endpoint. Never use
/// `_claim_sources`, which would disclose a bearer credential to an arbitrary URL.
pub async fn resolve_entra_groups(
    claims: &mut IdTokenClaims,
    access_token: &str,
) -> Result<(), OidcError> {
    if !claims.has_group_overage() {
        return Ok(());
    }
    if claims.entra_tenant().is_none() || access_token.is_empty() {
        return Err(OidcError::GroupMembershipUnknown);
    }
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| OidcError::GroupMembershipUnknown)?;
    claims.groups = fetch_entra_groups(
        &client,
        "https://graph.microsoft.com/v1.0/me/transitiveMemberOf/microsoft.graph.group?$select=id&$count=true",
        access_token,
    )
    .await?;
    claims.hasgroups = None;
    claims.claim_names.remove("groups");
    Ok(())
}

async fn fetch_entra_groups(
    client: &Client,
    endpoint: &str,
    token: &str,
) -> Result<Vec<String>, OidcError> {
    let denied = || OidcError::GroupMembershipUnknown;
    let origin = url::Url::parse(endpoint).map_err(|_| denied())?;
    let mut next = Some(origin.clone());
    let mut groups = Vec::new();
    for _ in 0..32 {
        let Some(url) = next.take() else {
            groups.sort();
            groups.dedup();
            return Ok(groups);
        };
        if url.origin() != origin.origin()
            || url.path() != origin.path()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(denied());
        }
        let mut response = client
            .get(url)
            .header("ConsistencyLevel", "eventual")
            .bearer_auth(token)
            .send()
            .await
            .map_err(|_| denied())?;
        if !response.status().is_success()
            || response.content_length().is_some_and(|n| n > 1024 * 1024)
        {
            return Err(denied());
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| denied())? {
            if bytes.len() + chunk.len() > 1024 * 1024 {
                return Err(denied());
            }
            bytes.extend_from_slice(&chunk);
        }
        #[derive(Deserialize)]
        struct Group {
            id: String,
        }
        #[derive(Deserialize)]
        struct Page {
            value: Vec<Group>,
            #[serde(rename = "@odata.nextLink")]
            next_link: Option<String>,
        }
        let page: Page = serde_json::from_slice(&bytes).map_err(|_| denied())?;
        for group in page.value {
            if Uuid::parse_str(&group.id).is_err() || groups.len() >= 2048 {
                return Err(denied());
            }
            groups.push(group.id);
        }
        next = page
            .next_link
            .map(|value| url::Url::parse(&value).map_err(|_| denied()))
            .transpose()?;
    }
    Err(denied())
}

/// User info from OIDC authentication
#[derive(Debug, Clone)]
pub struct OidcUser {
    pub subject: String,
    pub email: String,
    pub email_verified: bool,
    pub name: String,
    pub groups: Vec<String>,
    pub provider_id: Uuid,
}

/// PKCE (Proof Key for Code Exchange) parameters
#[derive(Debug, Clone)]
pub struct PkceParams {
    pub code_verifier: String,
    pub code_challenge: String,
}

impl PkceParams {
    /// Generate new PKCE parameters
    pub fn generate() -> Self {
        use rand::Rng;
        let mut rng = rand::rng();
        // Generate a random code verifier (43-128 characters)
        let code_verifier: String = (0..64)
            .map(|_| {
                let idx = rng.random_range(0..66usize);
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
                    .chars()
                    .nth(idx)
                    .unwrap()
            })
            .collect();

        // Create code challenge using SHA256
        let mut hasher = Sha256::new();
        hasher.update(code_verifier.as_bytes());
        let hash = hasher.finalize();
        let code_challenge = URL_SAFE_NO_PAD.encode(hash);

        Self {
            code_verifier,
            code_challenge,
        }
    }
}

/// Authorization URL response.
///
/// Only `url` and `state` are exposed to the client. `nonce` and `code_verifier`
/// are persisted server-side at /authorize and looked up at /callback —
/// they no longer round-trip through the browser.
#[derive(Debug, Clone, Serialize)]
pub struct AuthorizationUrl {
    pub url: String,
    pub state: String,
}

/// Server-side TTL for OIDC authorization transactions, in seconds.
///
/// The window between /authorize and /callback should be short — the user
/// just needs time to authenticate at the IdP. 10 minutes is generous and
/// matches typical IdP code lifetimes.
const AUTH_TRANSACTION_TTL_SECONDS: i64 = 600;

/// OIDC Service
#[derive(Clone)]
pub struct OidcService {
    oidc_repo: OidcRepository,
    user_repo: UserRepository,
    /// Cache for discovery documents
    discovery_cache: std::sync::Arc<tokio::sync::RwLock<HashMap<String, OidcDiscovery>>>,
    /// Cache for JWKS
    jwks_cache: std::sync::Arc<tokio::sync::RwLock<HashMap<String, Jwks>>>,
}

impl OidcService {
    pub fn new(
        oidc_repo: OidcRepository,
        user_repo: UserRepository,
        _group_repo: GroupRepository,
    ) -> Self {
        Self {
            oidc_repo,
            user_repo,
            // SSRF (NAN-1369 / NAN-2018): discovery & JWKS fetches build a
            // per-request client PINNED to the SSRF-validated IP (see
            // fetch_discovery / fetch_jwks), so no shared http_client is kept.
            discovery_cache: std::sync::Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            jwks_cache: std::sync::Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }

    /// Fetch OIDC discovery document
    async fn fetch_discovery(&self, issuer: &str) -> Result<OidcDiscovery, OidcError> {
        // Check cache first
        {
            let cache = self.discovery_cache.read().await;
            if let Some(discovery) = cache.get(issuer) {
                return Ok(discovery.clone());
            }
        }

        // Fetch from well-known endpoint
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        );

        // H4 + NAN-2018: SSRF-validate AND pin — build a client that dials only
        // the validated IP for this fetch, closing the DNS-rebinding TOCTOU.
        // Redirects keep the restricted policy (blocks IP-literal / non-https).
        let (client, _) = crate::inputlookup::SsrfValidator::default_secure()
            .build_pinned_client(
                &discovery_url,
                Client::builder().redirect(crate::inputlookup::restricted_redirect_policy()),
            )
            .await
            .map_err(|e| {
                OidcError::DiscoveryError(format!("Issuer URL blocked by security policy: {}", e))
            })?;

        let response = client.get(&discovery_url).send().await?;

        if !response.status().is_success() {
            return Err(OidcError::DiscoveryError(format!(
                "HTTP {} from {}",
                response.status(),
                discovery_url
            )));
        }

        let discovery: OidcDiscovery = response.json().await?;

        // Cache the discovery document
        {
            let mut cache = self.discovery_cache.write().await;
            cache.insert(issuer.to_string(), discovery.clone());
        }

        Ok(discovery)
    }

    /// Fetch JWKS from provider
    /// Requirements: 3.7
    async fn fetch_jwks(&self, jwks_uri: &str) -> Result<Jwks, OidcError> {
        // Check cache first
        {
            let cache = self.jwks_cache.read().await;
            if let Some(jwks) = cache.get(jwks_uri) {
                return Ok(jwks.clone());
            }
        }

        // H4 + NAN-2018: SSRF-validate AND pin the JWKS fetch to the validated IP.
        let (client, _) = crate::inputlookup::SsrfValidator::default_secure()
            .build_pinned_client(
                jwks_uri,
                Client::builder().redirect(crate::inputlookup::restricted_redirect_policy()),
            )
            .await
            .map_err(|e| {
                OidcError::JwksError(format!("JWKS URL blocked by security policy: {}", e))
            })?;

        let response = client.get(jwks_uri).send().await?;

        if !response.status().is_success() {
            return Err(OidcError::JwksError(format!(
                "HTTP {} from {}",
                response.status(),
                jwks_uri
            )));
        }

        let jwks: Jwks = response.json().await?;

        // Cache the JWKS
        {
            let mut cache = self.jwks_cache.write().await;
            cache.insert(jwks_uri.to_string(), jwks.clone());
        }

        Ok(jwks)
    }

    /// Get authorization URL for OIDC login
    /// Requirements: 3.1, 3.2
    pub async fn get_auth_url(
        &self,
        provider_slug: &str,
        redirect_uri: &str,
    ) -> Result<AuthorizationUrl, OidcError> {
        // Get provider
        let provider = self
            .oidc_repo
            .get_provider_by_slug(provider_slug)
            .await
            .map_err(|_| OidcError::ProviderNotFound(provider_slug.to_string()))?;

        if !provider.enabled {
            return Err(OidcError::ProviderDisabled(provider_slug.to_string()));
        }

        // M5: Validate redirect_uri against allowed origins
        // Only allow redirects to the NanoSIEM application itself (same origin)
        let parsed_redirect = url::Url::parse(redirect_uri)
            .map_err(|_| OidcError::InvalidConfig("Invalid redirect_uri".to_string()))?;
        let allowed_origin = std::env::var("NANOSIEM_BASE_URL")
            .or_else(|_| std::env::var("NANOSIEM_HOSTNAME").map(|h| format!("https://{}", h)))
            .unwrap_or_default();
        if !allowed_origin.is_empty() {
            if let Ok(allowed) = url::Url::parse(&allowed_origin) {
                if parsed_redirect.host_str() != allowed.host_str() {
                    return Err(OidcError::InvalidConfig(format!(
                        "redirect_uri host '{}' does not match allowed origin '{}'",
                        parsed_redirect.host_str().unwrap_or("unknown"),
                        allowed.host_str().unwrap_or("unknown"),
                    )));
                }
            }
        }
        // Additional safety: reject non-HTTPS redirect URIs in production
        if parsed_redirect.scheme() != "https" && parsed_redirect.scheme() != "http" {
            return Err(OidcError::InvalidConfig(
                "redirect_uri must use http or https".to_string(),
            ));
        }

        // Fetch discovery document
        let discovery = self.fetch_discovery(&provider.issuer).await?;

        // Generate PKCE parameters
        let pkce = PkceParams::generate();

        // Generate state and nonce
        let state = Uuid::now_v7().to_string();
        let nonce = Uuid::now_v7().to_string();

        // Persist the transaction server-side BEFORE handing the auth URL to
        // the browser. /callback will look this up by `state`, atomically mark
        // it consumed, and use the stored nonce/code_verifier.
        self.oidc_repo
            .create_auth_transaction(
                &state,
                provider.id,
                &nonce,
                &pkce.code_verifier,
                redirect_uri,
                AUTH_TRANSACTION_TTL_SECONDS,
            )
            .await?;

        // Build authorization URL
        let scopes = provider.scopes.join(" ");
        let auth_url = format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&nonce={}&code_challenge={}&code_challenge_method=S256",
            discovery.authorization_endpoint,
            urlencoding::encode(&provider.client_id),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(&scopes),
            urlencoding::encode(&state),
            urlencoding::encode(&nonce),
            urlencoding::encode(&pkce.code_challenge),
        );

        Ok(AuthorizationUrl {
            url: auth_url,
            state,
        })
    }

    /// Handle OIDC callback - exchange code for tokens
    /// Requirements: 3.2, 3.3
    ///
    /// `state` is the opaque value the IdP echoed back; we use it to look up the
    /// server-side transaction and pull the *server-issued* code_verifier and
    /// nonce. The client never supplies those directly.
    pub async fn handle_callback(
        &self,
        provider_slug: &str,
        code: &str,
        state: &str,
        redirect_uri: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<(User, OidcUser, bool), OidcCallbackError> {
        let (provider, claims, access_token) = self
            .validate_callback(provider_slug, code, state, redirect_uri)
            .await
            .map_err(|error| OidcCallbackError {
                error,
                identity: None,
            })?;
        // From here on the ID token is verified: a refusal carries the
        // IdP-asserted identity so the denial audit can name it (NAN-4547).
        let identity = OidcAssertedIdentity::from_validated_claims(&claims);
        self.admit_validated(provider, claims, &access_token, ip_address, user_agent)
            .await
            .map_err(|error| OidcCallbackError {
                error,
                identity: Some(identity),
            })
    }

    /// The callback up to and including ID-token validation: provider,
    /// transaction, code exchange, signature/nonce checks. Nothing it
    /// returns on error is trusted identity.
    async fn validate_callback(
        &self,
        provider_slug: &str,
        code: &str,
        state: &str,
        redirect_uri: &str,
    ) -> Result<(OidcProvider, IdTokenClaims, String), OidcError> {
        // Get provider
        let provider = self
            .oidc_repo
            .get_provider_by_slug(provider_slug)
            .await
            .map_err(|_| OidcError::ProviderNotFound(provider_slug.to_string()))?;

        if !provider.enabled {
            return Err(OidcError::ProviderDisabled(provider_slug.to_string()));
        }

        // Look up and atomically consume the transaction created at /authorize.
        // This rejects unknown states, replays, expired transactions, and
        // transactions belonging to a different provider (the provider_id is
        // part of the WHERE clause, so a callback submitted under the wrong
        // provider slug does not burn a legitimate transaction). The
        // mark-consumed happens in the same UPDATE that returns the row, so
        // two concurrent callbacks for the same `state` cannot both succeed.
        let transaction = self
            .oidc_repo
            .consume_auth_transaction(state, provider.id)
            .await
            .map_err(|e| match e {
                OidcRepositoryError::AuthTransactionInvalid => OidcError::InvalidAuthTransaction,
                other => OidcError::RepositoryError(other.to_string()),
            })?;

        // Defense in depth: the redirect_uri sent at /callback must match the
        // one we stored at /authorize. The IdP also enforces this against its
        // registered list, but binding it to the server-side transaction
        // closes mix-up attacks where a callback for one transaction is
        // submitted with a different redirect_uri.
        if transaction.redirect_uri != redirect_uri {
            return Err(OidcError::RedirectUriMismatch);
        }

        // Get client secret
        let client_secret = self.oidc_repo.get_client_secret(provider.id).await?;

        // Fetch discovery document
        let discovery = self.fetch_discovery(&provider.issuer).await?;

        // Exchange code for tokens — using the *server-stored* code_verifier
        let token_response = self
            .exchange_code(
                &discovery.token_endpoint,
                code,
                redirect_uri,
                &provider.client_id,
                &client_secret,
                &transaction.code_verifier,
            )
            .await?;

        // Get ID token
        let id_token = token_response
            .id_token
            .ok_or_else(|| OidcError::InvalidIdToken("No ID token in response".to_string()))?;

        // Validate ID token — using the *server-stored* nonce
        let claims = self
            .validate_id_token(
                &id_token,
                &provider,
                &discovery.jwks_uri,
                &transaction.nonce,
            )
            .await?;
        Ok((provider, claims, token_response.access_token))
    }

    /// The callback after ID-token validation: group resolution, user
    /// extraction and provisioning (where group-gated JIT may refuse).
    async fn admit_validated(
        &self,
        provider: OidcProvider,
        mut claims: IdTokenClaims,
        access_token: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<(User, OidcUser, bool), OidcError> {
        resolve_entra_groups(&mut claims, access_token).await?;

        // Extract user info
        let mut oidc_user = self.extract_user_info(&claims, &provider)?;
        if provider.issuer == "https://accounts.google.com" {
            oidc_user.groups.clear();
            if provider.access_policy.google_delegated_admin.is_some() {
                if let Some(key) = self.oidc_repo.google_service_account(provider.id).await? {
                    oidc_user.groups = super::google_workspace_groups(
                        &provider.access_policy,
                        &key,
                        &oidc_user.email,
                    )
                    .await?;
                }
            }
        }

        // Provision or update user
        let (user, newly_created) = self
            .provision_user(&oidc_user, ip_address, user_agent)
            .await?;

        // Provisioning and source-aware group reconciliation commit together.

        Ok((user, oidc_user, newly_created))
    }

    /// Exchange authorization code for tokens
    async fn exchange_code(
        &self,
        token_endpoint: &str,
        code: &str,
        redirect_uri: &str,
        client_id: &str,
        client_secret: &str,
        code_verifier: &str,
    ) -> Result<TokenResponse, OidcError> {
        let params = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("code_verifier", code_verifier),
        ];

        // NAN-2018: validate AND pin the token endpoint (from the provider's
        // discovery doc) before posting the code + client_secret, so a DNS rebind
        // can't redirect the secret to an internal/metadata host.
        let (client, _) = crate::inputlookup::SsrfValidator::default_secure()
            .build_pinned_client(
                token_endpoint,
                Client::builder().redirect(crate::inputlookup::restricted_redirect_policy()),
            )
            .await
            .map_err(|e| {
                OidcError::TokenExchangeError(format!(
                    "Token endpoint blocked by security policy: {}",
                    e
                ))
            })?;

        let response = client.post(token_endpoint).form(&params).send().await?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(OidcError::TokenExchangeError(format!(
                "Token exchange failed: {}",
                error_text
            )));
        }

        let token_response: TokenResponse = response.json().await?;
        Ok(token_response)
    }

    /// Validate ID token using JWKS
    /// Requirements: 3.7
    pub async fn validate_id_token(
        &self,
        id_token: &str,
        provider: &OidcProvider,
        jwks_uri: &str,
        expected_nonce: &str,
    ) -> Result<IdTokenClaims, OidcError> {
        // Decode header to get key ID
        let header = decode_header(id_token)
            .map_err(|e| OidcError::InvalidIdToken(format!("Invalid JWT header: {}", e)))?;

        // Fetch JWKS
        let jwks = self.fetch_jwks(jwks_uri).await?;

        // Find the key
        let key = if let Some(kid) = &header.kid {
            jwks.keys.iter().find(|k| k.kid.as_ref() == Some(kid))
        } else {
            jwks.keys.first()
        };

        let key =
            key.ok_or_else(|| OidcError::JwksError("No matching key found in JWKS".to_string()))?;

        // Create decoding key based on key type
        let decoding_key = self.create_decoding_key(key)?;

        // Set up validation
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&provider.issuer]);

        // Handle audience validation (can be string or array)
        validation.set_audience(&[&provider.client_id]);

        // Decode and validate token
        let token_data = decode::<IdTokenClaims>(id_token, &decoding_key, &validation)
            .map_err(|e| OidcError::InvalidIdToken(format!("Token validation failed: {}", e)))?;

        let claims = token_data.claims;

        // Validate nonce - REQUIRED for replay attack prevention
        // The nonce must be present in the token and must match what we sent
        match &claims.nonce {
            Some(nonce) if nonce == expected_nonce => {
                // Nonce matches - valid
            }
            Some(_) => {
                // Nonce present but doesn't match
                return Err(OidcError::InvalidNonce);
            }
            None => {
                // Nonce missing from token - this is a security issue
                // IdP should always echo back the nonce we sent
                tracing::warn!(
                    provider_id = %provider.id,
                    "OIDC token missing nonce claim - potential replay attack or misconfigured IdP"
                );
                return Err(OidcError::InvalidIdToken(
                    "Missing required nonce claim in ID token".to_string(),
                ));
            }
        }

        Ok(claims)
    }

    /// Create decoding key from JWK
    fn create_decoding_key(&self, jwk: &Jwk) -> Result<DecodingKey, OidcError> {
        match jwk.kty.as_str() {
            "RSA" => {
                let n = jwk
                    .n
                    .as_ref()
                    .ok_or_else(|| OidcError::JwksError("Missing RSA modulus".to_string()))?;
                let e = jwk
                    .e
                    .as_ref()
                    .ok_or_else(|| OidcError::JwksError("Missing RSA exponent".to_string()))?;

                DecodingKey::from_rsa_components(n, e)
                    .map_err(|e| OidcError::JwksError(format!("Invalid RSA key: {}", e)))
            }
            _ => Err(OidcError::JwksError(format!(
                "Unsupported key type: {}",
                jwk.kty
            ))),
        }
    }

    /// Extract user info from ID token claims
    fn extract_user_info(
        &self,
        claims: &IdTokenClaims,
        provider: &OidcProvider,
    ) -> Result<OidcUser, OidcError> {
        // Try email first, fall back to preferred_username (UPN) for Azure AD cloud-only users
        let email = claims
            .email
            .clone()
            .or_else(|| claims.preferred_username.clone())
            .ok_or_else(|| OidcError::MissingClaim("email or preferred_username".to_string()))?;

        let name = claims
            .name
            .clone()
            .or_else(|| {
                // Try to construct name from given_name and family_name
                match (&claims.given_name, &claims.family_name) {
                    (Some(given), Some(family)) => Some(format!("{} {}", given, family)),
                    (Some(given), None) => Some(given.clone()),
                    (None, Some(family)) => Some(family.clone()),
                    (None, None) => None,
                }
            })
            .unwrap_or_else(|| email.split('@').next().unwrap_or(&email).to_string());

        let groups = groups_from_validated_claims(claims, provider.group_claim.as_deref())?;

        Ok(OidcUser {
            subject: claims.sub.clone(),
            email,
            email_verified: provider.access_policy.verifies_email(claims),
            name,
            groups,
            provider_id: provider.id,
        })
    }

    /// Provision or update user from OIDC claims
    /// Requirements: 3.3, 3.8
    /// Provisions (or links/updates) the local user for an OIDC identity.
    ///
    /// Returns the resolved `User` and a `bool` that is `true` only when a brand
    /// new user was just-in-time created (so the caller can audit
    /// `oidc_user_provisioned`); it is `false` for updates to an existing OIDC
    /// user or links onto a pre-existing local account.
    pub async fn provision_user(
        &self,
        oidc_user: &OidcUser,
        _ip_address: Option<&str>,
        _user_agent: Option<&str>,
    ) -> Result<(User, bool), OidcError> {
        let failed = || OidcError::ProvisioningError("SSO provisioning unavailable".into());
        let mut tx = self.user_repo.pool().begin().await.map_err(|_| failed())?;
        let provider = sqlx::query_as::<_, OidcProvider>(
            "SELECT * FROM oidc_providers WHERE id=$1 AND enabled FOR SHARE",
        )
        .bind(oidc_user.provider_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| failed())?
        .ok_or_else(failed)?;
        let user = sqlx::query_as::<_, User>(
            "SELECT * FROM users WHERE oidc_provider_id=$1 AND oidc_subject=$2 FOR UPDATE",
        )
        .bind(provider.id)
        .bind(&oidc_user.subject)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| failed())?;
        let linked = user.is_some();
        let existing = if user.is_some() {
            user
        } else {
            sqlx::query_as::<_, User>("SELECT * FROM users WHERE lower(email)=lower($1) FOR UPDATE")
                .bind(&oidc_user.email)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|_| failed())?
        };
        if existing
            .as_ref()
            .is_some_and(|u| u.status != "active" || (!linked && u.oidc_provider_id.is_some()))
        {
            return Err(OidcError::ProvisioningError(
                "SSO account is not active or cannot be linked".into(),
            ));
        }
        let invited = if let Some(u) = &existing {
            !sqlx::query_scalar::<_, bool>("SELECT sso_jit FROM users WHERE id=$1")
                .bind(u.id)
                .fetch_one(&mut *tx)
                .await
                .map_err(|_| failed())?
        } else {
            false
        };
        let lookup_known=provider.issuer!="https://accounts.google.com" || (
            provider.access_policy.google_delegated_admin.is_some() &&
            sqlx::query_scalar::<_,bool>("SELECT google_service_account_encrypted IS NOT NULL FROM oidc_providers WHERE id=$1")
                .bind(provider.id).fetch_one(&mut *tx).await.map_err(|_| failed())?);
        if !provider
            .access_policy
            .allows(&oidc_user.groups, invited, lookup_known)
        {
            if let Some(u) = existing {
                self.reconcile_groups(&mut tx, u.id, &[], &provider).await?;
            }
            tx.commit().await.map_err(|_| failed())?;
            return Err(OidcError::GroupNotAllowed);
        }
        if !linked && !oidc_user.email_verified {
            return Err(OidcError::ProvisioningError(
                "Email address must be verified by the identity provider".into(),
            ));
        }
        let newly_created = existing.is_none();
        let user = if let Some(existing) = existing {
            let user=sqlx::query_as::<_,User>("UPDATE users SET oidc_provider_id=$2,oidc_subject=$3,last_login_at=NOW(),last_oidc_groups=$4,updated_at=NOW() WHERE id=$1 RETURNING *")
                .bind(existing.id).bind(provider.id).bind(&oidc_user.subject).bind(&oidc_user.groups)
                .fetch_one(&mut *tx).await.map_err(|_| failed())?;
            user
        } else {
            sqlx::query_as::<_,User>("INSERT INTO users(email,name,status,oidc_provider_id,oidc_subject,last_login_at,last_oidc_groups,sso_jit) VALUES($1,$2,'active',$3,$4,NOW(),$5,TRUE) RETURNING *")
                .bind(&oidc_user.email).bind(&oidc_user.name).bind(provider.id).bind(&oidc_user.subject).bind(&oidc_user.groups)
                .fetch_one(&mut *tx).await.map_err(|_| failed())?
        };
        self.reconcile_groups(&mut tx, user.id, &oidc_user.groups, &provider)
            .await?;
        tx.commit().await.map_err(|_| failed())?;
        Ok((user, newly_created))
    }

    async fn reconcile_groups(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        user_id: Uuid,
        groups: &[String],
        provider: &OidcProvider,
    ) -> Result<(), OidcError> {
        let failed = || OidcError::ProvisioningError("SSO group reconciliation unavailable".into());
        let prefix = format!("sso_group:{}:", provider.id);
        sqlx::query("DELETE FROM oidc_group_grant_sources WHERE user_id=$1 AND source LIKE $2")
            .bind(user_id)
            .bind(format!("{prefix}%"))
            .execute(&mut **tx)
            .await
            .map_err(|_| failed())?;
        for mapping in provider.access_policy.matching(groups) {
            let source = format!("{prefix}{}", mapping.idp_group);
            sqlx::query("SELECT set_config('nano.sso_grant_source',$1,TRUE)")
                .bind(&source)
                .execute(&mut **tx)
                .await
                .map_err(|_| failed())?;
            for group in &mapping.group_ids {
                sqlx::query("INSERT INTO user_groups(user_id,group_id) VALUES($1,$2) ON CONFLICT DO NOTHING")
                    .bind(user_id).bind(group).execute(&mut **tx).await.map_err(|_| failed())?;
            }
        }
        sqlx::query("SELECT set_config('nano.sso_grant_source','',TRUE)")
            .execute(&mut **tx)
            .await
            .map_err(|_| failed())?;
        let removed=sqlx::query("DELETE FROM user_groups g WHERE user_id=$1 AND NOT EXISTS(SELECT 1 FROM oidc_group_grant_sources s WHERE s.user_id=g.user_id AND s.group_id=g.group_id)")
            .bind(user_id).execute(&mut **tx).await.map_err(|_| failed())?.rows_affected();
        if removed > 0 {
            sqlx::query("UPDATE users SET tokens_valid_from=clock_timestamp() WHERE id=$1")
                .bind(user_id)
                .execute(&mut **tx)
                .await
                .map_err(|_| failed())?;
            sqlx::query("DELETE FROM sessions WHERE user_id=$1")
                .bind(user_id)
                .execute(&mut **tx)
                .await
                .map_err(|_| failed())?;
        }
        Ok(())
    }

    pub async fn sync_groups(
        &self,
        user_id: Uuid,
        groups: &[String],
        provider_id: Uuid,
    ) -> Result<(), OidcError> {
        let mut tx = self
            .user_repo
            .pool()
            .begin()
            .await
            .map_err(|_| OidcError::GroupNotAllowed)?;
        let provider = sqlx::query_as::<_, OidcProvider>(
            "SELECT * FROM oidc_providers WHERE id=$1 AND enabled FOR SHARE",
        )
        .bind(provider_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| OidcError::GroupNotAllowed)?;
        sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(|_| OidcError::GroupNotAllowed)?;
        self.reconcile_groups(&mut tx, user_id, groups, &provider)
            .await?;
        tx.commit().await.map_err(|_| OidcError::GroupNotAllowed)
    }

    /// List enabled OIDC providers (for login page)
    pub async fn list_enabled_providers(&self) -> Result<Vec<OidcProviderInfo>, OidcError> {
        let providers = self.oidc_repo.list_enabled_providers().await?;

        Ok(providers
            .into_iter()
            .map(|p| OidcProviderInfo {
                slug: p.slug,
                name: p.name,
            })
            .collect())
    }
}

/// Minimal provider info for login page
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct OidcProviderInfo {
    pub slug: String,
    pub name: String,
}

#[cfg(test)]
mod verified_email_tests {
    use super::IdTokenClaims;
    use serde_json::{json, Value};

    fn claims(patch: Value) -> IdTokenClaims {
        let mut value = json!({
            "iss": "https://login.microsoftonline.com/11111111-1111-4111-8111-111111111111/v2.0",
            "tid": "11111111-1111-4111-8111-111111111111",
            "sub": "test-subject", "aud": "test-client", "exp": 2000000000,
            "iat": 1900000000, "email": "member@example.com"
        });
        value
            .as_object_mut()
            .unwrap()
            .extend(patch.as_object().unwrap().clone());
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn entra_requires_verified_email_domain_signal() {
        assert!(claims(json!({"xms_edov": true})).verified_email());
        assert!(!claims(json!({})).verified_email());
        assert!(!claims(json!({"xms_edov": false})).verified_email());
        assert!(!claims(json!({"xms_edov": true, "email": null,
            "preferred_username": "member@example.com"}))
        .verified_email());
    }

    #[test]
    fn entra_signal_is_bound_to_exact_issuer_and_tenant() {
        for issuer in ["https://issuer.example", "https://login.microsoftonline.com.evil.example/11111111-1111-4111-8111-111111111111/v2.0",
            "https://login.microsoftonline.com/common/v2.0", "https://login.microsoftonline.com/11111111-1111-4111-8111-111111111111/v2.0/"] {
            assert!(!claims(json!({"iss": issuer, "xms_edov": true})).verified_email());
        }
        assert!(!claims(json!({"tid": null, "xms_edov": true})).verified_email());
        assert!(
            !claims(json!({"tid": "22222222-2222-4222-8222-222222222222", "xms_edov": true}))
                .verified_email()
        );
    }

    #[test]
    fn other_providers_still_require_email_verified() {
        assert!(
            claims(json!({"iss": "https://accounts.google.com", "email_verified": true}))
                .verified_email()
        );
        assert!(
            !claims(json!({"iss": "https://accounts.google.com", "xms_edov": true}))
                .verified_email()
        );
    }
}

#[cfg(test)]
mod entra_group_tests {
    use super::*;
    use serde_json::json;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    #[tokio::test]
    async fn graph_membership_is_read_from_complete_response() {
        let server = MockServer::start().await;
        let group = "11111111-1111-4111-8111-111111111111";
        Mock::given(method("GET"))
            .and(path("/groups"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"value": [{"id": group}]})),
            )
            .mount(&server)
            .await;
        let result = fetch_entra_groups(
            &Client::new(),
            &format!("{}/groups", server.uri()),
            "disposable-test-token",
        )
        .await
        .unwrap();
        assert_eq!(result, vec![group]);
    }

    #[tokio::test]
    async fn graph_failure_or_unknown_membership_is_denied() {
        for (status, body) in [
            (403, json!({"error": "consent required"})),
            (200, json!({"value": [{"id": "invalid"}]})),
            (200, json!({})),
            (
                200,
                json!({"value": [], "@odata.nextLink": "https://evil.example/groups"}),
            ),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(status).set_body_json(body))
                .mount(&server)
                .await;
            assert!(fetch_entra_groups(
                &Client::new(),
                &format!("{}/groups", server.uri()),
                "disposable-test-token"
            )
            .await
            .is_err());
        }
    }

    #[tokio::test]
    async fn graph_pagination_must_complete_before_granting_any_group() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/groups"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({"value": [{"id": "11111111-1111-4111-8111-111111111111"}],
                "@odata.nextLink": format!("{}/failure", server.uri())}),
            ))
            .mount(&server)
            .await;
        assert!(fetch_entra_groups(
            &Client::new(),
            &format!("{}/groups", server.uri()),
            "disposable-test-token"
        )
        .await
        .is_err());
    }
}

#[cfg(test)]
mod membership_boundary_tests {
    use super::*;
    #[test]
    fn shared_claim_boundary_respects_membership_source() {
        for (issuer, extra, claim, expected) in [
            (
                "https://example.okta.com",
                serde_json::json!({}),
                Some("groups"),
                vec!["allowed"],
            ),
            (
                "https://login.microsoftonline.com/11111111-1111-4111-8111-111111111111/v2.0",
                serde_json::json!({"tid":"11111111-1111-4111-8111-111111111111"}),
                Some("roles"),
                vec!["allowed"],
            ),
            (
                "https://accounts.google.com",
                serde_json::json!({}),
                Some("groups"),
                vec![],
            ),
        ] {
            let mut value = serde_json::json!({"iss":issuer,"sub":"subject","aud":"client","iat":1,"exp":2,"groups":["allowed"],"roles":["untrusted-role"]});
            value
                .as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            let claims: IdTokenClaims = serde_json::from_value(value).unwrap();
            assert_eq!(
                groups_from_validated_claims(&claims, claim).unwrap(),
                expected
            );
            if issuer != "https://accounts.google.com" {
                let mut unresolved = claims.clone();
                unresolved.hasgroups = Some(true);
                assert!(matches!(
                    groups_from_validated_claims(&unresolved, claim),
                    Err(OidcError::GroupMembershipUnknown)
                ));
            }
        }
    }
}
