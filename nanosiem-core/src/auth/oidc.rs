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

use tracing::warn;

use crate::auth::repository::{
    GroupRepository, OidcRepository, OidcRepositoryError, UserRepository, UserRepositoryError,
};
use crate::auth::types::{OidcProvider, User};

#[derive(Error, Debug)]
pub enum OidcError {
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
    group_repo: GroupRepository,
    /// Cache for discovery documents
    discovery_cache: std::sync::Arc<tokio::sync::RwLock<HashMap<String, OidcDiscovery>>>,
    /// Cache for JWKS
    jwks_cache: std::sync::Arc<tokio::sync::RwLock<HashMap<String, Jwks>>>,
}

impl OidcService {
    pub fn new(
        oidc_repo: OidcRepository,
        user_repo: UserRepository,
        group_repo: GroupRepository,
    ) -> Self {
        Self {
            oidc_repo,
            user_repo,
            group_repo,
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
    ) -> Result<(User, OidcUser, bool), OidcError> {
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
            .validate_id_token(&id_token, &provider, &discovery.jwks_uri, &transaction.nonce)
            .await?;

        // Extract user info
        let oidc_user = self.extract_user_info(&claims, &provider)?;

        // Provision or update user
        let (user, newly_created) = self
            .provision_user(&oidc_user, ip_address, user_agent)
            .await?;

        // Sync groups
        self.sync_groups(user.id, &oidc_user.groups, provider.id)
            .await?;

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

        let response = client
            .post(token_endpoint)
            .form(&params)
            .send()
            .await?;

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

        // Extract groups based on provider's group claim configuration
        let groups = if let Some(ref group_claim) = provider.group_claim {
            match group_claim.as_str() {
                "groups" => claims.groups.clone(),
                "roles" => claims.roles.clone(),
                _ => claims.groups.clone(), // Default to groups
            }
        } else {
            // Try both groups and roles
            if !claims.groups.is_empty() {
                claims.groups.clone()
            } else {
                claims.roles.clone()
            }
        };

        Ok(OidcUser {
            subject: claims.sub.clone(),
            email,
            email_verified: claims.email_verified.unwrap_or(false),
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
        // Try to find existing user by OIDC subject
        let existing_user = sqlx::query_as::<_, User>(
            "SELECT * FROM users WHERE oidc_provider_id = $1 AND oidc_subject = $2",
        )
        .bind(oidc_user.provider_id)
        .bind(&oidc_user.subject)
        .fetch_optional(self.user_repo.pool())
        .await
        .map_err(|e| OidcError::ProvisioningError(e.to_string()))?;

        let (user, newly_created) = if let Some(existing) = existing_user {
            // Update existing user
            let updated_user = sqlx::query_as::<_, User>(
                r#"
                UPDATE users SET
                    email = $2,
                    name = $3,
                    last_login_at = NOW(),
                    last_oidc_groups = $4,
                    updated_at = NOW()
                WHERE id = $1
                RETURNING *
                "#,
            )
            .bind(existing.id)
            .bind(&oidc_user.email)
            .bind(&oidc_user.name)
            .bind(&oidc_user.groups)
            .fetch_one(self.user_repo.pool())
            .await
            .map_err(|e| OidcError::ProvisioningError(e.to_string()))?;

            (updated_user, false)
        } else {
            // Check if user exists by email (might be a local user)
            let existing_by_email = self
                .user_repo
                .get_user_by_email(&oidc_user.email)
                .await
                .ok();

            if let Some(existing) = existing_by_email {
                // SECURITY: Only link existing accounts if OIDC email is verified
                // This prevents account takeover where an attacker creates an OIDC
                // account with a victim's email (unverified) to hijack their local account
                if !oidc_user.email_verified {
                    warn!(
                        email = %oidc_user.email,
                        provider_id = %oidc_user.provider_id,
                        "Rejected OIDC account linking: email not verified by provider"
                    );
                    return Err(OidcError::ProvisioningError(
                        "Cannot link to existing account: email address must be verified by the identity provider".to_string()
                    ));
                }

                // Link existing user to OIDC provider
                let linked_user = sqlx::query_as::<_, User>(
                    r#"
                    UPDATE users SET
                        oidc_provider_id = $2,
                        oidc_subject = $3,
                        last_login_at = NOW(),
                        last_oidc_groups = $4,
                        updated_at = NOW()
                    WHERE id = $1
                    RETURNING *
                    "#,
                )
                .bind(existing.id)
                .bind(oidc_user.provider_id)
                .bind(&oidc_user.subject)
                .bind(&oidc_user.groups)
                .fetch_one(self.user_repo.pool())
                .await
                .map_err(|e| OidcError::ProvisioningError(e.to_string()))?;

                (linked_user, false)
            } else {
                // Create new user (JIT provisioning)
                let new_user = sqlx::query_as::<_, User>(
                    r#"
                    INSERT INTO users (email, name, status, oidc_provider_id, oidc_subject, last_login_at, last_oidc_groups)
                    VALUES ($1, $2, 'active', $3, $4, NOW(), $5)
                    RETURNING *
                    "#
                )
                .bind(&oidc_user.email)
                .bind(&oidc_user.name)
                .bind(oidc_user.provider_id)
                .bind(&oidc_user.subject)
                .bind(&oidc_user.groups)
                .fetch_one(self.user_repo.pool())
                .await
                .map_err(|e| OidcError::ProvisioningError(e.to_string()))?;

                (new_user, true)
            }
        };

        Ok((user, newly_created))
    }

    /// Sync user groups from OIDC claims
    /// Requirements: 3.4
    pub async fn sync_groups(
        &self,
        user_id: Uuid,
        oidc_groups: &[String],
        provider_id: Uuid,
    ) -> Result<(), OidcError> {
        // Get local group IDs for the OIDC groups
        let local_group_ids = self
            .oidc_repo
            .get_local_groups_for_oidc_groups(provider_id, oidc_groups)
            .await?;

        // Get current user groups
        let current_groups = self
            .user_repo
            .get_user_groups(user_id)
            .await
            .map_err(|e| OidcError::ProvisioningError(e.to_string()))?;

        let current_group_ids: Vec<Uuid> = current_groups.iter().map(|g| g.id).collect();

        // Add user to mapped groups they're not already in
        for group_id in &local_group_ids {
            if !current_group_ids.contains(group_id) {
                self.group_repo
                    .add_user_to_group(user_id, *group_id)
                    .await
                    .map_err(|e| OidcError::ProvisioningError(e.to_string()))?;
            }
        }

        // Note: We don't remove users from groups they were added to via OIDC
        // This is intentional - group removal should be explicit
        // If you want to sync groups exactly, you could remove users from
        // groups that are mapped but not in their OIDC claims

        Ok(())
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
