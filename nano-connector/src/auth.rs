//! Auth plugins and their registry.
//!
//! Adding an auth scheme is one struct implementing [`AuthPlugin`] plus one
//! [`AuthRegistration`] line: a name, a params schema and a constructor. The
//! engine owns the secret values; a plugin reads them from [`Credentials`] and
//! writes headers (or query, or a TLS identity) onto the outbound request.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::time::{Duration, Instant};

use aws_lc_rs::{digest, hmac, rand, signature};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

mod session;
mod duo;
pub use duo::DuoHmacParams;
use duo::DuoHmacAuth;
mod oauth_json;
pub use oauth_json::{OAuth2JsonCredentialParams, JsonCredentialFormat};
use oauth_json::OAuth2JsonCredentialAuth;
mod json_body;
pub use json_body::JsonBodyCredentialParams;
use json_body::JsonBodyCredentialAuth;
pub use session::{SessionLoginParams, SessionResponse, LoginEncoding, CompositeTokenParams};
use session::{SessionLoginAuth, CompositeTokenAuth};

use crate::broker::{ClientIdentity, OutboundRequest};
use crate::template::{self, Scope};

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("auth type `{0}` is not registered")]
    Unknown(String),
    #[error("auth parameters are invalid: {0}")]
    Params(String),
    #[error("credential `{0}` is missing")]
    MissingCredential(String),
    #[error("token endpoint failed: {0}")]
    Token(String),
    #[error("authentication endpoint rate limited")]
    RateLimited,
    #[error("signing failed: {0}")]
    Signing(String),
}

/// Secret values by credential field name. Never printed.
#[derive(Clone, Default)]
pub struct Credentials(HashMap<String, String>);

impl Credentials {
    pub fn new(map: HashMap<String, String>) -> Self {
        Self(map)
    }
    pub fn get(&self, name: &str) -> Result<&str, AuthError> {
        self.0
            .get(name)
            .map(String::as_str)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| AuthError::MissingCredential(name.to_string()))
    }
    /// Every secret value, for scrubbing responses and outbound checks.
    pub fn values(&self) -> impl Iterator<Item = &str> {
        self.0.values().map(String::as_str).filter(|v| v.len() >= crate::secrets::MIN_SECRET_LEN)
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.0.keys()).finish()
    }
}

/// Engine callback used by token-based plugins: a policy-checked form POST.
#[async_trait::async_trait]
pub trait TokenFetch: Send + Sync {
    async fn post_form(&self, url: &str, form: &[(String, String)]) -> Result<(u16, Vec<u8>), String>;
    /// Policy-checked login POST with bounded response headers/body. Never
    /// follows redirects; implementations must charge authentication budgets.
    async fn session_login(&self, _request: &OutboundRequest) -> Result<crate::broker::InboundResponse, String> {
        Err("session login is unavailable".into())
    }
}

pub struct AuthContext<'a> {
    pub creds: &'a Credentials,
    pub fetch: &'a dyn TokenFetch,
    pub scope: &'a Scope,
    pub now: DateTime<Utc>,
}

#[async_trait::async_trait]
pub trait AuthPlugin: Send + Sync {
    /// Credential fields this plugin reads (validated before a run).
    fn credential_fields(&self) -> Vec<String>;
    /// Of [`AuthPlugin::credential_fields`], the ones that are non-secret
    /// identifiers (a client id, an access key id, a username). Every other
    /// credential field is a secret: the engine requires it to be at least
    /// [`crate::secrets::MIN_SECRET_LEN`] bytes, so the response scrubber can
    /// always track it (shorter values are never matched, to avoid false
    /// positives on ordinary text).
    fn identifier_fields(&self) -> Vec<String> {
        Vec::new()
    }
    /// The credential fields that are secrets.
    fn secret_fields(&self) -> Vec<String> {
        let ids = self.identifier_fields();
        self.credential_fields().into_iter().filter(|f| !ids.contains(f)).collect()
    }
    /// URLs the plugin itself calls; they must be in the allowlist.
    fn token_endpoints(&self) -> Vec<String> {
        Vec::new()
    }
    /// A TLS client identity (mTLS).
    fn client_identity(&self, _creds: &Credentials) -> Result<Option<ClientIdentity>, AuthError> {
        Ok(None)
    }
    /// Sign or decorate one request (called again on every retry and hop).
    async fn apply(&self, req: &mut OutboundRequest, cx: &AuthContext<'_>) -> Result<(), AuthError>;
    /// Drop the cached token only if it decorated the rejected request.
    /// A stale rejection may still retry using the newer cached token.
    async fn invalidate(&self, _rejected: &OutboundRequest) -> bool {
        false
    }
    /// Configure bounded derived-secret retention from the compiled run cap.
    fn set_request_limit(&mut self, _max_requests: u32) {}
    /// Session logins may repeat one request after an explicit 401 refusal.
    /// Transport errors and other statuses never enable this exception.
    fn retry_unauthorized(&self) -> bool { false }
    /// Secrets the plugin minted during the run (access tokens). They are
    /// redacted and refused like credentials.
    fn derived_secrets(&self) -> Vec<String> {
        Vec::new()
    }
}

pub struct AuthRegistration {
    pub name: &'static str,
    pub summary: &'static str,
    pub schema: fn() -> Value,
    pub build: fn(&serde_json::Map<String, Value>) -> Result<Box<dyn AuthPlugin>, AuthError>,
}

fn params<T: for<'de> Deserialize<'de>>(m: &serde_json::Map<String, Value>) -> Result<T, AuthError> {
    serde_json::from_value(Value::Object(m.clone())).map_err(|e| AuthError::Params(e.to_string()))
}

fn schema_of<T: JsonSchema>() -> Value {
    serde_json::to_value(
        schemars::generate::SchemaSettings::default()
            .with(|s| s.inline_subschemas = true)
            .into_generator()
            .into_root_schema_for::<T>(),
    )
    .unwrap_or_default()
}


macro_rules! reg {
    ($name:literal, $summary:literal, $params:ty, $plugin:expr) => {
        AuthRegistration {
            name: $name,
            summary: $summary,
            schema: schema_of::<$params>,
            build: |m| {
                let p: $params = params(m)?;
                #[allow(clippy::redundant_closure_call)]
                Ok(Box::new(($plugin)(p)?))
            },
        }
    };
}

/// The registry. One line per auth scheme.
pub fn registry() -> Vec<AuthRegistration> {
    vec![
        reg!("none", "No authentication", NoParams, |_p| Ok::<_, AuthError>(NoAuth)),
        reg!("bearer", "Authorization: Bearer <credential>", CredParam, |p: CredParam| Ok::<_, AuthError>(
            HeaderAuth { header: "Authorization".into(), prefix: "Bearer ".into(), credential: p.credential, optional: false }
        )),
        reg!("okta_ssws", "Okta API token: Authorization: SSWS <credential>", CredParam, |p: CredParam| Ok::<_, AuthError>(
            HeaderAuth { header: "Authorization".into(), prefix: "SSWS ".into(), credential: p.credential, optional: false }
        )),
        reg!("api_key_header", "<header>: [prefix]<credential>", ApiKeyHeaderParams, |p: ApiKeyHeaderParams| {
            check_header_name(&p.header)?;
            Ok::<_, AuthError>(HeaderAuth { header: p.header, prefix: p.prefix.unwrap_or_default(), credential: p.credential, optional: p.optional })
        }),
        reg!("api_key_query", "?<param>=<credential>, applied by the engine", ApiKeyQueryParams, |p: ApiKeyQueryParams| Ok::<_, AuthError>(QueryAuth(p))),
        reg!("json_body_credential", "One credential in a top-level JSON request field", JsonBodyCredentialParams, JsonBodyCredentialAuth::new),
        reg!("basic", "Authorization: Basic base64(user:password)", BasicParams, |p: BasicParams| Ok::<_, AuthError>(BasicAuth { params: p, issued: Default::default(), max_requests: crate::spec::Limits::default().max_requests as usize })),
        reg!("oauth2_client_credentials", "RFC 6749 client credentials, cached, refreshed on 401", OAuth2Params, |p: OAuth2Params| {
            p.check()?;
            Ok::<_, AuthError>(OAuth2Auth { p, cache: TokenCache::default() })
        }),
        reg!("oauth2_json_credential", "OAuth client credentials with a scoped secret JSON field", OAuth2JsonCredentialParams, OAuth2JsonCredentialAuth::new),
        reg!("google_service_account", "Google service account JWT (RFC 7523, RS256), cached, refreshed on 401", GoogleSaParams, |p: GoogleSaParams| { p.check()?; Ok::<_, AuthError>(GoogleSaAuth { p, cache: TokenCache::default() }) }),
        reg!("session_login", "Credential POST login; cached token or origin-scoped cookie, refreshed once on 401", SessionLoginParams, SessionLoginAuth::new),
        reg!("composite_token", "One header composed from two named credentials", CompositeTokenParams, CompositeTokenAuth::new),
        reg!("hmac", "HMAC request signature over method/path/timestamp/body", HmacParams, |p: HmacParams| {
            p.check()?;
            Ok::<_, AuthError>(HmacAuth { p, signatures: Default::default(), max_signatures: crate::spec::Limits::default().max_requests as usize })
        }),
        reg!("duo_hmac", "Duo v5 HMAC-SHA512 with JSON body and signed headers", DuoHmacParams, DuoHmacAuth::new),
        reg!("aws_sigv4", "AWS Signature Version 4", SigV4Params, SigV4Auth::new),
        reg!("mtls", "TLS client certificate (PEM cert + key credentials), optional bearer", MtlsParams, |p: MtlsParams| Ok::<_, AuthError>(MtlsAuth(p))),
    ]
}

pub fn build(kind: &str, params: &serde_json::Map<String, Value>) -> Result<Box<dyn AuthPlugin>, AuthError> {
    let reg = registry()
        .into_iter()
        .find(|r| r.name == kind)
        .ok_or_else(|| AuthError::Unknown(kind.to_string()))?;
    (reg.build)(params)
}

/// `oneOf` over every registered plugin, each with its `type` constant.
pub fn registry_schema() -> schemars::Schema {
    let variants: Vec<Value> = registry()
        .into_iter()
        .map(|r| {
            let mut s = (r.schema)();
            if let Some(obj) = s.as_object_mut() {
                obj.remove("$schema");
                obj.insert("description".into(), Value::String(r.summary.into()));
                let props = obj.entry("properties").or_insert_with(|| Value::Object(Default::default()));
                props
                    .as_object_mut()
                    .expect("properties object")
                    .insert("type".into(), serde_json::json!({ "const": r.name }));
                let req = obj.entry("required").or_insert_with(|| Value::Array(vec![]));
                req.as_array_mut().expect("required array").push(Value::String("type".into()));
            }
            s
        })
        .collect();
    schemars::Schema::try_from(serde_json::json!({ "oneOf": variants })).expect("valid schema")
}

/// Plugins may not overwrite routing or framing headers.
fn check_header_name(h: &str) -> Result<(), AuthError> {
    const FORBIDDEN: &[&str] = &["host", "content-length", "transfer-encoding", "connection", "te", "upgrade"];
    if FORBIDDEN.contains(&h.to_ascii_lowercase().as_str()) || h.is_empty() || !h.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return Err(AuthError::Params(format!("header {h:?} cannot carry auth")));
    }
    Ok(())
}

fn set_header(req: &mut OutboundRequest, name: &str, value: String) {
    req.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
    req.headers.push((name.to_string(), value));
}

// ---------------------------------------------------------------- params

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoParams {
    #[serde(rename = "type", default)]
    _t: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CredParam {
    #[serde(rename = "type", default)]
    _t: Option<String>,
    /// Credential field holding the secret.
    pub credential: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApiKeyHeaderParams {
    #[serde(rename = "type", default)]
    _t: Option<String>,
    pub header: String,
    pub credential: String,
    #[serde(default)]
    pub prefix: Option<String>,
    /// Send the header only when the credential is set (keyless public tier).
    #[serde(default)]
    pub optional: bool,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApiKeyQueryParams {
    #[serde(rename = "type", default)]
    _t: Option<String>,
    pub param: String,
    pub credential: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BasicParams {
    #[serde(rename = "type", default)]
    _t: Option<String>,
    pub username_credential: String,
    pub password_credential: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OAuth2Params {
    #[serde(rename = "type", default)]
    _t: Option<String>,
    /// The token endpoint; may template `config.*` (for example
    /// `https://login.microsoftonline.com/{{config.DIRECTORY_ID}}/oauth2/v2.0/token`).
    /// The rendered URL must be in the spec allowlist.
    pub token_url: String,
    /// Credential field holding the client id. Exactly one of this and
    /// `client_id`.
    #[serde(default)]
    pub client_id_credential: Option<String>,
    /// The client id itself, not a secret; may template `config.*` (for
    /// example `{{config.CLIENT_ID}}`). Exactly one of this and
    /// `client_id_credential`.
    #[serde(default)]
    pub client_id: Option<String>,
    pub client_secret_credential: String,
    #[serde(default)]
    pub scope: Option<String>,
    /// RFC 6749 client authentication: form fields (default), or HTTP Basic.
    #[serde(default)]
    pub client_auth: OAuth2ClientAuth,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OAuth2ClientAuth { #[default] Body, Basic }

/// Plugin parameters that may template only `config.*`.
fn config_only(what: &str, t: &str) -> Result<(), AuthError> {
    for r in template::references(t).map_err(|e| AuthError::Params(format!("{what}: {e}")))? {
        if !r.starts_with("config.") {
            return Err(AuthError::Params(format!("{what} may only template config.*")));
        }
    }
    Ok(())
}

impl OAuth2Params {
    fn check(&self) -> Result<(), AuthError> {
        config_only("token_url", &self.token_url)?;
        if let Some(scope) = &self.scope { config_only("scope", scope)?; }
        match (&self.client_id_credential, &self.client_id) {
            (Some(_), None) => Ok(()),
            (None, Some(c)) => config_only("client_id", c),
            _ => Err(AuthError::Params("oauth2_client_credentials needs exactly one of client_id_credential and client_id".into())),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GoogleSaParams {
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    _t: Option<String>,
    pub token_url: String,
    pub private_key_credential: String,
    pub client_email_credential: String,
    pub scope: String,
    /// Domain-wide delegation subject; a template such as `{{config.ADMIN_EMAIL}}`.
    #[serde(default)]
    pub subject: Option<String>,
}
impl GoogleSaParams {
    fn check(&self) -> Result<(), AuthError> {
        config_only("service-account token_url", &self.token_url)?;
        if self.scope.is_empty() || self.scope.len() > 4096 || !template::references(&self.scope)
            .map_err(|_| AuthError::Params("invalid service-account scope".into()))?.is_empty() {
            return Err(AuthError::Params("service-account scope must be literal".into()));
        }
        if let Some(subject) = &self.subject { config_only("service-account subject", subject)?; }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone, Copy, Default)]
#[serde(rename_all = "snake_case")]
pub enum HmacAlg {
    /// For vendor protocols that explicitly require legacy HMAC-SHA1.
    Sha1,
    Sha384,
    #[default]
    Sha256,
    Sha512,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone, Copy, Default)]
#[serde(rename_all = "snake_case")]
pub enum SigEncoding {
    #[default]
    Hex,
    Base64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HmacParams {
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    _t: Option<String>,
    pub credential: String,
    pub header: String,
    /// Canonical fields: method, path (with query), uri_path, query, host,
    /// timestamp, body, body_sha256 and body_sha512, in single braces.
    pub message: String,
    #[serde(default)]
    pub algorithm: HmacAlg,
    #[serde(default)]
    pub encoding: SigEncoding,
    #[serde(default)]
    pub prefix: Option<String>,
    #[serde(default)]
    pub timestamp_header: Option<String>,
    #[serde(default)]
    pub timestamp_format: HmacTimestamp,
    #[serde(default)]
    pub key_id_header: Option<String>,
    #[serde(default)]
    pub key_id_credential: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SigV4Params {
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    _t: Option<String>,
    pub region: String,
    pub service: String,
    pub access_key_credential: String,
    pub secret_key_credential: String,
    #[serde(default)]
    pub session_token_credential: Option<String>,
}
impl SigV4Params {
    fn check(&self) -> Result<(), AuthError> {
        config_only("SigV4 region", &self.region)?;
        if self.service.is_empty() || self.service.len() > 64
            || !self.service.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
            return Err(AuthError::Params("invalid SigV4 service".into()));
        }
        Ok(())
    }
}
fn sigv4_region(p: &SigV4Params, scope: &Scope) -> Result<String, AuthError> {
    let region = template::render_str(&p.region, scope).map_err(|_| AuthError::Params("invalid SigV4 region".into()))?;
    if region.is_empty() || region.len() > 64
        || !region.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
        return Err(AuthError::Params("invalid SigV4 region".into()));
    }
    Ok(region)
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MtlsParams {
    #[serde(rename = "type", default)]
    _t: Option<String>,
    pub cert_credential: String,
    pub key_credential: String,
    #[serde(default)]
    pub bearer_credential: Option<String>,
}

// ---------------------------------------------------------------- plugins

pub struct NoAuth;

#[async_trait::async_trait]
impl AuthPlugin for NoAuth {
    fn credential_fields(&self) -> Vec<String> {
        vec![]
    }
    async fn apply(&self, _: &mut OutboundRequest, _: &AuthContext<'_>) -> Result<(), AuthError> {
        Ok(())
    }
}

pub struct HeaderAuth {
    header: String,
    prefix: String,
    credential: String,
    optional: bool,
}

#[async_trait::async_trait]
impl AuthPlugin for HeaderAuth {
    fn credential_fields(&self) -> Vec<String> {
        if self.optional { vec![] } else { vec![self.credential.clone()] }
    }
    /// Optional or not, a key that is set is sent, so it is a secret.
    fn secret_fields(&self) -> Vec<String> {
        vec![self.credential.clone()]
    }
    async fn apply(&self, req: &mut OutboundRequest, cx: &AuthContext<'_>) -> Result<(), AuthError> {
        if self.optional && cx.creds.get(&self.credential).is_err() {
            return Ok(());
        }
        let v = format!("{}{}", self.prefix, cx.creds.get(&self.credential)?);
        set_header(req, &self.header, v);
        Ok(())
    }
}

pub struct QueryAuth(ApiKeyQueryParams);

#[async_trait::async_trait]
impl AuthPlugin for QueryAuth {
    fn credential_fields(&self) -> Vec<String> {
        vec![self.0.credential.clone()]
    }
    async fn apply(&self, req: &mut OutboundRequest, cx: &AuthContext<'_>) -> Result<(), AuthError> {
        let key = cx.creds.get(&self.0.credential)?.to_string();
        let pairs: Vec<(String, String)> = req
            .url
            .query_pairs()
            .filter(|(k, _)| k != &self.0.param)
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        req.url.query_pairs_mut().clear().extend_pairs(pairs).append_pair(&self.0.param, &key);
        Ok(())
    }
}

pub struct BasicAuth {
    params: BasicParams,
    issued: std::sync::Mutex<Vec<[String; 2]>>,
    max_requests: usize,
}

#[async_trait::async_trait]
impl AuthPlugin for BasicAuth {
    fn set_request_limit(&mut self, max_requests: u32) {
        self.max_requests = max_requests as usize;
    }
    fn credential_fields(&self) -> Vec<String> {
        vec![self.params.username_credential.clone(), self.params.password_credential.clone()]
    }
    fn identifier_fields(&self) -> Vec<String> {
        vec![self.params.username_credential.clone()]
    }
    fn derived_secrets(&self) -> Vec<String> {
        self.issued.lock().expect("Basic issued authorization").iter().flatten().cloned().collect()
    }
    async fn apply(&self, req: &mut OutboundRequest, cx: &AuthContext<'_>) -> Result<(), AuthError> {
        let raw = format!("{}:{}", cx.creds.get(&self.params.username_credential)?, cx.creds.get(&self.params.password_credential)?);
        let encoded = STANDARD.encode(raw);
        let authorization = format!("Basic {encoded}");
        {
            let mut issued = self.issued.lock().expect("Basic issued authorization");
            // A Basic envelope is itself encoded credential material; retain
            // it for vendors reflecting another encoding of the whole header.
            if !issued.iter().any(|pair| pair[0] == authorization) {
                if issued.len() >= self.max_requests {
                    return Err(AuthError::Signing("authorization request cap reached".into()));
                }
                issued.push([authorization.clone(), encoded]);
            }
        }
        set_header(req, "Authorization", authorization);
        Ok(())
    }
}

/// One bearer token per (plugin, run), shared by fan-out tasks.
#[derive(Default)]
pub struct TokenCache {
    slot: tokio::sync::Mutex<Option<(String, Instant)>>,
    pub fetches: std::sync::atomic::AtomicU32,
    /// Every token issued during the run (for redaction).
    issued: std::sync::Mutex<Vec<String>>,
}

impl TokenCache {
    async fn get_or_fetch<F, Fut>(&self, fetch: F) -> Result<String, AuthError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<(String, u64), AuthError>>,
    {
        let mut slot = self.slot.lock().await;
        if let Some((tok, exp)) = slot.as_ref() {
            if Instant::now() < *exp {
                return Ok(tok.clone());
            }
        }
        let (tok, expires_in) = fetch().await?;
        self.fetches.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.issued.lock().expect("issued tokens").push(tok.clone());
        // Refresh 60 s early so a long page walk does not race the expiry.
        let ttl = Duration::from_secs(expires_in.saturating_sub(60).max(1));
        *slot = Some((tok.clone(), Instant::now() + ttl));
        Ok(tok)
    }

    async fn invalidate(&self, rejected: &OutboundRequest, header: &str, prefix: &str) -> bool {
        let Some(token) = rejected
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(header))
            .and_then(|(_, value)| value.strip_prefix(prefix))
        else {
            return false;
        };
        // Hold the same lock as get_or_fetch: a late 401 for token A must
        // never evict token B fetched by another fan-out task.
        let mut slot = self.slot.lock().await;
        if slot.as_ref().is_some_and(|(cached, _)| cached == token) {
            *slot = None;
        }
        true
    }

    /// Record a secret minted on the way to a token (a signed assertion) so
    /// the run redacts and refuses it like the token itself.
    fn remember(&self, secret: &str) {
        self.issued.lock().expect("issued tokens").push(secret.to_string());
    }

    pub fn issued(&self) -> Vec<String> {
        self.issued.lock().expect("issued tokens").clone()
    }
}

async fn exchange(cx: &AuthContext<'_>, url: &str, form: Vec<(String, String)>) -> Result<(String, u64), AuthError> {
    let (status, body) = cx.fetch.post_form(url, &form).await.map_err(AuthError::Token)?;
    token_response(status, &body)
}

fn token_response(status: u16, body: &[u8]) -> Result<(String, u64), AuthError> {
    if !(200..300).contains(&status) {
        return Err(AuthError::Token(format!("HTTP {status}")));
    }
    let v: Value = serde_json::from_slice(body).map_err(|e| AuthError::Token(e.to_string()))?;
    let tok = v
        .get("access_token")
        .and_then(Value::as_str)
        .ok_or_else(|| AuthError::Token("no access_token".into()))?;
    let exp = v.get("expires_in").and_then(Value::as_u64).unwrap_or(3600);
    Ok((tok.to_string(), exp))
}

pub struct OAuth2Auth {
    p: OAuth2Params,
    pub cache: TokenCache,
}

#[async_trait::async_trait]
impl AuthPlugin for OAuth2Auth {
    fn credential_fields(&self) -> Vec<String> {
        self.p.client_id_credential.iter().cloned().chain([self.p.client_secret_credential.clone()]).collect()
    }
    fn identifier_fields(&self) -> Vec<String> {
        self.p.client_id_credential.iter().cloned().collect()
    }
    fn token_endpoints(&self) -> Vec<String> {
        vec![self.p.token_url.clone()]
    }
    async fn apply(&self, req: &mut OutboundRequest, cx: &AuthContext<'_>) -> Result<(), AuthError> {
        let tok = self
            .cache
            .get_or_fetch(|| async {
                let render = |t: &str| template::render_str(t, cx.scope).map_err(|e| AuthError::Params(e.to_string()));
                let client_id = match (&self.p.client_id_credential, &self.p.client_id) {
                    (Some(c), _) => cx.creds.get(c)?.to_string(),
                    (None, Some(t)) => render(t)?.trim().to_string(),
                    (None, None) => String::new(),
                };
                if client_id.is_empty() {
                    return Err(AuthError::Params("oauth2_client_credentials: client_id is empty".into()));
                }
                let client_secret = cx.creds.get(&self.p.client_secret_credential)?;
                let mut form = vec![("grant_type".to_string(), "client_credentials".to_string())];
                if self.p.client_auth == OAuth2ClientAuth::Body {
                    form.push(("client_id".into(), client_id.clone()));
                    form.push(("client_secret".into(), client_secret.to_string()));
                }
                if let Some(s) = &self.p.scope {
                    let scope = render(s)?;
                    if scope.is_empty() || scope.len() > 4096 || scope.chars().any(char::is_control) {
                        return Err(AuthError::Params("invalid OAuth scope".into()));
                    }
                    form.push(("scope".into(), scope));
                }
                let url = render(&self.p.token_url)?;
                if self.p.client_auth == OAuth2ClientAuth::Body { return exchange(cx, &url, form).await; }
                // RFC 6749 2.3.1: form-encode each credential before Basic.
                let encode = |value: &str| url::form_urlencoded::Serializer::new(String::new())
                    .append_pair("", value).finish().trim_start_matches('=').to_string();
                let encoded = STANDARD.encode(format!("{}:{}", encode(&client_id), encode(client_secret)));
                self.cache.remember(&encoded);
                let authorization = format!("Basic {encoded}");
                self.cache.remember(&authorization);
                let body = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(&form).finish();
                let response = cx.fetch.session_login(&OutboundRequest {
                    method: http::Method::POST,
                    url: url.parse().map_err(|_| AuthError::Params("invalid OAuth token URL".into()))?,
                    headers: vec![("Content-Type".into(), "application/x-www-form-urlencoded".into()),
                        ("Authorization".into(), authorization), ("Accept".into(), "application/json".into())],
                    body: body.into(),
                }).await.map_err(|_| AuthError::Token("OAuth token exchange unavailable".into()))?;
                if response.status == 429 { return Err(AuthError::RateLimited); }
                token_response(response.status, &response.body)
            })
            .await?;
        set_header(req, "Authorization", format!("Bearer {tok}"));
        Ok(())
    }
    async fn invalidate(&self, rejected: &OutboundRequest) -> bool {
        self.cache
            .invalidate(rejected, "Authorization", "Bearer ")
            .await
    }
    fn derived_secrets(&self) -> Vec<String> {
        self.cache.issued()
    }
}

pub struct GoogleSaAuth {
    p: GoogleSaParams,
    pub cache: TokenCache,
}

/// PEM (PKCS#8) to DER. Accepts the literal `\n` escapes of SA JSON files.
pub fn pem_to_der(pem: &str) -> Result<Vec<u8>, AuthError> {
    let body: String = pem
        .replace("\\n", "\n")
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<String>()
        .split_whitespace()
        .collect();
    STANDARD.decode(body).map_err(|e| AuthError::Signing(format!("private key is not PEM: {e}")))
}

/// RS256-signed JWT assertion (RFC 7523).
pub fn google_assertion(p: &GoogleSaParams, cx: &AuthContext<'_>) -> Result<String, AuthError> {
    let key = signature::RsaKeyPair::from_pkcs8(&pem_to_der(cx.creds.get(&p.private_key_credential)?)?)
        .map_err(|e| AuthError::Signing(format!("private key rejected: {e}")))?;
    let iat = cx.now.timestamp();
    let mut claims = serde_json::json!({
        "iss": cx.creds.get(&p.client_email_credential)?,
        "scope": p.scope,
        "aud": template::render_str(&p.token_url, cx.scope).map_err(|_| AuthError::Params("invalid service-account token URL".into()))?,
        "iat": iat,
        "exp": iat + 3600,
    });
    if let Some(sub) = &p.subject {
        let s = template::render_str(sub, cx.scope).map_err(|e| AuthError::Params(e.to_string()))?;
        if !s.is_empty() {
            claims["sub"] = Value::String(s);
        }
    }
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let mut sig = vec![0u8; key.public_modulus_len()];
    key.sign(&signature::RSA_PKCS1_SHA256, &rand::SystemRandom::new(), input.as_bytes(), &mut sig)
        .map_err(|e| AuthError::Signing(e.to_string()))?;
    Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig)))
}

#[async_trait::async_trait]
impl AuthPlugin for GoogleSaAuth {
    fn credential_fields(&self) -> Vec<String> {
        vec![self.p.private_key_credential.clone(), self.p.client_email_credential.clone()]
    }
    fn identifier_fields(&self) -> Vec<String> {
        vec![self.p.client_email_credential.clone()]
    }
    fn token_endpoints(&self) -> Vec<String> {
        vec![self.p.token_url.clone()]
    }
    async fn apply(&self, req: &mut OutboundRequest, cx: &AuthContext<'_>) -> Result<(), AuthError> {
        let tok = self
            .cache
            .get_or_fetch(|| async {
                let assertion = google_assertion(&self.p, cx)?;
                self.cache.remember(&assertion);
                exchange(
                    cx,
                    &template::render_str(&self.p.token_url, cx.scope).map_err(|_| AuthError::Params("invalid service-account token URL".into()))?,
                    vec![
                        ("grant_type".into(), "urn:ietf:params:oauth:grant-type:jwt-bearer".into()),
                        ("assertion".into(), assertion),
                    ],
                )
                .await
            })
            .await?;
        set_header(req, "Authorization", format!("Bearer {tok}"));
        Ok(())
    }
    async fn invalidate(&self, rejected: &OutboundRequest) -> bool {
        self.cache
            .invalidate(rejected, "Authorization", "Bearer ")
            .await
    }
    fn derived_secrets(&self) -> Vec<String> {
        self.cache.issued()
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HmacTimestamp {
    #[default]
    UnixSeconds,
    Rfc3339,
    Rfc2822,
}

impl HmacParams {
    fn check(&self) -> Result<(), AuthError> {
        let mut headers = vec![self.header.as_str()];
        headers.extend(self.timestamp_header.as_deref());
        headers.extend(self.key_id_header.as_deref());
        let mut names = std::collections::BTreeSet::new();
        for h in headers {
            check_header_name(h)?;
            if !names.insert(h.to_ascii_lowercase()) {
                return Err(AuthError::Params("HMAC headers must be distinct".into()));
            }
        }
        if self.key_id_header.is_some() != self.key_id_credential.is_some()
            || self.message.is_empty()
            || self.message.len() > 8192
            || self
                .prefix
                .as_ref()
                .is_some_and(|p| p.len() > 128 || p.chars().any(char::is_control))
        {
            return Err(AuthError::Params("invalid HMAC parameters".into()));
        }
        canonical_parts(&self.message)?;
        Ok(())
    }
}
fn canonical_parts(message: &str) -> Result<Vec<(&str, bool)>, AuthError> {
    let mut rest = message;
    let mut parts = Vec::new();
    while let Some(start) = rest.find('{') {
        parts.push((&rest[..start], false));
        let end = rest[start..]
            .find('}')
            .map(|i| i + start)
            .ok_or_else(|| AuthError::Params("invalid HMAC canonical placeholder".into()))?;
        let field = &rest[start + 1..end];
        if !matches!(
            field,
            "method"
                | "path"
                | "uri_path"
                | "query"
                | "host"
                | "timestamp"
                | "body"
                | "body_sha256"
                | "body_sha512"
        ) {
            return Err(AuthError::Params(
                "unknown HMAC canonical placeholder".into(),
            ));
        }
        parts.push((field, true));
        rest = &rest[end + 1..];
    }
    parts.push((rest, false));
    Ok(parts)
}

pub struct HmacAuth {
    p: HmacParams,
    signatures: std::sync::Mutex<std::collections::VecDeque<String>>,
    max_signatures: usize,
}
#[async_trait::async_trait]
impl AuthPlugin for HmacAuth {
    fn set_request_limit(&mut self, max_requests: u32) {
        self.max_signatures = max_requests as usize;
    }
    fn credential_fields(&self) -> Vec<String> {
        let mut v = vec![self.p.credential.clone()];
        v.extend(self.p.key_id_credential.clone());
        v
    }
    fn identifier_fields(&self) -> Vec<String> {
        self.p.key_id_credential.iter().cloned().collect()
    }
    async fn apply(
        &self,
        req: &mut OutboundRequest,
        cx: &AuthContext<'_>,
    ) -> Result<(), AuthError> {
        let ts = match self.p.timestamp_format {
            HmacTimestamp::UnixSeconds => cx.now.timestamp().to_string(),
            HmacTimestamp::Rfc3339 => cx.now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            HmacTimestamp::Rfc2822 => cx.now.to_rfc2822(),
        };
        let path = match req.url.query() {
            Some(q) => format!("{}?{}", req.url.path(), q),
            None => req.url.path().to_string(),
        };
        let body256 = sha256_hex(&req.body);
        let body512 = hex::encode(digest::digest(&digest::SHA512, &req.body).as_ref());
        let mut msg = Vec::new();
        // Expand spec tokens once. Body/query bytes containing {timestamp} are
        // signed literally, never recursively interpreted as placeholders.
        for (part, field) in canonical_parts(&self.p.message)? {
            let bytes = if !field {
                part.as_bytes()
            } else {
                match part {
                    "method" => req.method.as_str().as_bytes(),
                    "path" => path.as_bytes(),
                    "uri_path" => req.url.path().as_bytes(),
                    "query" => req.url.query().unwrap_or_default().as_bytes(),
                    "host" => req.url.host_str().unwrap_or_default().as_bytes(),
                    "timestamp" => ts.as_bytes(),
                    "body" => &req.body,
                    "body_sha256" => body256.as_bytes(),
                    "body_sha512" => body512.as_bytes(),
                    _ => unreachable!("validated placeholder"),
                }
            };
            if msg.len().saturating_add(bytes.len()) > 8 * 1024 * 1024 {
                return Err(AuthError::Signing("canonical message exceeds limit".into()));
            }
            msg.extend_from_slice(bytes);
        }
        let alg = match self.p.algorithm {
            HmacAlg::Sha1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            HmacAlg::Sha256 => hmac::HMAC_SHA256,
            HmacAlg::Sha384 => hmac::HMAC_SHA384,
            HmacAlg::Sha512 => hmac::HMAC_SHA512,
        };
        let key = hmac::Key::new(alg, cx.creds.get(&self.p.credential)?.as_bytes());
        let tag = hmac::sign(&key, &msg);
        let sig = match self.p.encoding {
            SigEncoding::Hex => hex::encode(tag.as_ref()),
            SigEncoding::Base64 => STANDARD.encode(tag.as_ref()),
        };
        {
            let mut signatures = self.signatures.lock().expect("HMAC signatures");
            // Never forget an early signature while its response may still
            // be reflected. Refuse signing if a caller exceeds the run cap.
            if signatures.len() >= self.max_signatures {
                return Err(AuthError::Signing("signature request cap reached".into()));
            }
            signatures.push_back(sig.clone());
        }
        set_header(
            req,
            &self.p.header,
            format!("{}{}", self.p.prefix.as_deref().unwrap_or_default(), sig),
        );
        if let Some(h) = &self.p.timestamp_header {
            set_header(req, h, ts);
        }
        if let (Some(h), Some(c)) = (&self.p.key_id_header, &self.p.key_id_credential) {
            set_header(req, h, cx.creds.get(c)?.to_string());
        }
        Ok(())
    }
    fn derived_secrets(&self) -> Vec<String> {
        self.signatures
            .lock()
            .expect("HMAC signatures")
            .iter()
            .cloned()
            .collect()
    }
}

pub struct SigV4Auth {
    params: SigV4Params,
    issued: std::sync::Mutex<Vec<[String; 2]>>,
    max_requests: usize,
}
impl SigV4Auth {
    fn new(params: SigV4Params) -> Result<Self, AuthError> {
        params.check()?;
        Ok(Self { params, issued: Default::default(), max_requests: crate::spec::Limits::default().max_requests as usize })
    }
}

fn sha256_hex(b: &[u8]) -> String {
    hex::encode(digest::digest(&digest::SHA256, b).as_ref())
}

fn hmac256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), msg).as_ref().to_vec()
}

/// RFC 3986 encoding as SigV4 requires (unreserved set only).
fn aws_encode(s: &str) -> String {
    const SET: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'_')
        .remove(b'.')
        .remove(b'~');
    percent_encoding::utf8_percent_encode(s, SET).to_string()
}

/// Sign `req` with SigV4 (returns the headers to add). Public for the AWS
/// test-vector test.
pub fn sigv4_headers(
    req: &OutboundRequest,
    region: &str,
    service: &str,
    access_key: &str,
    secret_key: &str,
    session_token: Option<&str>,
    now: DateTime<Utc>,
) -> Vec<(String, String)> {
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date = now.format("%Y%m%d").to_string();
    let host = req.url.host_str().unwrap_or_default().to_string();
    let mut signed: BTreeMap<String, String> = BTreeMap::new();
    signed.insert("host".into(), host);
    signed.insert("x-amz-date".into(), amz_date.clone());
    if let Some(t) = session_token {
        signed.insert("x-amz-security-token".into(), t.to_string());
    }
    let mut q: Vec<(String, String)> = req
        .url
        .query_pairs()
        .map(|(k, v)| (aws_encode(&k), aws_encode(&v)))
        .collect();
    q.sort();
    let canonical_query = q.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("&");
    let canonical_headers: String = signed.iter().map(|(k, v)| format!("{k}:{}\n", v.trim())).collect();
    let signed_headers = signed.keys().cloned().collect::<Vec<_>>().join(";");
    let canonical = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        req.method.as_str(),
        req.url.path(),
        canonical_query,
        canonical_headers,
        signed_headers,
        sha256_hex(&req.body)
    );
    let scope = format!("{date}/{region}/{service}/aws4_request");
    let sts = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}", sha256_hex(canonical.as_bytes()));
    let k = hmac256(format!("AWS4{secret_key}").as_bytes(), date.as_bytes());
    let k = hmac256(&k, region.as_bytes());
    let k = hmac256(&k, service.as_bytes());
    let k = hmac256(&k, b"aws4_request");
    let sig = hex::encode(hmac256(&k, sts.as_bytes()));
    let mut out = vec![
        ("x-amz-date".to_string(), amz_date),
        (
            "Authorization".to_string(),
            format!("AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed_headers}, Signature={sig}"),
        ),
    ];
    if let Some(t) = session_token {
        out.push(("x-amz-security-token".into(), t.into()));
    }
    out
}

#[async_trait::async_trait]
impl AuthPlugin for SigV4Auth {
    fn set_request_limit(&mut self, max_requests: u32) {
        self.max_requests = max_requests as usize;
    }
    fn derived_secrets(&self) -> Vec<String> {
        self.issued.lock().expect("SigV4 issued signatures").iter().flatten().cloned().collect()
    }
    fn credential_fields(&self) -> Vec<String> {
        let mut v = vec![self.params.access_key_credential.clone(), self.params.secret_key_credential.clone()];
        v.extend(self.params.session_token_credential.clone());
        v
    }
    fn identifier_fields(&self) -> Vec<String> {
        vec![self.params.access_key_credential.clone()]
    }
    async fn apply(&self, req: &mut OutboundRequest, cx: &AuthContext<'_>) -> Result<(), AuthError> {
        let token = match &self.params.session_token_credential {
            Some(c) => Some(cx.creds.get(c)?.to_string()),
            None => None,
        };
        let hs = sigv4_headers(
            req,
            &sigv4_region(&self.params, cx.scope)?,
            &self.params.service,
            cx.creds.get(&self.params.access_key_credential)?,
            cx.creds.get(&self.params.secret_key_credential)?,
            token.as_deref(),
            cx.now,
        );
        let authorization = hs.iter().find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
            .map(|(_, v)| v).ok_or_else(|| AuthError::Signing("SigV4 authorization missing".into()))?;
        let signature = authorization.rsplit_once("Signature=")
            .map(|(_, value)| value).ok_or_else(|| AuthError::Signing("SigV4 signature missing".into()))?;
        {
            let mut issued = self.issued.lock().expect("SigV4 issued signatures");
            // Never evict an early signature while a later response may echo it.
            // Refuse before decorating/sending when the compiled run cap is spent.
            if issued.len() >= self.max_requests {
                return Err(AuthError::Signing("signature request cap reached".into()));
            }
            issued.push([authorization.clone(), signature.to_owned()]);
        }
        for (k, v) in hs {
            set_header(req, &k, v);
        }
        Ok(())
    }
}

pub struct MtlsAuth(MtlsParams);

#[async_trait::async_trait]
impl AuthPlugin for MtlsAuth {
    fn credential_fields(&self) -> Vec<String> {
        let mut v = vec![self.0.cert_credential.clone(), self.0.key_credential.clone()];
        v.extend(self.0.bearer_credential.clone());
        v
    }
    fn client_identity(&self, creds: &Credentials) -> Result<Option<ClientIdentity>, AuthError> {
        ClientIdentity::from_pem(creds.get(&self.0.cert_credential)?, creds.get(&self.0.key_credential)?)
            .map(Some)
            .map_err(|e| AuthError::Params(e.to_string()))
    }
    async fn apply(&self, req: &mut OutboundRequest, cx: &AuthContext<'_>) -> Result<(), AuthError> {
        if let Some(c) = &self.0.bearer_credential {
            set_header(req, "Authorization", format!("Bearer {}", cx.creds.get(c)?));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committed_schema_covers_registered_auth() {
        let actual=crate::spec::ConnectorSpec::json_schema();
        let expected:Value=serde_json::from_str(include_str!("../docs/connector.schema.json")).unwrap();
        assert_eq!(actual, expected, "regenerate docs/connector.schema.json");
    }

    /// AWS sig-v4 test suite, `get-vanilla`.
    #[test]
    fn sigv4_matches_aws_test_vector() {
        let req = OutboundRequest {
            method: http::Method::GET,
            url: url::Url::parse("https://example.amazonaws.com/").unwrap(),
            headers: vec![],
            body: bytes::Bytes::new(),
        };
        let now = DateTime::parse_from_rfc3339("2015-08-30T12:36:00Z").unwrap().with_timezone(&Utc);
        let hs = sigv4_headers(&req, "us-east-1", "service", "AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", None, now);
        let auth = &hs.iter().find(|(k, _)| k == "Authorization").unwrap().1;
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
    }

    #[test]
    fn every_registered_plugin_has_a_schema_and_builds_from_its_example() {
        let names: Vec<_> = registry().iter().map(|r| r.name).collect();
        assert_eq!(names.len(), 16, "{names:?}");
        assert!(names.contains(&"json_body_credential"));
        assert!(names.contains(&"duo_hmac"));
        assert!(names.contains(&"oauth2_json_credential"));
        assert!(build("bearer", &serde_json::json!({"credential": "T"}).as_object().unwrap().clone()).is_ok());
        assert!(build("bearer", &serde_json::json!({"credential": "T", "url": "x"}).as_object().unwrap().clone()).is_err());
        assert!(build("api_key_header", &serde_json::json!({"credential": "T", "header": "Host"}).as_object().unwrap().clone()).is_err());
        assert!(build("nope", &Default::default()).is_err());
        for (kind, example) in [
            ("session_login", serde_json::json!({"login_url":"https://api.example.com/login","credential_fields":{"username":"USER","password":"PASSWORD"},"response":{"type":"json_token","pointer":"/token","header":"X-Session"}})),
            ("composite_token", serde_json::json!({"header":"X-Auth-Token","first_credential":"KEY","second_credential":"ID","separator":"/"})),
            ("duo_hmac", serde_json::json!({"integration_key_credential":"IKEY","secret_key_credential":"SKEY"})),
            ("oauth2_json_credential", serde_json::json!({"oauth2":{"token_url":"https://api.example.com/token","client_id_credential":"CLIENT_ID","client_secret_credential":"CLIENT_SECRET"},"credential":"PIN","field_pointer":"/command/pin","selector_pointer":"/command/type","selector_value":"LOCK","format":"six_digit_pin"})),
            ("json_body_credential", serde_json::json!({"credential":"ROUTING_KEY","field":"routing_key"})),
        ] { assert!((registry().into_iter().find(|r| r.name == kind).unwrap().schema)().is_object()); build(kind, example.as_object().unwrap()).unwrap(); }
    }
}

