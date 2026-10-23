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
    /// A platform-brokered auth failure with a stable `<code>: <text>`
    /// message (`google_dwd_*`), shown to the tenant as-is.
    #[error("{0}")]
    Platform(String),
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
        self.0.values().map(String::as_str).filter(|v| v.len() >= 6)
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
    /// POST a JSON body to the platform pull broker's DWD-assertion route,
    /// authenticated as the run's tenant by the runner (the plugin never sees
    /// the caller key). Fails with [`crate::pull_broker::UNCONFIGURED`] when
    /// this process has no broker (engine-local, preview, open core).
    async fn post_dwd_assertion(&self, _body: &Value) -> Result<BrokerReply, String> {
        Err(crate::pull_broker::UNCONFIGURED.into())
    }
    /// POST a JSON body to the platform pull broker's Entra Graph token
    /// route (NAN-3503), authenticated as the run's tenant by the runner.
    /// Same failure contract as [`TokenFetch::post_dwd_assertion`].
    async fn post_graph_token(&self, _body: &Value) -> Result<BrokerReply, String> {
        Err(crate::pull_broker::UNCONFIGURED.into())
    }
    /// POST a JSON body to the platform pull broker's Okta client-assertion
    /// route (NAN-3503). Same failure contract as
    /// [`TokenFetch::post_dwd_assertion`].
    async fn post_okta_assertion(&self, _body: &Value) -> Result<BrokerReply, String> {
        Err(crate::pull_broker::UNCONFIGURED.into())
    }
}

/// The pull broker's answer to one call.
#[derive(Debug, Clone)]
pub struct BrokerReply {
    pub status: u16,
    /// `Retry-After` in seconds, when the broker sent one (429).
    pub retry_after: Option<u64>,
    pub body: Vec<u8>,
}

/// Longest `Retry-After` the plugin waits out inside a run; a longer one
/// fails the run and the feed backs off.
pub const BROKER_MAX_WAIT_SECS: u64 = 60;

pub struct AuthContext<'a> {
    pub creds: &'a Credentials,
    pub fetch: &'a dyn TokenFetch,
    pub scope: &'a Scope,
    pub now: DateTime<Utc>,
    /// The feed this run belongs to (hosted runner only).
    pub feed_id: Option<&'a str>,
}

#[async_trait::async_trait]
pub trait AuthPlugin: Send + Sync {
    /// Credential fields this plugin reads (validated before a run).
    fn credential_fields(&self) -> Vec<String>;
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
        reg!("basic", "Authorization: Basic base64(user:password)", BasicParams, |p: BasicParams| Ok::<_, AuthError>(BasicAuth(p))),
        reg!("oauth2_client_credentials", "RFC 6749 client credentials, cached, refreshed on 401", OAuth2Params, |p: OAuth2Params| {
            p.check()?;
            Ok::<_, AuthError>(OAuth2Auth { p, cache: TokenCache::default() })
        }),
        reg!("google_service_account", "Google service account JWT (RFC 7523, RS256), cached, refreshed on 401", GoogleSaParams, |p: GoogleSaParams| Ok::<_, AuthError>(GoogleSaAuth { p, cache: TokenCache::default() })),
        reg!("google_dwd_broker", "Keyless Google domain-wide delegation: the platform pull broker signs the assertion for the tenant's own service account (hosted only), cached, refreshed on 401", GoogleDwdBrokerParams, |p: GoogleDwdBrokerParams| Ok::<_, AuthError>(GoogleDwdBrokerAuth { p, cache: TokenCache::default(), service_account: Default::default() })),
        reg!("entra_fic_broker", "Keyless Microsoft Entra (Graph): the platform pull broker mints a Graph access token for the tenant's app registration with nano's federated identity credential (hosted only), cached, refreshed on 401", EntraFicBrokerParams, |p: EntraFicBrokerParams| Ok::<_, AuthError>(EntraFicBrokerAuth { p, cache: TokenCache::default() })),
        reg!("okta_broker_jwt", "Keyless Okta (API Services app, private_key_jwt): the platform pull broker signs the client assertion with the tenant's broker-held key; the runner trades it for an access token (hosted only), cached, refreshed on 401", OktaBrokerJwtParams, |p: OktaBrokerJwtParams| {
            p.check()?;
            Ok::<_, AuthError>(OktaBrokerJwtAuth { p, cache: TokenCache::default() })
        }),
        reg!("session_login", "Credential POST login; cached token or origin-scoped cookie, refreshed once on 401", SessionLoginParams, SessionLoginAuth::new),
        reg!("composite_token", "One header composed from two named credentials", CompositeTokenParams, CompositeTokenAuth::new),
        reg!("hmac", "HMAC request signature over method/path/timestamp/body", HmacParams, |p: HmacParams| {
            p.check()?;
            Ok::<_, AuthError>(HmacAuth { p, signatures: Default::default(), max_signatures: crate::spec::Limits::default().max_requests as usize })
        }),
        reg!("aws_sigv4", "AWS Signature Version 4", SigV4Params, |p: SigV4Params| Ok::<_, AuthError>(SigV4Auth(p))),
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

#[derive(Deserialize, JsonSchema)]
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
}

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
        match (&self.client_id_credential, &self.client_id) {
            (Some(_), None) => Ok(()),
            (None, Some(c)) => config_only("client_id", c),
            _ => Err(AuthError::Params("oauth2_client_credentials needs exactly one of client_id_credential and client_id".into())),
        }
    }
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GoogleSaParams {
    #[serde(rename = "type", default)]
    _t: Option<String>,
    pub token_url: String,
    pub private_key_credential: String,
    pub client_email_credential: String,
    pub scope: String,
    /// Domain-wide delegation subject; a template such as `{{config.ADMIN_EMAIL}}`.
    #[serde(default)]
    pub subject: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GoogleDwdBrokerParams {
    #[serde(rename = "type", default)]
    _t: Option<String>,
    /// Google's token endpoint (`https://oauth2.googleapis.com/token`); must
    /// be in the spec allowlist.
    pub token_url: String,
    /// The OAuth scope(s) requested, space-separated (the broker allowlists
    /// each).
    pub scope: String,
    /// The admin user to impersonate; a template such as `{{config.ADMIN_EMAIL}}`.
    pub subject: String,
}

impl GoogleDwdBrokerParams {
    fn scopes(&self) -> Vec<String> {
        self.scope.split_ascii_whitespace().map(str::to_string).collect()
    }
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EntraFicBrokerParams {
    #[serde(rename = "type", default)]
    _t: Option<String>,
    /// The tenant's Entra directory (tenant) id, a GUID; a template such as
    /// `{{config.DIRECTORY_ID}}`.
    pub directory_id: String,
    /// The tenant's app registration (client) id that trusts nano's
    /// federated credential, a GUID; a template such as `{{config.CLIENT_ID}}`.
    pub client_id: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OktaBrokerJwtParams {
    #[serde(rename = "type", default)]
    _t: Option<String>,
    /// The Okta org host (`acme.okta.com`); a template such as
    /// `{{config.OKTA_DOMAIN}}`. The token endpoint is
    /// `https://<okta_domain>/oauth2/v1/token` and must be in the allowlist.
    pub okta_domain: String,
    /// The API Services app's client id; a template such as `{{config.CLIENT_ID}}`.
    pub client_id: String,
    /// Okta scopes, space-separated (`okta.users.read okta.groups.read`).
    pub scope: String,
}

impl OktaBrokerJwtParams {
    fn check(&self) -> Result<(), AuthError> {
        config_only("okta_domain", &self.okta_domain)?;
        config_only("client_id", &self.client_id)?;
        if self.scope.split_ascii_whitespace().next().is_none() {
            return Err(AuthError::Params("okta_broker_jwt: scope is empty".into()));
        }
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

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SigV4Params {
    #[serde(rename = "type", default)]
    _t: Option<String>,
    pub region: String,
    pub service: String,
    pub access_key_credential: String,
    pub secret_key_credential: String,
    #[serde(default)]
    pub session_token_credential: Option<String>,
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

pub struct BasicAuth(BasicParams);

#[async_trait::async_trait]
impl AuthPlugin for BasicAuth {
    fn credential_fields(&self) -> Vec<String> {
        vec![self.0.username_credential.clone(), self.0.password_credential.clone()]
    }
    async fn apply(&self, req: &mut OutboundRequest, cx: &AuthContext<'_>) -> Result<(), AuthError> {
        let raw = format!("{}:{}", cx.creds.get(&self.0.username_credential)?, cx.creds.get(&self.0.password_credential)?);
        set_header(req, "Authorization", format!("Basic {}", STANDARD.encode(raw)));
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
                let mut form = vec![
                    ("grant_type".to_string(), "client_credentials".to_string()),
                    ("client_id".to_string(), client_id),
                    ("client_secret".to_string(), cx.creds.get(&self.p.client_secret_credential)?.to_string()),
                ];
                if let Some(s) = &self.p.scope {
                    form.push(("scope".into(), s.clone()));
                }
                exchange(cx, &render(&self.p.token_url)?, form).await
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
        "aud": p.token_url,
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
    fn token_endpoints(&self) -> Vec<String> {
        vec![self.p.token_url.clone()]
    }
    async fn apply(&self, req: &mut OutboundRequest, cx: &AuthContext<'_>) -> Result<(), AuthError> {
        let tok = self
            .cache
            .get_or_fetch(|| async {
                let assertion = google_assertion(&self.p, cx)?;
                exchange(
                    cx,
                    &self.p.token_url,
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

/// `google_dwd_broker`: no key in the tenant's hands. The runner asks the
/// platform pull broker for a DWD assertion signed by the tenant's own
/// service account (`signJwt` under workload identity), then trades it for
/// an access token at `token_url` (RFC 7523 jwt-bearer). The assertion and
/// the token are both derived secrets of the run.
pub struct GoogleDwdBrokerAuth {
    p: GoogleDwdBrokerParams,
    pub cache: TokenCache,
    /// The service account the broker last named (for error text only).
    service_account: std::sync::Mutex<Option<String>>,
}

/// A short machine code from an error body's `error` field, if it has one.
fn error_code(body: &[u8]) -> Option<String> {
    let v: Value = serde_json::from_slice(body).ok()?;
    let e = v.get("error")?;
    let code = e.as_str().or_else(|| e.get("code").and_then(Value::as_str)).or_else(|| e.get("status").and_then(Value::as_str))?;
    let ok = !code.is_empty() && code.len() <= 64 && code.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-');
    ok.then(|| code.to_ascii_lowercase())
}

/// A Google service account email, or nothing (never echo anything else).
fn service_account_email(v: &Value) -> Option<String> {
    let s = v.get("service_account")?.as_str()?;
    let ok = s.len() <= 128
        && s.ends_with(".iam.gserviceaccount.com")
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'@' || b == b'.');
    ok.then(|| s.to_string())
}

impl GoogleDwdBrokerAuth {
    fn sa_suffix(&self) -> String {
        match self.service_account.lock().expect("service account").as_deref() {
            Some(sa) => format!(" (service account {sa})"),
            None => String::new(),
        }
    }

    fn broker_error(&self, status: u16, body: &[u8], subject: &str) -> AuthError {
        if let Ok(v) = serde_json::from_slice::<Value>(body) {
            if let Some(sa) = service_account_email(&v) {
                *self.service_account.lock().expect("service account") = Some(sa);
            }
        }
        let code = error_code(body);
        let detail = code.as_deref().map(|c| format!(", {c}")).unwrap_or_default();
        let sa = self.sa_suffix();
        AuthError::Platform(match (status, code.as_deref()) {
            (403, Some("dwd_subject_denied")) => {
                let domain = subject.rsplit_once('@').map(|(_, d)| d.to_ascii_lowercase()).unwrap_or_default();
                format!("google_dwd_subject_denied: {domain} is a nano platform domain and cannot be the delegated admin; set ADMIN_EMAIL to an admin of your own Google Workspace domain (HTTP 403{detail})")
            }
            (401, _) => format!("google_dwd_broker_rejected: the pull broker refused this runner's caller token (HTTP 401{detail})"),
            (403, _) => format!("google_dwd_broker_denied: the pull broker or Google IAM denied signing for this tenant (HTTP 403{detail}){sa}"),
            (409, _) => format!("google_dwd_service_account_missing: this tenant has no Google service account provisioned yet (HTTP 409{detail})"),
            (400, _) => format!("google_dwd_broker_refused: the pull broker refused the request (HTTP 400{detail}); check ADMIN_EMAIL and the scope"),
            (s, _) if s >= 500 => format!("google_dwd_broker_unavailable: the pull broker is unavailable (HTTP {s}{detail}); retrying on the next run"),
            (s, _) => format!("google_dwd_broker_failed: unexpected pull broker answer (HTTP {s}{detail})"),
        })
    }

    /// Google's token endpoint refusing the delegated assertion, as fix-it
    /// text: an unauthorized client ID / scope, or an admin email that is not
    /// an active user of the Workspace. `None` for anything else.
    fn token_error(&self, body: &[u8], subject: &str) -> Option<AuthError> {
        let code = error_code(body)?;
        let description = serde_json::from_slice::<Value>(body)
            .ok()
            .and_then(|v| v.get("error_description").and_then(Value::as_str).map(str::to_ascii_lowercase))
            .unwrap_or_default();
        let not_authorized = |hint: &str| {
            AuthError::Platform(format!(
                "google_dwd_not_authorized: authorize the service account's client ID for domain-wide delegation with scope {}{}{hint}",
                self.p.scope,
                self.sa_suffix()
            ))
        };
        match code.as_str() {
            "unauthorized_client" | "access_denied" => Some(not_authorized("")),
            "invalid_grant" if ["email", "user", "subject", "account"].iter().any(|w| description.contains(w)) => {
                let domain = subject.rsplit_once('@').map(|(_, d)| d.to_ascii_lowercase()).unwrap_or_default();
                Some(AuthError::Platform(format!(
                    "google_dwd_invalid_subject: ADMIN_EMAIL is not a valid, active user of the Google Workspace ({domain}) that authorized the client ID; set it to an active admin of that domain (Google: invalid_grant)"
                )))
            }
            "invalid_grant" => Some(not_authorized(
                "; Google refused the delegated assertion (invalid_grant): check that the client ID is authorized in this Workspace's Admin console",
            )),
            _ => None,
        }
    }

    async fn fetch_token(&self, cx: &AuthContext<'_>) -> Result<(String, u64), AuthError> {
        let subject = template::render_str(&self.p.subject, cx.scope).map_err(|e| AuthError::Params(e.to_string()))?;
        let subject = subject.trim();
        if subject.is_empty() {
            return Err(AuthError::Params("google_dwd_broker: subject (the admin email) is empty".into()));
        }
        let unconfigured = || AuthError::Platform(format!("{}: this runner has no platform pull broker; Google Workspace (keyless) runs only on hosted collectors", crate::pull_broker::UNCONFIGURED));
        let feed_id = cx.feed_id.ok_or_else(unconfigured)?;
        let scopes = self.p.scopes();
        if scopes.is_empty() {
            return Err(AuthError::Params("google_dwd_broker: scope is empty".into()));
        }
        let body = serde_json::json!({ "feed_id": feed_id, "subject": subject, "scope": scopes });
        let mut waits = 0;
        let resp = loop {
            let r = match cx.fetch.post_dwd_assertion(&body).await {
                Ok(r) => r,
                Err(e) if e == crate::pull_broker::UNCONFIGURED => return Err(unconfigured()),
                Err(e) => return Err(AuthError::Platform(format!("google_dwd_broker_unavailable: the pull broker could not be reached ({e}); retrying on the next run"))),
            };
            match (r.status, r.retry_after) {
                (200, _) => break r.body,
                (429, Some(secs)) if secs <= BROKER_MAX_WAIT_SECS && waits < 2 => {
                    waits += 1;
                    tokio::time::sleep(Duration::from_secs(secs.max(1))).await;
                }
                (429, after) => {
                    let after = after.map(|s| format!("; retry after {s} s")).unwrap_or_default();
                    return Err(AuthError::Platform(format!("google_dwd_broker_rate_limited: the pull broker limits assertions per tenant (HTTP 429{after})")));
                }
                (s, _) => return Err(self.broker_error(s, &r.body, subject)),
            }
        };
        let v: Value = serde_json::from_slice(&resp).map_err(|_| AuthError::Platform("google_dwd_broker_failed: the pull broker answered with invalid JSON".into()))?;
        let assertion = match (v.get("kind").and_then(Value::as_str), v.get("assertion").and_then(Value::as_str)) {
            (Some("google_dwd_assertion"), Some(a)) if a.split('.').count() == 3 && a.len() <= 8192 => a.to_string(),
            _ => return Err(AuthError::Platform("google_dwd_broker_failed: the pull broker answer has no assertion".into())),
        };
        self.cache.remember(&assertion);
        if let Some(sa) = service_account_email(&v) {
            *self.service_account.lock().expect("service account") = Some(sa);
        }
        let form = vec![
            ("grant_type".to_string(), "urn:ietf:params:oauth:grant-type:jwt-bearer".to_string()),
            ("assertion".to_string(), assertion),
        ];
        let (status, body) = cx.fetch.post_form(&self.p.token_url, &form).await.map_err(AuthError::Token)?;
        if matches!(status, 400 | 401 | 403) {
            if let Some(e) = self.token_error(&body, subject) {
                return Err(e);
            }
        }
        if !(200..300).contains(&status) {
            let detail = error_code(&body).map(|c| format!(", {c}")).unwrap_or_default();
            return Err(AuthError::Token(format!("HTTP {status}{detail}")));
        }
        token_response(status, &body)
    }
}

#[async_trait::async_trait]
impl AuthPlugin for GoogleDwdBrokerAuth {
    fn credential_fields(&self) -> Vec<String> {
        vec![]
    }
    fn token_endpoints(&self) -> Vec<String> {
        vec![self.p.token_url.clone()]
    }
    async fn apply(&self, req: &mut OutboundRequest, cx: &AuthContext<'_>) -> Result<(), AuthError> {
        let tok = self.cache.get_or_fetch(|| self.fetch_token(cx)).await?;
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

/// Microsoft Graph, the only resource `entra_fic_broker` accepts a token for.
pub const GRAPH_RESOURCE: &str = "https://graph.microsoft.com";
/// Graph's well-known application id (an `aud` some v1 tokens carry).
const GRAPH_APP_ID: &str = "00000003-0000-0000-c000-000000000000";

/// `entra_fic_broker` (NAN-3503): no client secret in the tenant's hands.
/// The runner asks the platform pull broker for a Microsoft Graph access
/// token for the tenant's own app registration; the broker signs a client
/// assertion with nano's federated identity credential
/// (`sub = nano-connector:entra:<tenant>`), trades it at Entra and checks
/// the token. The plugin checks again what it can see (kind, resource, and
/// the `tid` / `appid`|`azp` / `aud` claims when the token is a JWT), so a
/// broker answer for another directory, app or resource is refused. The
/// token is a derived secret of the run, cached until 60 s before
/// `expires_on`, and dropped once on a Graph 401.
pub struct EntraFicBrokerAuth {
    p: EntraFicBrokerParams,
    pub cache: TokenCache,
}

fn is_guid(s: &str) -> bool {
    uuid::Uuid::parse_str(s).is_ok() && s.len() == 36
}

/// A number or a numeric string (Entra sends both).
fn num(v: Option<&Value>) -> Option<i64> {
    match v? {
        Value::Number(n) => n.as_i64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// The payload of a JWT, when `token` is one (no signature check: the
/// broker verified it; this is a consistency check on its answer).
fn jwt_claims(token: &str) -> Option<Value> {
    let mut parts = token.split('.');
    let (_h, p, _s) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(p.trim_end_matches('=')).ok()?).ok()
}

impl EntraFicBrokerAuth {
    fn broker_error(status: u16, body: &[u8]) -> AuthError {
        let code = error_code(body);
        let detail = code.as_deref().map(|c| format!(", {c}")).unwrap_or_default();
        AuthError::Platform(match status {
            401 => format!("entra_fic_broker_rejected: the pull broker refused this runner's caller token (HTTP 401{detail})"),
            403 => format!("entra_fic_denied: the pull broker or Entra denied a Graph token for this directory and app (HTTP 403{detail}); check that the app registration trusts nano's federated credential and has admin consent"),
            404 | 409 => format!("entra_fic_not_configured: the pull broker has no federated credential set up for this tenant (HTTP {status}{detail})"),
            400 => format!("entra_fic_refused: the pull broker refused the request (HTTP 400{detail}); check DIRECTORY_ID and CLIENT_ID"),
            s if s >= 500 => format!("entra_fic_broker_unavailable: the pull broker is unavailable (HTTP {s}{detail}); retrying on the next run"),
            s => format!("entra_fic_broker_failed: unexpected pull broker answer (HTTP {s}{detail})"),
        })
    }

    async fn fetch_token(&self, cx: &AuthContext<'_>) -> Result<(String, u64), AuthError> {
        let render = |what: &str, t: &str| -> Result<String, AuthError> {
            let v = template::render_str(t, cx.scope).map_err(|e| AuthError::Params(e.to_string()))?.trim().to_ascii_lowercase();
            if !is_guid(&v) {
                return Err(AuthError::Params(format!("entra_fic_broker: {what} must be a GUID")));
            }
            Ok(v)
        };
        let directory_id = render("directory_id", &self.p.directory_id)?;
        let client_id = render("client_id", &self.p.client_id)?;
        let unconfigured = || AuthError::Platform(format!("{}: this runner has no platform pull broker; Microsoft Entra (keyless) runs only on hosted collectors", crate::pull_broker::UNCONFIGURED));
        let feed_id = cx.feed_id.ok_or_else(unconfigured)?;
        let body = serde_json::json!({ "feed_id": feed_id, "directory_id": directory_id, "client_id": client_id });
        let mut waits = 0;
        let resp = loop {
            let r = match cx.fetch.post_graph_token(&body).await {
                Ok(r) => r,
                Err(e) if e == crate::pull_broker::UNCONFIGURED => return Err(unconfigured()),
                Err(e) => return Err(AuthError::Platform(format!("entra_fic_broker_unavailable: the pull broker could not be reached ({e}); retrying on the next run"))),
            };
            match (r.status, r.retry_after) {
                (200, _) => break r.body,
                (429, Some(secs)) if secs <= BROKER_MAX_WAIT_SECS && waits < 2 => {
                    waits += 1;
                    tokio::time::sleep(Duration::from_secs(secs.max(1))).await;
                }
                (429, after) => {
                    let after = after.map(|s| format!("; retry after {s} s")).unwrap_or_default();
                    return Err(AuthError::Platform(format!("entra_fic_broker_rate_limited: the pull broker limits Graph tokens per tenant (HTTP 429{after})")));
                }
                (s, _) => return Err(Self::broker_error(s, &r.body)),
            }
        };
        let bad = |why: &str| AuthError::Platform(format!("entra_fic_broker_failed: {why}"));
        let v: Value = serde_json::from_slice(&resp).map_err(|_| bad("the pull broker answered with invalid JSON"))?;
        let token = match (v.get("kind").and_then(Value::as_str), v.get("access_token").and_then(Value::as_str)) {
            (Some("azure_access_token"), Some(t)) if !t.is_empty() && t.len() <= 16384 && t.bytes().all(|b| b.is_ascii_graphic()) => t.to_string(),
            _ => return Err(bad("the pull broker answer has no access token")),
        };
        // Remember it before any refusal so it is redacted from every error.
        self.cache.remember(&token);
        if v.get("resource").and_then(Value::as_str).map(|r| r.trim_end_matches('/')) != Some(GRAPH_RESOURCE) {
            return Err(bad("the pull broker issued a token for another resource than Microsoft Graph"));
        }
        if let Some(claims) = jwt_claims(&token) {
            let s = |k: &str| claims.get(k).and_then(Value::as_str).map(str::to_ascii_lowercase);
            let aud = s("aud").map(|a| a.trim_end_matches('/').to_string());
            let app = s("appid").or_else(|| s("azp"));
            if s("tid").as_deref() != Some(directory_id.as_str()) {
                return Err(bad("the Graph token belongs to another directory (tid)"));
            }
            if app.as_deref() != Some(client_id.as_str()) {
                return Err(bad("the Graph token belongs to another app (appid / azp)"));
            }
            if !matches!(aud.as_deref(), Some(GRAPH_RESOURCE | GRAPH_APP_ID)) {
                return Err(bad("the Graph token is for another audience (aud)"));
            }
        }
        let now = cx.now.timestamp();
        let by_in = num(v.get("expires_in")).filter(|n| *n > 0);
        let by_on = num(v.get("expires_on")).map(|on| on - now).filter(|n| *n > 0);
        let ttl = match (by_in, by_on) {
            (Some(a), Some(b)) => a.min(b),
            (Some(a), None) | (None, Some(a)) => a,
            (None, None) => return Err(bad("the pull broker answer has no expiry")),
        };
        Ok((token, ttl as u64))
    }
}

#[async_trait::async_trait]
impl AuthPlugin for EntraFicBrokerAuth {
    fn credential_fields(&self) -> Vec<String> {
        vec![]
    }
    async fn apply(&self, req: &mut OutboundRequest, cx: &AuthContext<'_>) -> Result<(), AuthError> {
        let tok = self.cache.get_or_fetch(|| self.fetch_token(cx)).await?;
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

/// `okta_broker_jwt` (NAN-3503): Okta OAuth for an API Services app with
/// `private_key_jwt` and no client secret anywhere. The tenant's signing key
/// lives in its pull-broker Durable Object; the runner asks the broker for a
/// short-lived client assertion (`iss = sub = client_id`, `aud` = the org's
/// token endpoint, `exp` <= 300 s), checks it, trades it at
/// `https://<okta_domain>/oauth2/v1/token` (client credentials) and sends
/// `Authorization: Bearer <access_token>`. DPoP must be off on the app; a
/// DPoP demand fails with a fix-it error. Assertion and token are derived
/// secrets of the run; the token is cached and dropped once on a 401.
pub struct OktaBrokerJwtAuth {
    p: OktaBrokerJwtParams,
    pub cache: TokenCache,
}

/// Longest assertion lifetime the plugin accepts from the broker.
const OKTA_ASSERTION_MAX_SECS: i64 = 300;

fn is_plain_host(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && h.split('.').count() >= 2
        && h.split('.').all(|l| !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-'))
        && h.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
}

impl OktaBrokerJwtAuth {
    fn token_url(domain: &str) -> String {
        format!("https://{domain}/oauth2/v1/token")
    }

    fn broker_error(status: u16, body: &[u8]) -> AuthError {
        let code = error_code(body);
        let detail = code.as_deref().map(|c| format!(", {c}")).unwrap_or_default();
        AuthError::Platform(match status {
            401 => format!("okta_broker_rejected: the pull broker refused this runner's caller token (HTTP 401{detail})"),
            403 => format!("okta_broker_denied: the pull broker denied an Okta assertion for this tenant (HTTP 403{detail})"),
            404 | 409 => format!("okta_broker_not_configured: this tenant has no Okta signing key provisioned yet (HTTP {status}{detail})"),
            400 => format!("okta_broker_refused: the pull broker refused the request (HTTP 400{detail}); check OKTA_DOMAIN and CLIENT_ID"),
            s if s >= 500 => format!("okta_broker_unavailable: the pull broker is unavailable (HTTP {s}{detail}); retrying on the next run"),
            s => format!("okta_broker_failed: unexpected pull broker answer (HTTP {s}{detail})"),
        })
    }

    /// Okta's token endpoint refusing the exchange, as fix-it text.
    fn token_error(&self, status: u16, body: &[u8]) -> AuthError {
        let code = error_code(body).unwrap_or_default();
        AuthError::Platform(match code.as_str() {
            "invalid_dpop_proof" | "use_dpop_nonce" => format!(
                "okta_dpop_required: the Okta app requires DPoP ({code}); turn off \"Require Demonstrating Proof of Possession (DPoP) header in token requests\" on the API Services app"
            ),
            "invalid_client" => "okta_client_not_authorized: Okta refused the client assertion (invalid_client); register nano's public key (JWKS) on the API Services app and set CLIENT_ID to its client id".to_string(),
            "invalid_scope" => format!("okta_scope_not_granted: grant the Okta API scopes {} to the API Services app (invalid_scope)", self.p.scope),
            "unauthorized_client" => "okta_client_not_authorized: the app may not use the client credentials grant (unauthorized_client); create it as an API Services app".to_string(),
            "" => format!("okta_token_failed: the Okta token endpoint answered HTTP {status}"),
            c => format!("okta_token_failed: the Okta token endpoint answered HTTP {status}, {c}"),
        })
    }

    async fn fetch_token(&self, cx: &AuthContext<'_>) -> Result<(String, u64), AuthError> {
        let render = |t: &str| template::render_str(t, cx.scope).map_err(|e| AuthError::Params(e.to_string())).map(|v| v.trim().to_string());
        let domain = render(&self.p.okta_domain)?.to_ascii_lowercase();
        if !is_plain_host(&domain) {
            return Err(AuthError::Params("okta_broker_jwt: okta_domain must be a host name such as acme.okta.com".into()));
        }
        let client_id = render(&self.p.client_id)?;
        if client_id.is_empty() || client_id.len() > 128 || !client_id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') {
            return Err(AuthError::Params("okta_broker_jwt: client_id must be an Okta client id".into()));
        }
        let unconfigured = || AuthError::Platform(format!("{}: this runner has no platform pull broker; Okta (keyless) runs only on hosted collectors", crate::pull_broker::UNCONFIGURED));
        let feed_id = cx.feed_id.ok_or_else(unconfigured)?;
        let body = serde_json::json!({ "feed_id": feed_id, "okta_domain": domain, "client_id": client_id });
        let mut waits = 0;
        let resp = loop {
            let r = match cx.fetch.post_okta_assertion(&body).await {
                Ok(r) => r,
                Err(e) if e == crate::pull_broker::UNCONFIGURED => return Err(unconfigured()),
                Err(e) => return Err(AuthError::Platform(format!("okta_broker_unavailable: the pull broker could not be reached ({e}); retrying on the next run"))),
            };
            match (r.status, r.retry_after) {
                (200, _) => break r.body,
                (429, Some(secs)) if secs <= BROKER_MAX_WAIT_SECS && waits < 2 => {
                    waits += 1;
                    tokio::time::sleep(Duration::from_secs(secs.max(1))).await;
                }
                (429, after) => {
                    let after = after.map(|s| format!("; retry after {s} s")).unwrap_or_default();
                    return Err(AuthError::Platform(format!("okta_broker_rate_limited: the pull broker limits Okta assertions per tenant (HTTP 429{after})")));
                }
                (s, _) => return Err(Self::broker_error(s, &r.body)),
            }
        };
        let bad = |why: &str| AuthError::Platform(format!("okta_broker_failed: {why}"));
        let v: Value = serde_json::from_slice(&resp).map_err(|_| bad("the pull broker answered with invalid JSON"))?;
        let assertion = match (v.get("kind").and_then(Value::as_str), v.get("assertion").and_then(Value::as_str)) {
            (Some("okta_client_assertion"), Some(a)) if a.split('.').count() == 3 && a.len() <= 8192 => a.to_string(),
            _ => return Err(bad("the pull broker answer has no client assertion")),
        };
        self.cache.remember(&assertion);
        let token_url = Self::token_url(&domain);
        let claims = jwt_claims(&assertion).ok_or_else(|| bad("the client assertion is not a JWT"))?;
        let s = |k: &str| claims.get(k).and_then(Value::as_str);
        if s("iss") != Some(client_id.as_str()) || s("sub") != Some(client_id.as_str()) {
            return Err(bad("the client assertion is for another client (iss / sub)"));
        }
        if s("aud") != Some(token_url.as_str()) {
            return Err(bad("the client assertion is for another Okta org (aud)"));
        }
        let left = num(claims.get("exp")).map(|e| e - cx.now.timestamp());
        if !left.is_some_and(|l| l > 0 && l <= OKTA_ASSERTION_MAX_SECS + 30) {
            return Err(bad("the client assertion is expired or lives longer than 300 s"));
        }
        let form = vec![
            ("grant_type".to_string(), "client_credentials".to_string()),
            ("scope".to_string(), self.p.scope.split_ascii_whitespace().collect::<Vec<_>>().join(" ")),
            ("client_assertion_type".to_string(), "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".to_string()),
            ("client_assertion".to_string(), assertion),
        ];
        let (status, body) = cx.fetch.post_form(&token_url, &form).await.map_err(AuthError::Token)?;
        if !(200..300).contains(&status) {
            return Err(self.token_error(status, &body));
        }
        let token_type = serde_json::from_slice::<Value>(&body)
            .ok()
            .and_then(|v| v.get("token_type").and_then(Value::as_str).map(str::to_ascii_lowercase));
        if token_type.as_deref().is_some_and(|t| t != "bearer") {
            return Err(AuthError::Platform(
                "okta_dpop_required: Okta issued a DPoP-bound token; turn off DPoP on the API Services app".into(),
            ));
        }
        token_response(status, &body)
    }
}

#[async_trait::async_trait]
impl AuthPlugin for OktaBrokerJwtAuth {
    fn credential_fields(&self) -> Vec<String> {
        vec![]
    }
    fn token_endpoints(&self) -> Vec<String> {
        vec![Self::token_url(&self.p.okta_domain)]
    }
    async fn apply(&self, req: &mut OutboundRequest, cx: &AuthContext<'_>) -> Result<(), AuthError> {
        let tok = self.cache.get_or_fetch(|| self.fetch_token(cx)).await?;
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

pub struct SigV4Auth(SigV4Params);

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
    fn credential_fields(&self) -> Vec<String> {
        let mut v = vec![self.0.access_key_credential.clone(), self.0.secret_key_credential.clone()];
        v.extend(self.0.session_token_credential.clone());
        v
    }
    async fn apply(&self, req: &mut OutboundRequest, cx: &AuthContext<'_>) -> Result<(), AuthError> {
        let token = match &self.0.session_token_credential {
            Some(c) => Some(cx.creds.get(c)?.to_string()),
            None => None,
        };
        let hs = sigv4_headers(
            req,
            &self.0.region,
            &self.0.service,
            cx.creds.get(&self.0.access_key_credential)?,
            cx.creds.get(&self.0.secret_key_credential)?,
            token.as_deref(),
            cx.now,
        );
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
        assert!(build("bearer", &serde_json::json!({"credential": "T"}).as_object().unwrap().clone()).is_ok());
        assert!(build("bearer", &serde_json::json!({"credential": "T", "url": "x"}).as_object().unwrap().clone()).is_err());
        assert!(build("api_key_header", &serde_json::json!({"credential": "T", "header": "Host"}).as_object().unwrap().clone()).is_err());
        assert!(build("nope", &Default::default()).is_err());
        for (kind, example) in [
            ("session_login", serde_json::json!({"login_url":"https://api.example.com/login","credential_fields":{"username":"USER","password":"PASSWORD"},"response":{"type":"json_token","pointer":"/token","header":"X-Session"}})),
            ("composite_token", serde_json::json!({"header":"X-Auth-Token","first_credential":"KEY","second_credential":"ID","separator":"/"})),
        ] { assert!((registry().into_iter().find(|r| r.name == kind).unwrap().schema)().is_object()); build(kind, example.as_object().unwrap()).unwrap(); }
        let dwd = serde_json::json!({"token_url": "https://oauth2.googleapis.com/token", "scope": "s", "subject": "{{config.ADMIN_EMAIL}}"});
        let p = build("google_dwd_broker", dwd.as_object().unwrap()).unwrap();
        assert!(p.credential_fields().is_empty());
        assert_eq!(p.token_endpoints(), vec!["https://oauth2.googleapis.com/token".to_string()]);
        // No credential (or broker) field can ride in from a spec.
        for extra in [("private_key_credential", "PRIVATE_KEY"), ("broker_url", "https://evil.example.com"), ("key", "00")] {
            let mut m = dwd.as_object().unwrap().clone();
            m.insert(extra.0.into(), extra.1.into());
            assert!(build("google_dwd_broker", &m).is_err(), "{extra:?}");
        }
    }
}
