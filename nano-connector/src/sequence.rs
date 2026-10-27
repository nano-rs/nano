//! Bounded declarative request sequences. Uses the connector compiler, auth
//! registry and policy-checked broker; never invokes a script or VRL worker.
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use crate::auth::{AuthContext, AuthPlugin, Credentials, TokenFetch};
use crate::broker::{BodyCaps, Broker, BrokerError, InboundResponse, OutboundRequest};
use crate::engine::{self, EngineConfig, RequestPurpose, Transport};
use crate::policy::{EgressDeny, HostPolicy};
use crate::preview::ReplayTransport;
use crate::secrets::SecretSet;
use crate::spec::{AllowRule, AuthConfig, Body, ConnectorSpec, Method, RequestTemplate};
use crate::template::{self, Scope};
use bytes::Bytes;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const MAX_STEPS: usize = 32;
pub const MAX_REQUESTS: u32 = 128;
pub const MAX_POLL_SECS: u64 = 900;
pub const MAX_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_TOTAL_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub method: Method,
    pub url: String,
    #[serde(default)]
    pub query: BTreeMap<String, String>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub json: Option<Value>,
    /// Exact JSON text, rendered by the production template engine. Used when
    /// the canonical serializer's field order is part of the body contract.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub json_text: Option<String>,
    #[serde(default)]
    pub form: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub idempotency_header: Option<String>,
    #[serde(default)]
    pub response_format: ResponseFormat,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResponseFormat {
    #[default]
    Json,
    Text,
}

impl Request {
    // Validation-only projection: the common compiler walks expressions in
    // JSON strings. The sequence renderer below preserves json_text bytes.
    fn compiler_template(&self) -> RequestTemplate {
        RequestTemplate {
            method: self.method,
            url: self.url.clone(),
            query: self.query.clone(),
            headers: self.headers.clone(),
            body: (self.json.is_some() || self.form.is_some() || self.json_text.is_some()).then(
                || Body {
                    json: self
                        .json
                        .clone()
                        .or_else(|| self.json_text.clone().map(Value::String)),
                    form: self.form.clone(),
                },
            ),
        }
    }
    pub fn strings(&self) -> Vec<String> {
        fn leaves(v: &Value, out: &mut Vec<String>) {
            match v {
                Value::String(s) => out.push(s.clone()),
                Value::Array(a) => a.iter().for_each(|v| leaves(v, out)),
                Value::Object(m) => m.iter().for_each(|(k, v)| {
                    out.push(k.clone());
                    leaves(v, out);
                }),
                _ => {}
            }
        }
        let mut out = vec![self.url.clone()];
        if let Some(text) = &self.json_text {
            out.push(text.clone());
        }
        for m in [&self.query, &self.headers] {
            for (k, v) in m {
                out.extend([k.clone(), v.clone()]);
            }
        }
        if let Some(m) = &self.form {
            for (k, v) in m {
                out.extend([k.clone(), v.clone()]);
            }
        }
        if let Some(v) = &self.json {
            leaves(v, &mut out);
        }
        out
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Step {
    pub id: String,
    #[serde(default)]
    pub skip_if: Option<SkipIf>,
    pub request: Request,
    pub expect: Expect,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkipIf {
    pub input_present: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Expect {
    pub status: Vec<u16>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub non_empty: bool,
    /// Text APIs can return application errors with HTTP 200.
    #[serde(default)]
    pub contains: Option<String>,
    /// Require an exact array cardinality (e.g. resolve exactly one device).
    #[serde(default)]
    pub items: Option<usize>,
    /// Require the selected JSON value to match exactly, including its type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub equals: Option<Value>,
    /// Assert a JSON type without rejecting an empty array/object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub json_type: Option<JsonType>,
    /// Additional literal JSON field assertions; an explicit null must be present.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, Value>,
    /// Bind response string identities to required input strings before the next step.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub input_equals: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum JsonType { Array, Object, String, Number, Boolean, Null }
impl JsonType {
    fn accepts(self, value: &Value) -> bool {
        match self {
            Self::Array => value.is_array(), Self::Object => value.is_object(),
            Self::String => value.is_string(), Self::Number => value.is_number(),
            Self::Boolean => value.is_boolean(), Self::Null => value.is_null(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Poll {
    pub request: Request,
    pub until: Until,
    pub interval_secs: u64,
    pub max_secs: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Until {
    pub path: String,
    pub one_of: Vec<Value>,
}

pub struct Plan {
    pub network_scope: crate::policy::NetworkScope,
    pub allow: Vec<AllowRule>,
    pub auth: Arc<dyn AuthPlugin>,
    pub auth_config: AuthConfig,
    pub steps: Vec<Step>,
    pub poll: Option<Poll>,
    pub outputs: BTreeMap<String, String>,
    pub timeout_secs: u64,
}

/// Compile every request using the same static engine checks as collectors.
pub fn compile(
    allow: &[AllowRule],
    auth: &AuthConfig,
    steps: &[Step],
    poll: Option<&Poll>,
    outputs: &BTreeMap<String, String>,
    timeout_secs: u64,
) -> Result<Plan, String> {
    if steps.is_empty() || steps.len() > MAX_STEPS || !(1..=60).contains(&timeout_secs) {
        return Err("invalid sequence size or timeout".into());
    }
    if let Some(p) = poll {
        if !(1..=60).contains(&p.interval_secs)
            || p.max_secs < p.interval_secs
            || p.max_secs > MAX_POLL_SECS
            || !matches!(p.request.method, Method::Get | Method::Head)
            || p.until.one_of.is_empty()
        {
            return Err("poll must be bounded and read-only".into());
        }
    }
    let requests = steps
        .iter()
        .map(|s| &s.request)
        .chain(poll.map(|p| &p.request));
    let mut streams = Vec::new();
    for (i, r) in requests.enumerate() {
        if usize::from(r.json.is_some())
            + usize::from(r.form.is_some())
            + usize::from(r.json_text.is_some())
            > 1
        {
            return Err("request must use only one body encoding".into());
        }
        if let Some(h) = &r.idempotency_header {
            if r.headers.keys().any(|k| k.eq_ignore_ascii_case(h)) {
                return Err("idempotency header collides with a static header".into());
            }
            http::HeaderName::from_bytes(h.as_bytes()).map_err(|_| "invalid idempotency header")?;
            if [
                "authorization",
                "proxy-authorization",
                "cookie",
                "host",
                "content-type",
                "content-length",
                "transfer-encoding",
                "connection",
                "x-api-key",
                "api-key",
                "x-apikey",
            ]
            .contains(&h.to_ascii_lowercase().as_str())
            {
                return Err("idempotency header is reserved".into());
            }
        }
        streams.push(json!({"id": format!("request_{i}"), "request": r.compiler_template()}));
    }
    for s in steps {
        if s.expect.input_equals.len() > 16
            || s.expect.input_equals.iter().any(|(path, input)| {
                path.len() > 256 || path.split('.').any(|p| p.is_empty()
                    || !p.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_'))
                    || input.is_empty() || input.len() > 64
                    || !input.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
            })
        {
            return Err("expect.input_equals requires at most 16 JSON paths and literal input names".into());
        }
        if s.expect.fields.len() > 16
            || s.expect.fields.keys().any(|p| {
                p.len() > 256
                    || p.split('.').any(|part| {
                        part.is_empty()
                            || !part.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
                    })
            })
        {
            return Err("expect.fields requires at most 16 valid JSON paths".into());
        }
        if s.expect.status.is_empty()
            || s.expect.status.iter().any(|s| !(200..300).contains(s))
            || ((s.expect.non_empty || s.expect.items.is_some() || s.expect.equals.is_some() || s.expect.json_type.is_some())
                && s.expect.path.is_none())
        {
            return Err("expect requires successful statuses and a path for non_empty".into());
        }
    }
    let spec: ConnectorSpec = serde_json::from_value(json!({"version":1,"name":"request_sequence","kind":"collector","allow":allow,"auth":auth,"streams":streams})).map_err(|e| e.to_string())?;
    let compiled =
        engine::compile(&spec, &engine::default_ceilings()).map_err(|e| e.to_string())?;
    Ok(Plan {
        network_scope: crate::policy::NetworkScope::Public,
        allow: allow.to_vec(),
        auth: compiled.auth,
        auth_config: auth.clone(),
        steps: steps.to_vec(),
        poll: poll.cloned(),
        outputs: outputs.clone(),
        timeout_secs,
    })
}

pub enum Mode<'a> {
    Live,
    DryRun,
    Replay(&'a ReplayTransport),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpSummary {
    pub step: String,
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub status: Option<u16>,
    pub deferred: Vec<String>,
}
#[derive(Debug, Serialize)]
pub struct Output {
    pub outputs: Value,
    pub http_summary: Vec<HttpSummary>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Invalid(String),
    #[error("authentication failed")]
    Auth,
    #[error("rate limited")]
    RateLimited,
    #[error("request outcome is ambiguous: {0}")]
    Ambiguous(String),
    #[error("poll completion timed out")]
    PollTimeout,
    #[error("{0}")]
    Failed(String),
}

fn present(v: &Value) -> bool {
    !v.is_null()
        && v.as_str() != Some("")
        && v.as_array().is_none_or(|a| !a.is_empty())
        && v.as_object().is_none_or(|m| !m.is_empty())
}
pub fn path<'a>(value: &'a Value, path: &str) -> &'a Value {
    field_path(value, path).unwrap_or(&Value::Null)
}

fn field_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    // An explicitly empty expectation path selects the complete JSON body,
    // including root-array receipts returned by batch response APIs.
    if path.is_empty() { return Some(value); }
    path.split('.').try_fold(value, |v, p| match v {
        Value::Object(m) => m.get(p),
        Value::Array(a) => p.parse::<usize>().ok().and_then(|i| a.get(i)),
        _ => None,
    })
}

/// Scrub every string (including keys), then fail closed on encoded leftovers.
pub fn scrub(value: &Value, secrets: &SecretSet) -> Value {
    let text = value.to_string();
    let redacted = secrets.redact_str(&text);
    if secrets.contains_decoded(redacted.as_bytes()) {
        return json!("[REDACTED]");
    }
    serde_json::from_str(&redacted).unwrap_or_else(|_| json!("[REDACTED]"))
}

fn render(r: &Request, scope: &Scope, key: Option<&str>) -> Result<OutboundRequest, Error> {
    let bad = |e: template::TemplateError| Error::Invalid(e.to_string());
    let mut remaining = template::MAX_RENDER_BYTES;
    let mut url = template::render_url(&r.url, scope).map_err(bad)?;
    spend(&mut remaining, url.as_str().len())?;
    for (k, v) in &r.query {
        let value = template::render_str(v, scope).map_err(bad)?;
        if value.is_empty() {
            continue;
        }
        let pair = url::form_urlencoded::Serializer::new(String::new())
            .append_pair(k, &value)
            .finish();
        if url
            .as_str()
            .len()
            .saturating_add(pair.len())
            .saturating_add(1)
            > crate::policy::MAX_URL_BYTES
        {
            return Err(Error::Invalid("rendered URL exceeds its byte limit".into()));
        }
        spend(&mut remaining, pair.len().saturating_add(1))?;
        url.query_pairs_mut().append_pair(k, &value);
    }
    let mut headers = Vec::new();
    for (k, v) in &r.headers {
        let value = template::render_str(v, scope).map_err(bad)?;
        spend(
            &mut remaining,
            k.len().saturating_add(value.len()).saturating_add(4),
        )?;
        headers.push((k.clone(), value));
    }
    let body = if let Some(text) = &r.json_text {
        headers.push(("Content-Type".into(), "application/json".into()));
        let rendered = template::render_str(text, scope).map_err(bad)?;
        serde_json::from_str::<Value>(&rendered)
            .map_err(|_| Error::Invalid("json_text must render valid JSON".into()))?;
        rendered.into_bytes()
    } else if let Some(v) = &r.json {
        headers.push(("Content-Type".into(), "application/json".into()));
        template::render_json(v, scope)
            .map_err(bad)?
            .to_string()
            .into_bytes()
    } else if let Some(m) = &r.form {
        headers.push((
            "Content-Type".into(),
            "application/x-www-form-urlencoded".into(),
        ));
        let mut body = String::new();
        for (k, v) in m {
            // A missing whole input value is absent, matching optional query
            // parameters. Preserve literal empty strings and explicit helpers.
            if let Some(reference) = v.strip_prefix("{{").and_then(|s| s.strip_suffix("}}")) {
                let reference = reference.trim();
                if reference.starts_with("input.")
                    && reference.split('.').all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
                    && template::evaluate(reference, scope).map_err(bad)?.is_null() {
                    continue;
                }
            }
            let value = template::render_str(v, scope).map_err(bad)?;
            let pair = url::form_urlencoded::Serializer::new(String::new())
                .append_pair(k, &value)
                .finish();
            spend(&mut remaining, pair.len().saturating_add(1))?;
            if !body.is_empty() {
                body.push('&');
            }
            body.push_str(&pair);
        }
        body.into_bytes()
    } else {
        Vec::new()
    };
    if r.form.is_none() {
        spend(&mut remaining, body.len())?;
    }
    if let Some(h) = &r.idempotency_header {
        let key = key.ok_or_else(|| Error::Invalid("idempotency key is required".into()))?;
        http::HeaderValue::from_str(key)
            .map_err(|_| Error::Invalid("invalid idempotency key".into()))?;
        spend(
            &mut remaining,
            h.len().saturating_add(key.len()).saturating_add(4),
        )?;
        headers.push((h.clone(), key.into()));
    }
    let method = match r.method {
        Method::Get => http::Method::GET,
        Method::Post => http::Method::POST,
        Method::Put => http::Method::PUT,
        Method::Patch => http::Method::PATCH,
        Method::Delete => http::Method::DELETE,
        Method::Head => http::Method::HEAD,
    };
    Ok(OutboundRequest {
        method,
        url,
        headers,
        body: Bytes::from(body),
    })
}

fn spend(remaining: &mut usize, bytes: usize) -> Result<(), Error> {
    *remaining = remaining
        .checked_sub(bytes)
        .ok_or_else(|| Error::Invalid("aggregate rendered data exceeds its byte limit".into()))?;
    Ok(())
}

struct Exchange<'a> {
    transport: &'a dyn Transport,
    hosts: HostPolicy,
    count: std::sync::atomic::AtomicU32,
    bytes: std::sync::atomic::AtomicU64,
    request_bytes: std::sync::atomic::AtomicU64,
    mutation_accepted: std::sync::atomic::AtomicBool,
    auth_rate_limited: std::sync::atomic::AtomicBool,
    timeout_secs: u64,
    budget: &'a dyn RequestBudget,
}
impl Exchange<'_> {
    async fn send(&self, r: &OutboundRequest, purpose: RequestPurpose) -> Result<InboundResponse, Error> {
        use std::sync::atomic::Ordering::Relaxed;
        self.hosts
            .check(&r.url)
            .map_err(|_| Error::Invalid("request is outside egress policy".into()))?;
        if self.count.fetch_add(1, Relaxed) >= MAX_REQUESTS {
            return Err(Error::Failed("request budget exhausted".into()));
        }
        let bytes = r
            .url
            .as_str()
            .len()
            .saturating_add(r.body.len())
            .saturating_add(
                r.headers
                    .iter()
                    .map(|(k, v)| k.len().saturating_add(v.len()))
                    .sum::<usize>(),
            ) as u64;
        if bytes > template::MAX_RENDER_BYTES as u64
            || self
                .request_bytes
                .fetch_add(bytes, Relaxed)
                .saturating_add(bytes)
                > MAX_TOTAL_BYTES
        {
            return Err(Error::Failed("request byte budget exhausted".into()));
        }
        if !self
            .budget
            .reserve()
            .await
            .map_err(|_| Error::Failed("usage accounting unavailable".into()))?
        {
            return Err(Error::RateLimited);
        }
        let caps = BodyCaps {
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_decompressed_bytes: MAX_RESPONSE_BYTES,
        };
        let result = tokio::time::timeout(
            Duration::from_secs(self.timeout_secs),
            self.transport.send_once_with_purpose(r, &self.hosts, caps, purpose),
        )
        .await;
        let ambiguous = || Error::Ambiguous("connection ended after send may have begun".into());
        let response = match result {
            Err(_) => {
                return Err(
                    if r.method == http::Method::GET || r.method == http::Method::HEAD {
                        Error::Failed("request timed out".into())
                    } else {
                        ambiguous()
                    },
                );
            }
            Ok(Err(e)) => {
                return Err(match e {
                    BrokerError::Deferred(_) => Error::RateLimited,
                    // A proxy refusal is always before send: say so plainly,
                    // it is an operator-visible platform condition.
                    BrokerError::EgressProxy(refusal) => {
                        Error::Failed(format!("{refusal}; the request was not sent"))
                    }
                    BrokerError::Policy(_)
                    | BrokerError::NotSent(_)
                    | BrokerError::Dns(..)
                    | BrokerError::DnsBlocked { .. }
                    | BrokerError::Connect(..)
                    | BrokerError::Tls(..)
                    | BrokerError::ClientCert(_)
                    | BrokerError::RequestTooLarge(_) => {
                        Error::Failed("request refused before send".into())
                    }
                    _ if r.method == http::Method::GET || r.method == http::Method::HEAD => {
                        Error::Failed("HTTP exchange failed".into())
                    }
                    _ => ambiguous(),
                });
            }
            Ok(Ok(r)) => r,
        };
        let bytes = response.body.len() as u64;
        if bytes > MAX_RESPONSE_BYTES
            || self.bytes.fetch_add(bytes, Relaxed).saturating_add(bytes) > MAX_TOTAL_BYTES
        {
            return Err(
                if r.method != http::Method::GET && r.method != http::Method::HEAD {
                    Error::Ambiguous("mutation response exceeded the byte budget".into())
                } else {
                    Error::Failed("response byte budget exhausted".into())
                },
            );
        }
        Ok(response)
    }
}
#[async_trait::async_trait]
impl TokenFetch for Exchange<'_> {
    async fn session_login(&self, request: &OutboundRequest) -> Result<InboundResponse, String> {
        let response = match self.send(request, RequestPurpose::Authentication).await {
            Ok(response) => response,
            Err(Error::RateLimited) => {
                self.auth_rate_limited
                    .store(true, std::sync::atomic::Ordering::Release);
                return Err("session exchange rate limited".into());
            }
            Err(_) => return Err("session exchange failed".into()),
        };
        if response.status == 429 {
            self.auth_rate_limited
                .store(true, std::sync::atomic::Ordering::Release);
        }
        Ok(response)
    }
    async fn post_form(
        &self,
        url: &str,
        form: &[(String, String)],
    ) -> Result<(u16, Vec<u8>), String> {
        let body = {
            let mut ser = url::form_urlencoded::Serializer::new(String::new());
            ser.extend_pairs(form.iter().map(|(k, v)| (k.as_str(), v.as_str())));
            ser.finish()
        };
        let request = OutboundRequest {
            method: http::Method::POST,
            url: url.parse().map_err(|_| "invalid token URL")?,
            headers: vec![(
                "Content-Type".into(),
                "application/x-www-form-urlencoded".into(),
            )],
            body: Bytes::from(body),
        };
        let response = match self.send(&request, RequestPurpose::Authentication).await {
            Ok(response) => response,
            Err(Error::RateLimited) => {
                self.auth_rate_limited
                    .store(true, std::sync::atomic::Ordering::Release);
                return Err("token exchange rate limited".into());
            }
            Err(_) => return Err("token exchange failed".into()),
        };
        if response.status == 429 {
            self.auth_rate_limited
                .store(true, std::sync::atomic::Ordering::Release);
        }
        Ok((response.status, response.body.to_vec()))
    }
}

pub struct RunContext<'a> {
    pub engine: &'a EngineConfig,
    pub credentials: &'a Credentials,
    pub secrets: &'a SecretSet,
    pub deny: EgressDeny,
    pub idempotency_key: Option<&'a str>,
    pub budget: &'a dyn RequestBudget,
}

#[async_trait::async_trait]
pub trait RequestBudget: Send + Sync {
    async fn reserve(&self) -> Result<bool, String>;
}

/// Execute without transport/status retries or redirect following. Session
/// authentication alone may re-login once after an explicit HTTP 401 refusal. The caller
/// owns durable retries, approval policy, and connection-scoped auth caching.
pub async fn run(
    ctx: &RunContext<'_>,
    plan: &Plan,
    mut scope: Scope,
    mode: Mode<'_>,
) -> Result<Output, Error> {
    let guard = template::SecretGuard::new(all_secrets(ctx, plan)?, ctx.secrets.clone());
    scope.secret_guard = Some(if matches!(&mode, Mode::DryRun) { guard.for_preview() } else { guard });
    let broker_deny = EgressDeny {
        hosts: ctx
            .engine
            .pull_broker
            .iter()
            .map(|b| b.host().to_string())
            .collect(),
        cidrs: vec![],
    };
    let hosts = HostPolicy::compile_for_network(&plan.allow, &scope, plan.network_scope)
        .and_then(|p| {
            p.with_deny(
                ctx.engine
                    .platform_deny
                    .merged(&ctx.deny)
                    .merged(&broker_deny),
            )
        })
        .map_err(|_| Error::Invalid("invalid egress policy".into()))?;
    if matches!(mode, Mode::DryRun) {
        return dry_run(plan, &mut scope, &hosts, ctx);
    }
    for name in plan.auth.credential_fields() {
        if ctx.credentials.get(&name).map_err(|_| Error::Auth)?.len()
            < crate::secrets::MIN_SECRET_LEN
        {
            return Err(Error::Auth);
        }
    }
    let replaying = matches!(&mode, Mode::Replay(_));
    let broker;
    let transport: &dyn Transport = match mode {
        Mode::Replay(t) => t,
        Mode::Live => match &ctx.engine.transport {
            Some(t) => t.as_ref(),
            None => {
                broker = Broker::new(
                    ctx.engine.broker.clone(),
                    plan.auth
                        .client_identity(ctx.credentials)
                        .map_err(|_| Error::Auth)?,
                )
                .map_err(|_| Error::Auth)?;
                &broker
            }
        },
        Mode::DryRun => unreachable!(),
    };
    let exchange = Exchange {
        transport,
        hosts,
        count: 0.into(),
        bytes: 0.into(),
        request_bytes: 0.into(),
        mutation_accepted: false.into(),
        auth_rate_limited: false.into(),
        timeout_secs: plan.timeout_secs,
        budget: ctx.budget,
    };
    let result: Result<Output, Error> = async {
        let mut summaries = Vec::new();
        for step in &plan.steps {
            if step
                .skip_if
                .as_ref()
                .is_some_and(|s| present(&scope.input[&s.input_present]))
            {
                continue;
            }
            let (body, summary) = request(
                ctx,
                plan,
                &scope,
                &exchange,
                &step.id,
                &step.request,
                Some(&step.expect),
            )
            .await?;
            scope.steps[&step.id] = body;
            summaries.push(summary);
        }
        if let Some(poll) = &plan.poll {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(poll.max_secs);
            let mut replay_elapsed = 0u64;
            loop {
                let (body, summary) = tokio::time::timeout_at(
                    deadline,
                    request(ctx, plan, &scope, &exchange, "poll", &poll.request, None),
                )
                .await
                .map_err(|_| Error::PollTimeout)??;
                scope.poll = body;
                summaries.push(summary);
                if poll
                    .until
                    .one_of
                    .contains(path(&scope.poll, &poll.until.path))
                {
                    break;
                }
                if replaying {
                    // A recording has no wall-clock latency. Advance its poll
                    // clock by the declared interval while preserving the same
                    // deadline and exchange caps as a live request sequence.
                    replay_elapsed = replay_elapsed.saturating_add(poll.interval_secs);
                    if replay_elapsed >= poll.max_secs {
                        return Err(Error::PollTimeout);
                    }
                    tokio::task::yield_now().await;
                } else {
                    tokio::time::timeout_at(
                        deadline,
                        tokio::time::sleep(Duration::from_secs(poll.interval_secs)),
                    )
                    .await
                    .map_err(|_| Error::PollTimeout)?;
                }
            }
        }
        scope.secret_guard = Some(template::SecretGuard::new(all_secrets(ctx, plan)?, ctx.secrets.clone()));
        let mut outputs = serde_json::Map::new();
        let mut remaining = template::MAX_RENDER_BYTES;
        for (k, p) in &plan.outputs {
            let v = template::evaluate(p, &scope)
                .map_err(|_| Error::Failed("output expression failed".into()))?;
            if v.is_null() {
                return Err(Error::Failed("output path did not resolve".into()));
            }
            spend(
                &mut remaining,
                k.len()
                    .saturating_add(v.to_string().len())
                    .saturating_add(8),
            )?;
            outputs.insert(k.clone(), v);
        }
        let secrets = all_secrets(ctx, plan)?;
        let outputs = scrub(&scrub(&Value::Object(outputs), &secrets), ctx.secrets);
        Ok(Output {
            outputs,
            http_summary: summaries,
        })
    }
    .await;
    if result.is_err()
        && exchange
            .mutation_accepted
            .load(std::sync::atomic::Ordering::Acquire)
    {
        return Err(Error::Ambiguous(
            "vendor accepted a write before action completion could be verified".into(),
        ));
    }
    result
}

fn all_secrets(ctx: &RunContext<'_>, plan: &Plan) -> Result<SecretSet, Error> {
    let derived = plan.auth.derived_secrets();
    if derived
        .iter()
        .any(|s| s.len() < crate::secrets::MIN_SECRET_LEN)
    {
        return Err(Error::Auth);
    }
    Ok(SecretSet::with_derived(
        ctx.credentials.values(),
        derived.iter().map(String::as_str),
    ))
}

async fn request(
    ctx: &RunContext<'_>,
    plan: &Plan,
    scope: &Scope,
    exchange: &Exchange<'_>,
    id: &str,
    r: &Request,
    expect: Option<&Expect>,
) -> Result<(Value, HttpSummary), Error> {
    let secrets = all_secrets(ctx, plan)?;
    let mut guarded = scope.clone();
    guarded.secret_guard = Some(template::SecretGuard::new(secrets.clone(), ctx.secrets.clone()));
    let scope = &guarded;
    let mut req = render(r, scope, ctx.idempotency_key)?;
    let material = format!(
        "{}{:?}{}",
        req.url,
        req.headers,
        String::from_utf8_lossy(&req.body)
    );
    if secrets.contains_decoded(material.as_bytes())
        || ctx.secrets.contains_decoded(material.as_bytes())
    {
        return Err(Error::Invalid(
            "request would expose a credential outside authentication".into(),
        ));
    }
    let auth_ctx = AuthContext {
        creds: ctx.credentials,
        fetch: exchange,
        scope,
        now: (ctx.engine.clock)(),
        feed_id: None,
    };
    for endpoint in plan.auth.token_endpoints() {
        let url = template::render_url(&endpoint, scope)
            .map_err(|_| Error::Invalid("invalid token URL".into()))?;
        if secrets.contains_decoded(url.as_str().as_bytes())
            || ctx.secrets.contains_decoded(url.as_str().as_bytes())
        {
            return Err(Error::Invalid("token URL would expose a credential".into()));
        }
    }
    plan.auth.apply(&mut req, &auth_ctx).await.map_err(|_| {
        if exchange
            .auth_rate_limited
            .load(std::sync::atomic::Ordering::Acquire)
        {
            Error::RateLimited
        } else {
            Error::Auth
        }
    })?;
    let mutation = req.method != http::Method::GET && req.method != http::Method::HEAD;
    let purpose = if mutation {
        RequestPurpose::VendorMutation
    } else {
        RequestPurpose::Read
    };
    let mut response = exchange.send(&req, purpose).await?;
    // A 401 proves authentication was refused. Session auth alone opts into
    // one re-login and resend, charged to the same deadline/request budgets.
    // Never retry a transport error, 403, or an accepted/ambiguous mutation.
    if response.status == 401
        && plan.auth.retry_unauthorized()
        && plan.auth.invalidate(&req).await
    {
        plan.auth.apply(&mut req, &auth_ctx).await.map_err(|_| {
            if exchange
                .auth_rate_limited
                .load(std::sync::atomic::Ordering::Acquire)
            {
                Error::RateLimited
            } else {
                Error::Auth
            }
        })?;
        response = exchange.send(&req, purpose).await?;
    }
    let secrets = all_secrets(ctx, plan)?;
    if mutation && (200..300).contains(&response.status) {
        exchange
            .mutation_accepted
            .store(true, std::sync::atomic::Ordering::Release);
    }
    if matches!(response.status, 401 | 403) {
        plan.auth.invalidate(&req).await;
        return Err(Error::Auth);
    }
    if response.status == 429 {
        return Err(Error::RateLimited);
    }
    let accepted = expect.map_or((200..300).contains(&response.status), |e| {
        e.status.contains(&response.status)
    });
    if !accepted {
        return Err(
            if (response.status >= 500 || (300..400).contains(&response.status))
                && req.method != http::Method::GET
                && req.method != http::Method::HEAD
            {
                Error::Ambiguous(format!("upstream HTTP {}", response.status))
            } else {
                Error::Failed(format!("upstream HTTP {}", response.status))
            },
        );
    }
    let body = match r.response_format {
        ResponseFormat::Json if response.body.is_empty() => Value::Null,
        ResponseFormat::Json => serde_json::from_slice(&response.body)
            .map_err(|_| Error::Failed("invalid JSON response".into()))?,
        ResponseFormat::Text => json!({"text":String::from_utf8_lossy(&response.body)}),
    };
    if let Some(e) = expect {
        if (e.non_empty && !present(path(&body, e.path.as_deref().unwrap_or_default())))
            || e.json_type.is_some_and(|kind| field_path(&body, e.path.as_deref().unwrap_or_default()).is_none_or(|value| !kind.accepts(value)))
            || e.fields.iter().any(|(p, v)| field_path(&body, p) != Some(v))
            || e.input_equals.iter().any(|(p, input)| {
                let expected = scope.input.get(input).and_then(Value::as_str);
                expected.is_none_or(str::is_empty)
                    || field_path(&body, p).and_then(Value::as_str) != expected
            })
            || e.equals
                .as_ref()
                .is_some_and(|v| path(&body, e.path.as_deref().unwrap_or_default()) != v)
            || e.contains
                .as_ref()
                .is_some_and(|s| !String::from_utf8_lossy(&response.body).contains(s))
            || e.items.is_some_and(|n| {
                path(&body, e.path.as_deref().unwrap_or_default())
                    .as_array()
                    .is_none_or(|a| a.len() != n)
            })
        {
            return Err(Error::Failed("response assertion failed".into()));
        }
    }
    let summary = summary(
        id,
        &req,
        Some(response.status),
        Vec::new(),
        &secrets,
        ctx.secrets,
    );
    Ok((scrub(&scrub(&body, &secrets), ctx.secrets), summary))
}

fn summary(
    id: &str,
    r: &OutboundRequest,
    status: Option<u16>,
    deferred: Vec<String>,
    secrets: &SecretSet,
    extra: &SecretSet,
) -> HttpSummary {
    let headers = r
        .headers
        .iter()
        .map(|(k, v)| {
            let value = if [
                "authorization",
                "proxy-authorization",
                "cookie",
                "x-api-key",
                "api-key",
                "x-pan-key",
            ]
            .contains(&k.to_ascii_lowercase().as_str())
            {
                "[REDACTED]".into()
            } else {
                v.clone()
            };
            (k.clone(), value)
        })
        .collect::<Vec<_>>();
    let value = json!({"step":id,"method":r.method.as_str(),"url":r.url.as_str(),"headers":headers,"body":String::from_utf8_lossy(&r.body),"status":status,"deferred":deferred});
    serde_json::from_value(scrub(&scrub(&value, secrets), extra)).unwrap_or_else(|_| HttpSummary {
        step: id.into(),
        method: r.method.to_string(),
        url: "[REDACTED]".into(),
        headers: vec![],
        body: "[REDACTED]".into(),
        status,
        deferred: vec![],
    })
}

fn dry_run(
    plan: &Plan,
    scope: &mut Scope,
    hosts: &HostPolicy,
    ctx: &RunContext<'_>,
) -> Result<Output, Error> {
    scope.defer_responses = true;
    let mut summaries = Vec::new();
    let mut summary_bytes = MAX_TOTAL_BYTES as usize;
    for endpoint in plan.auth.token_endpoints() {
        let url = template::render_url(&endpoint, scope)
            .map_err(|_| Error::Invalid("invalid token URL".into()))?;
        hosts
            .check(&url)
            .map_err(|_| Error::Invalid("token URL is outside egress policy".into()))?;
        let session = plan.auth_config.kind == "session_login";
        let json_login = session
            && plan
                .auth_config
                .params
                .get("encoding")
                .and_then(Value::as_str)
                != Some("form");
        let request = OutboundRequest {
            method: http::Method::POST,
            url,
            headers: vec![(
                "Content-Type".into(),
                if json_login {
                    "application/json"
                } else {
                    "application/x-www-form-urlencoded"
                }
                .into(),
            )],
            body: Bytes::from_static(if json_login {
                b"{\"authentication\":\"[REDACTED]\"}"
            } else if session {
                b"authentication=[REDACTED]"
            } else {
                b"grant_type=client_credentials&client_id=[REDACTED]&client_secret=[REDACTED]"
            }),
        };
        let item = summary(
            "authentication",
            &request,
            None,
            vec!["authentication_if_needed".into()],
            &all_secrets(ctx, plan)?,
            ctx.secrets,
        );
        spend(
            &mut summary_bytes,
            serde_json::to_vec(&item)
                .map_err(|_| Error::Invalid("cannot encode preview".into()))?
                .len(),
        )?;
        summaries.push(item);
    }
    let requests: Vec<_> = plan
        .steps
        .iter()
        .filter(|s| {
            !s.skip_if
                .as_ref()
                .is_some_and(|s| present(&scope.input[&s.input_present]))
        })
        .map(|s| (s.id.as_str(), &s.request))
        .chain(plan.poll.as_ref().map(|p| ("poll", &p.request)))
        .collect();
    for (id, r) in requests {
        let mut deferred = Vec::new();
        for text in r.strings() {
            for expr in template::references(&text).map_err(|e| Error::Invalid(e.to_string()))? {
                let rendered =
                    template::evaluate(&expr, scope).map_err(|e| Error::Invalid(e.to_string()))?;
                if !rendered
                    .as_str()
                    .is_some_and(|s| s.starts_with("{{") && s.ends_with("}}"))
                {
                    continue;
                }
                for reference in template::expression_references(&expr)
                    .map_err(|e| Error::Invalid(e.to_string()))?
                {
                    if reference.starts_with("steps.") || reference.starts_with("poll.") {
                        deferred.push(reference);
                    }
                }
            }
        }
        deferred.sort();
        deferred.dedup();
        let mut request = render(r, scope, ctx.idempotency_key)?;
        hosts
            .check(&request.url)
            .map_err(|_| Error::Invalid("dry-run request is outside egress policy".into()))?;
        match plan.auth_config.kind.as_str() {
            "none" => {}
            "api_key_query" => {
                let key = plan
                    .auth_config
                    .params
                    .get("param")
                    .and_then(Value::as_str)
                    .ok_or_else(|| Error::Invalid("missing auth query key".into()))?;
                request.url.query_pairs_mut().append_pair(key, "[REDACTED]");
            }
            "api_key_header" => {
                let header = plan
                    .auth_config
                    .params
                    .get("header")
                    .and_then(Value::as_str)
                    .ok_or_else(|| Error::Invalid("missing auth header".into()))?;
                request.headers.push((header.into(), "[REDACTED]".into()));
            }
            "composite_token" | "hmac" => {
                for name in ["header", "timestamp_header", "key_id_header"] {
                    if let Some(header) = plan.auth_config.params.get(name).and_then(Value::as_str)
                    {
                        request.headers.push((header.into(), "[REDACTED]".into()));
                    }
                }
            }
            "session_login" => {
                let response = &plan.auth_config.params["response"];
                let header = if response["type"] == "cookie" {
                    "Cookie"
                } else {
                    response["header"].as_str().unwrap_or("Authentication")
                };
                request.headers.push((header.into(), "[REDACTED]".into()));
            }
            "bearer" | "basic" | "okta_ssws" | "oauth2_client_credentials" => request
                .headers
                .push(("Authorization".into(), "[REDACTED]".into())),
            _ => request
                .headers
                .push(("Authentication".into(), "[REDACTED]".into())),
        }
        let secrets = all_secrets(ctx, plan)?;
        let item = summary(id, &request, None, deferred, &secrets, ctx.secrets);
        spend(
            &mut summary_bytes,
            serde_json::to_vec(&item)
                .map_err(|_| Error::Invalid("cannot encode preview".into()))?
                .len(),
        )?;
        summaries.push(item);
    }
    Ok(Output {
        outputs: json!({}),
        http_summary: summaries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct IdentityCapture {
        body: Value,
        calls: std::sync::Mutex<Vec<http::Method>>,
    }
    #[async_trait::async_trait]
    impl Transport for IdentityCapture {
        async fn send_once(&self, r: &OutboundRequest, _: &HostPolicy, _: BodyCaps) -> Result<InboundResponse, BrokerError> {
            self.calls.lock().unwrap().push(r.method.clone());
            if r.method == http::Method::POST {
                assert_eq!(r.url.path(), "/devices/selected/lock");
            }
            Ok(InboundResponse { status: 200, headers: Default::default(), body: Bytes::from(serde_json::to_vec(&self.body).unwrap()) })
        }
    }
    #[tokio::test]
    async fn identity_input_equals_refuses_before_mutation_and_never_coerces() {
        let allow: Vec<AllowRule> = serde_json::from_value(json!([{"host":"api.vendor.com"}])).unwrap();
        let steps: Vec<Step> = serde_json::from_value(json!([
            {"id":"identity","request":{"method":"GET","url":"https://api.vendor.com/devices/selected"},"expect":{"status":[200],"input_equals":{"id":"device_id"}}},
            {"id":"write","request":{"method":"POST","url":"https://api.vendor.com/devices/{{steps.identity.id}}/lock"},"expect":{"status":[200]}}
        ])).unwrap();
        for (input, body, accepted) in [
            (json!({"device_id":"selected"}), json!({"id":"selected"}), true),
            (json!({"device_id":"selected"}), json!({"id":"unrelated"}), false),
            (json!({"device_id":"selected"}), json!({}), false),
            (json!({"device_id":"selected"}), json!({"id":null}), false),
            (json!({"device_id":"selected"}), json!({"id":42}), false),
            (json!({"device_id":""}), json!({"id":""}), false),
            (json!({}), json!({}), false),
            (json!({"device_id":42}), json!({"id":42}), false),
        ] {
            let transport = Arc::new(IdentityCapture { body, calls: Default::default() });
            let mut engine = EngineConfig::try_new("/unused-no-code".into()).unwrap();
            engine.transport = Some(transport.clone());
            let plan = compile(&allow, &AuthConfig::default(), &steps, None, &BTreeMap::new(), 10).unwrap();
            let credentials = Credentials::new(Default::default());
            let secrets = SecretSet::new(std::iter::empty::<&str>());
            let context = RunContext { engine: &engine, credentials: &credentials, secrets: &secrets, deny: EgressDeny::default(), idempotency_key: None, budget: &AllowBudget };
            let result = run(&context, &plan, Scope { input, ..Default::default() }, Mode::Live).await;
            assert_eq!(result.is_ok(), accepted);
            assert_eq!(*transport.calls.lock().unwrap(), if accepted { vec![http::Method::GET,http::Method::POST] } else { vec![http::Method::GET] });
        }
    }
    #[test]
    fn identity_input_equals_rejects_namespaces_paths_and_unbounded_maps() {
        let allow: Vec<AllowRule> = serde_json::from_value(json!([{"host":"api.vendor.com"}])).unwrap();
        for bindings in [json!({"id":"credential.TOKEN"}), json!({"id":"input.device_id"}), json!({"id":"{{input.device_id}}"}), json!({"a..id":"device_id"}), json!({"id":""}), Value::Object((0..17).map(|i|(format!("id{i}"),json!("device_id"))).collect())] {
            let steps: Vec<Step> = serde_json::from_value(json!([{"id":"read","request":{"method":"GET","url":"https://api.vendor.com/devices"},"expect":{"status":[200],"input_equals":bindings}}])).unwrap();
            assert!(compile(&allow, &AuthConfig::default(), &steps, None, &BTreeMap::new(), 10).is_err());
        }
    }

    struct PurposeCapture(std::sync::Mutex<Vec<RequestPurpose>>);
    #[async_trait::async_trait]
    impl Transport for PurposeCapture {
        async fn send_once(&self, _: &OutboundRequest, _: &HostPolicy, _: BodyCaps) -> Result<InboundResponse, BrokerError> {
            panic!("the sequence must preserve semantic purpose");
        }
        async fn send_once_with_purpose(&self, _: &OutboundRequest, _: &HostPolicy, _: BodyCaps, purpose: RequestPurpose) -> Result<InboundResponse, BrokerError> {
            self.0.lock().unwrap().push(purpose);
            Ok(InboundResponse {
                status: 200,
                headers: Default::default(),
                body: Bytes::from(if purpose == RequestPurpose::Authentication {
                    br#"{"access_token":"public_fixture_access_token","expires_in":3600}"#.as_slice()
                } else { b"{}".as_slice() }),
            })
        }
    }

    #[tokio::test]
    async fn semantic_purpose_separates_authentication_from_vendor_mutations() {
        let transport = Arc::new(PurposeCapture(std::sync::Mutex::new(Vec::new())));
        let mut engine = EngineConfig::try_new("/unused-no-code".into()).unwrap();
        engine.transport = Some(transport.clone());
        // All three use exactly the same URL: purpose cannot be inferred from
        // the token endpoint or from POST alone.
        let allow: Vec<AllowRule> = serde_json::from_value(json!([{"host":"api.vendor.com"}])).unwrap();
        let auth: AuthConfig = serde_json::from_value(json!({"type":"oauth2_client_credentials","token_url":"https://api.vendor.com/v1","client_id_credential":"CLIENT_ID","client_secret_credential":"CLIENT_SECRET"})).unwrap();
        let steps: Vec<Step> = serde_json::from_value(json!([
            {"id":"resolve","request":{"method":"GET","url":"https://api.vendor.com/v1"},"expect":{"status":[200]}},
            {"id":"write","request":{"method":"POST","url":"https://api.vendor.com/v1"},"expect":{"status":[200]}}
        ])).unwrap();
        let plan = compile(&allow, &auth, &steps, None, &BTreeMap::new(), 10).unwrap();
        let credentials = Credentials::new(std::collections::HashMap::from([
            ("CLIENT_ID".into(), "public_fixture_client".into()),
            ("CLIENT_SECRET".into(), "public_fixture_secret".into()),
        ]));
        let secrets = SecretSet::new(std::iter::empty::<&str>());
        let context = RunContext { engine: &engine, credentials: &credentials, secrets: &secrets, deny: EgressDeny::default(), idempotency_key: None, budget: &AllowBudget };
        run(&context, &plan, Scope::default(), Mode::Live).await.unwrap();
        assert_eq!(*transport.0.lock().unwrap(), vec![RequestPurpose::Authentication, RequestPurpose::Read, RequestPurpose::VendorMutation]);
        // A pre-existing transport implementing only send_once retains its
        // behavior through the new default method.
        let legacy = AdmissionRefusal { accept_first: false, deferred: true, calls: 0.into() };
        let request = OutboundRequest { method: http::Method::GET, url: "https://api.vendor.com/v1".parse().unwrap(), headers: vec![], body: Bytes::new() };
        assert!(matches!(legacy.send_once_with_purpose(&request, &HostPolicy::compile(&allow, &Scope::default()).unwrap(), BodyCaps { max_response_bytes: 1024, max_decompressed_bytes: 1024 }, RequestPurpose::Read).await, Err(BrokerError::Deferred(_))));
        assert_eq!(legacy.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    struct AllowBudget;
    #[async_trait::async_trait]
    impl RequestBudget for AllowBudget {
        async fn reserve(&self) -> Result<bool, String> { Ok(true) }
    }
    struct AdmissionRefusal {
        accept_first: bool,
        deferred: bool,
        calls: std::sync::atomic::AtomicUsize,
    }
    #[async_trait::async_trait]
    impl Transport for AdmissionRefusal {
        async fn send_once(&self, _: &OutboundRequest, _: &HostPolicy, _: BodyCaps) -> Result<InboundResponse, BrokerError> {
            let call = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.accept_first && call == 0 {
                return Ok(InboundResponse { status: 200, headers: Default::default(), body: Bytes::from_static(b"{}") });
            }
            Err(if self.deferred { BrokerError::Deferred("admission busy") } else { BrokerError::NotSent("admission denied") })
        }
    }
    #[tokio::test]
    async fn presend_refusals_are_safe_but_cannot_erase_an_accepted_mutation() {
        for deferred in [false, true] {
            for accept_first in [false, true] {
                let mut engine = EngineConfig::try_new("/unused-no-code".into()).unwrap();
                engine.transport = Some(std::sync::Arc::new(AdmissionRefusal { accept_first, deferred, calls: 0.into() }));
                let allow: Vec<AllowRule> = serde_json::from_value(json!([{"host":"api.vendor.com"}])).unwrap();
                let steps: Vec<Step> = (0..if accept_first { 2 } else { 1 }).map(|i| serde_json::from_value(json!({"id":format!("write_{i}"),"request":{"method":"POST","url":"https://api.vendor.com/v1"},"expect":{"status":[200]}})).unwrap()).collect();
                let plan = compile(&allow, &AuthConfig::default(), &steps, None, &BTreeMap::new(), 10).unwrap();
                let credentials = Credentials::new(std::collections::HashMap::new());
                let secrets = SecretSet::new(std::iter::empty::<&str>());
                let context = RunContext { engine: &engine, credentials: &credentials, secrets: &secrets, deny: EgressDeny::default(), idempotency_key: None, budget: &AllowBudget };
                let result = run(&context, &plan, Scope::default(), Mode::Live).await;
                match (accept_first, deferred, result) {
                    (true, _, Err(Error::Ambiguous(_))) | (false, true, Err(Error::RateLimited)) | (false, false, Err(Error::Failed(_))) => {},
                    (_, _, other) => panic!("unexpected admission result: {other:?}"),
                }
            }
        }
    }

    #[test]
    fn aggregate_form_headers_and_json_are_bounded_before_submission() {
        let scope = Scope {
            steps: json!({"read":{"blob":"a".repeat(3*1024*1024)}}),
            ..Default::default()
        };
        for fields in [
            json!({"form":{"one":"{{steps.read.blob}}","two":"{{steps.read.blob}}"}}),
            json!({"headers":{"X-One":"{{steps.read.blob}}","X-Two":"{{steps.read.blob}}"}}),
            json!({"json":{"one":"{{steps.read.blob}}","two":"{{steps.read.blob}}"}}),
            json!({"query":{"large":"{{steps.read.blob}}"}}),
        ] {
            let mut value = json!({"method":"POST","url":"https://api.vendor.com/v1"});
            value
                .as_object_mut()
                .unwrap()
                .extend(fields.as_object().unwrap().clone());
            let request: Request = serde_json::from_value(value).unwrap();
            assert!(render(&request, &scope, None).is_err());
        }
    }

    #[test]
    fn idempotency_header_cannot_collide_with_static_headers() {
        let step:Step=serde_json::from_value(json!({"id":"submit","request":{"method":"POST","url":"https://api.vendor.com/v1","headers":{"Idempotency-Key":"constant"},"idempotency_header":"idempotency-key"},"expect":{"status":[200]}})).unwrap();
        let allow: Vec<AllowRule> =
            serde_json::from_value(json!([{"host":"api.vendor.com"}])).unwrap();
        assert!(
            compile(
                &allow,
                &AuthConfig::default(),
                &[step],
                None,
                &BTreeMap::new(),
                20
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn strict_replay_refuses_duplicate_queries_and_incorrect_bodies() {
        use crate::preview::{ExpectedRequest, Recorded};
        let allow: Vec<AllowRule> =
            serde_json::from_value(json!([{"host":"api.vendor.com"}])).unwrap();
        let policy = HostPolicy::compile(&allow, &Scope::default()).unwrap();
        for (expected, url, body) in [
            (
                json!({"method":"POST","url":"https://api.vendor.com/v1","query":{"id":"expected"}}),
                "https://api.vendor.com/v1?id=wrong&id=expected",
                Bytes::new(),
            ),
            (
                json!({"method":"POST","url":"https://api.vendor.com/v1","json":{"ids":["expected"]}}),
                "https://api.vendor.com/v1",
                Bytes::from_static(b"{\"ids\":[\"wrong\"]}"),
            ),
        ] {
            let expected: ExpectedRequest = serde_json::from_value(expected).unwrap();
            let response: Recorded =
                serde_json::from_value(json!({"host":"api.vendor.com","path":"/v1","body":{}}))
                    .unwrap();
            let replay = ReplayTransport::strict(vec![(expected, response)]);
            let request = OutboundRequest {
                method: http::Method::POST,
                url: url.parse().unwrap(),
                headers: vec![],
                body,
            };
            assert!(
                replay
                    .send_once(
                        &request,
                        &policy,
                        BodyCaps {
                            max_response_bytes: 1024,
                            max_decompressed_bytes: 1024
                        }
                    )
                    .await
                    .is_err()
            );
            assert!(replay.assert_complete().is_err());
        }
    }
}

#[cfg(test)]
mod json_text_tests {
    use super::*;
    #[test]
    fn exact_json_text_preserves_order_and_rejects_invalid_or_oversize_json() {
        let request: Request = serde_json::from_value(json!({"method":"POST", "url":"https://hooks.example.com/inbox", "json_text":"{{input.body}}"})).unwrap();
        let mut scope = Scope {
            input: json!({"body":"{\"z\":1,\"a\":2}"}),
            ..Default::default()
        };
        assert_eq!(
            render(&request, &scope, None).unwrap().body.as_ref(),
            br#"{"z":1,"a":2}"#
        );
        for value in [
            "invalid".to_string(),
            serde_json::to_string(&"x".repeat(template::MAX_RENDER_BYTES)).unwrap(),
        ] {
            scope.input = json!({"body":value});
            assert!(render(&request, &scope, None).is_err());
        }
        assert!(request.strings().contains(&"{{input.body}}".into()));
        let step: Step = serde_json::from_value(json!({"id":"send", "request":{"method":"POST","url":"https://hooks.example.com/inbox", "json":{},"json_text":"{}"},"expect":{"status":[200]}})).unwrap();
        let allow: Vec<AllowRule> = serde_json::from_value(json!([{"host":"hooks.example.com"}])).unwrap();
        let mut valid = step.clone();
        valid.request.json = None;
        assert!(compile(&allow, &AuthConfig::default(), &[valid], None, &BTreeMap::new(), 10).is_ok());
        assert!(compile(&allow, &AuthConfig::default(), &[step], None, &BTreeMap::new(), 10).is_err());
    }
}
