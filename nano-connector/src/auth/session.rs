//! Generic credential POST login, connection/run-local caching and refresh.
use super::*;
use crate::broker::InboundResponse;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionLoginParams {
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    _t: Option<String>,
    /// HTTPS login endpoint; only config templates, always policy checked.
    pub login_url: String,
    /// Login field name -> credential field name. Values never live in a spec.
    pub credential_fields: BTreeMap<String, String>,
    /// Optional non-secret login fields; only config templates.
    #[serde(default)]
    pub fields: BTreeMap<String, String>,
    #[serde(default)]
    pub encoding: LoginEncoding,
    pub response: SessionResponse,
    #[serde(default = "session_ttl")]
    pub expires_in_secs: u64,
}
fn session_ttl() -> u64 {
    3600
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LoginEncoding {
    #[default]
    Json,
    Form,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum SessionResponse {
    JsonToken {
        pointer: String,
        header: String,
        #[serde(default)]
        prefix: String,
    },
    /// Select exactly one Set-Cookie pair. No browser cookie jar: it is sent
    /// only to the login origin and the explicitly configured path prefix.
    Cookie { name: String, path_prefix: String },
}

pub(super) struct SessionLoginAuth {
    p: SessionLoginParams,
    cache: TokenCache,
}
impl SessionLoginAuth {
    pub(super) fn new(p: SessionLoginParams) -> Result<Self, AuthError> {
        config_only("login_url", &p.login_url)?;
        if p.login_url.len() > 8192
            || p.credential_fields.is_empty()
            || p.credential_fields.len() > 16
            || p.fields.len() > 16
            || !(1..=86400).contains(&p.expires_in_secs)
            || p.credential_fields
                .iter()
                .any(|(k, v)| !field_name(k) || !field_name(v) || p.fields.contains_key(k))
            || p.fields.keys().any(|k| !field_name(k))
        {
            return Err(invalid());
        }
        for v in p.fields.values() {
            if v.len() > 4096 {
                return Err(invalid());
            }
            config_only("login field", v)?;
        }
        match &p.response {
            SessionResponse::JsonToken {
                pointer,
                header,
                prefix,
            } => {
                check_header_name(header)?;
                if !pointer.starts_with('/') || pointer.len() > 256 || !safe_header(prefix) {
                    return Err(invalid());
                }
            }
            SessionResponse::Cookie { name, path_prefix } => {
                if !field_name(name)
                    || !path_prefix.starts_with('/')
                    || path_prefix.len() > 512
                    || path_prefix.contains(['?', '#', '\\'])
                    || path_prefix.chars().any(char::is_control)
                {
                    return Err(invalid());
                }
            }
        }
        Ok(Self {
            p,
            cache: TokenCache::default(),
        })
    }
}
fn invalid() -> AuthError {
    AuthError::Params("invalid session login parameters".into())
}
fn field_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}
fn safe_header(s: &str) -> bool {
    s.len() <= 4096 && !s.chars().any(char::is_control) && http::HeaderValue::from_str(s).is_ok()
}
fn failed() -> AuthError {
    AuthError::Token("session login refused".into())
}

#[async_trait::async_trait]
impl AuthPlugin for SessionLoginAuth {
    fn credential_fields(&self) -> Vec<String> {
        self.p.credential_fields.values().cloned().collect()
    }
    fn token_endpoints(&self) -> Vec<String> {
        vec![self.p.login_url.clone()]
    }
    async fn apply(
        &self,
        req: &mut OutboundRequest,
        cx: &AuthContext<'_>,
    ) -> Result<(), AuthError> {
        let url = template::render_url(&self.p.login_url, cx.scope).map_err(|_| invalid())?;
        if req.url.origin() != url.origin() {
            return Err(failed());
        }
        if let SessionResponse::Cookie { path_prefix, .. } = &self.p.response {
            let prefix = path_prefix.trim_end_matches('/');
            if !(req.url.path() == prefix || req.url.path().starts_with(&format!("{prefix}/"))) {
                return Err(failed());
            }
        }
        let token = self
            .cache
            .get_or_fetch(|| async {
                // Connection-scoped contexts may outlive a single run. Bound the
                // retained redaction history and require a fresh context at cap.
                if self.cache.issued().len() >= 1024 {
                    return Err(failed());
                }
                let mut fields = BTreeMap::new();
                for (field, credential) in &self.p.credential_fields {
                    fields.insert(field.clone(), cx.creds.get(credential)?.to_string());
                }
                for (field, value) in &self.p.fields {
                    fields.insert(
                        field.clone(),
                        template::render_str(value, cx.scope).map_err(|_| invalid())?,
                    );
                }
                let (content_type, body) = match self.p.encoding {
                    LoginEncoding::Json => (
                        "application/json",
                        serde_json::to_vec(&fields).map_err(|_| invalid())?,
                    ),
                    LoginEncoding::Form => {
                        let mut encoded = url::form_urlencoded::Serializer::new(String::new());
                        encoded.extend_pairs(fields.iter());
                        (
                            "application/x-www-form-urlencoded",
                            encoded.finish().into_bytes(),
                        )
                    }
                };
                let response: InboundResponse = cx
                    .fetch
                    .session_login(&OutboundRequest {
                        method: http::Method::POST,
                        url,
                        headers: vec![
                            ("Content-Type".into(), content_type.into()),
                            ("Accept".into(), "application/json".into()),
                        ],
                        body: body.into(),
                    })
                    .await
                    .map_err(|_| failed())?;
                // Never follow redirects or echo a login body/header in an error.
                if response.status == 429 {
                    return Err(AuthError::RateLimited);
                }
                if !(200..300).contains(&response.status) {
                    return Err(failed());
                }
                let value = match &self.p.response {
                    SessionResponse::JsonToken { pointer, .. } => {
                        let json: Value =
                            serde_json::from_slice(&response.body).map_err(|_| failed())?;
                        json.pointer(pointer)
                            .and_then(Value::as_str)
                            .ok_or_else(failed)?
                            .to_string()
                    }
                    SessionResponse::Cookie { name, .. } => {
                        let values: Vec<_> = response
                            .headers
                            .get_all(http::header::SET_COOKIE)
                            .iter()
                            .map(|v| v.to_str().map_err(|_| failed()))
                            .collect::<Result<_, _>>()?;
                        let pairs: Vec<_> = values
                            .iter()
                            .filter_map(|v| v.split(';').next()?.trim().split_once('='))
                            .filter(|(n, _)| *n == name)
                            .collect();
                        if pairs.len() != 1 {
                            return Err(failed());
                        }
                        let v = pairs[0].1;
                        if !v
                            .bytes()
                            .all(|b| b.is_ascii_graphic() && !b"\";,\\".contains(&b))
                        {
                            return Err(failed());
                        }
                        v.to_string()
                    }
                };
                if value.len() < crate::secrets::MIN_SECRET_LEN || !safe_header(&value) {
                    return Err(failed());
                }
                Ok((value, self.p.expires_in_secs))
            })
            .await?;
        match &self.p.response {
            SessionResponse::JsonToken { header, prefix, .. } => {
                set_header(req, header, format!("{prefix}{token}"))
            }
            SessionResponse::Cookie { name, .. } => {
                set_header(req, "Cookie", format!("{name}={token}"))
            }
        }
        Ok(())
    }
    async fn invalidate(&self, rejected: &OutboundRequest) -> bool {
        match &self.p.response {
            SessionResponse::JsonToken { header, prefix, .. } => {
                self.cache.invalidate(rejected, header, prefix).await
            }
            SessionResponse::Cookie { name, .. } => {
                self.cache
                    .invalidate(rejected, "Cookie", &format!("{name}="))
                    .await
            }
        }
    }
    fn retry_unauthorized(&self) -> bool {
        true
    }
    fn derived_secrets(&self) -> Vec<String> {
        self.cache.issued()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompositeTokenParams {
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    _t: Option<String>,
    pub header: String,
    pub first_credential: String,
    pub second_credential: String,
    pub separator: String,
    #[serde(default)]
    pub prefix: String,
}
pub(super) struct CompositeTokenAuth {
    p: CompositeTokenParams,
    value: std::sync::Mutex<Option<String>>,
}
impl CompositeTokenAuth {
    pub(super) fn new(p: CompositeTokenParams) -> Result<Self, AuthError> {
        check_header_name(&p.header)?;
        if !field_name(&p.first_credential)
            || !field_name(&p.second_credential)
            || p.separator.len() > 16
            || p.prefix.len() > 64
            || !safe_header(&p.separator)
            || !safe_header(&p.prefix)
        {
            return Err(AuthError::Params(
                "invalid composite token parameters".into(),
            ));
        }
        Ok(Self {
            p,
            value: Default::default(),
        })
    }
}
#[async_trait::async_trait]
impl AuthPlugin for CompositeTokenAuth {
    fn credential_fields(&self) -> Vec<String> {
        vec![
            self.p.first_credential.clone(),
            self.p.second_credential.clone(),
        ]
    }
    async fn apply(
        &self,
        req: &mut OutboundRequest,
        cx: &AuthContext<'_>,
    ) -> Result<(), AuthError> {
        let value = format!(
            "{}{}{}{}",
            self.p.prefix,
            cx.creds.get(&self.p.first_credential)?,
            self.p.separator,
            cx.creds.get(&self.p.second_credential)?
        );
        if !safe_header(&value) || value.len() < crate::secrets::MIN_SECRET_LEN {
            return Err(AuthError::Signing("invalid composite token value".into()));
        }
        *self.value.lock().expect("composite token") = Some(value.clone());
        set_header(req, &self.p.header, value);
        Ok(())
    }
    fn derived_secrets(&self) -> Vec<String> {
        self.value
            .lock()
            .expect("composite token")
            .iter()
            .cloned()
            .collect()
    }
}
