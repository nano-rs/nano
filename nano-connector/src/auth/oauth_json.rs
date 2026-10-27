//! Reuse OAuth client credentials while injecting a scoped secret JSON field.
//! The secret never appears in a template, flow input or retained HTTP summary.
use super::{AuthContext, AuthError, AuthPlugin, OAuth2Params, OutboundRequest};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Mutex;

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum JsonCredentialFormat {
    #[default]
    Opaque,
    SixDigitPin,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OAuth2JsonCredentialParams {
    pub oauth2: OAuth2Params,
    pub credential: String,
    /// Literal RFC 6901 object-member pointer, at most eight identifier segments.
    pub field_pointer: String,
    /// Every JSON mutation must have this string discriminator. Other values
    /// use OAuth only; exactly selector_value additionally injects the secret.
    pub selector_pointer: String,
    pub selector_value: String,
    #[serde(default)]
    pub format: JsonCredentialFormat,
}

pub(super) struct OAuth2JsonCredentialAuth {
    p: OAuth2JsonCredentialParams,
    oauth2: Box<dyn AuthPlugin>,
    // Only exact requests this instance decorated may be re-applied after 401.
    // Never retain plaintext request bodies or silently forget old fingerprints.
    injected: Mutex<Vec<Vec<u8>>>,
    limit: usize,
}
fn invalid() -> AuthError {
    AuthError::Params("scoped JSON credential requires a valid bounded request".into())
}
fn pointer(value: &str) -> bool {
    value.starts_with('/')
        && value.len() <= 256
        && (1..=8).contains(&value[1..].split('/').count())
        && value[1..].split('/').all(|s| {
            !s.is_empty()
                && (s.as_bytes()[0].is_ascii_alphabetic() || s.as_bytes()[0] == b'_')
                && s.len() <= 64
                && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
}
fn fingerprint(req: &OutboundRequest, body: &[u8]) -> Vec<u8> {
    use aws_lc_rs::digest::{Context, SHA256};
    let mut hash = Context::new(&SHA256);
    for item in [
        req.method.as_str().as_bytes(),
        req.url.as_str().as_bytes(),
        body,
    ] {
        hash.update(&(item.len() as u64).to_be_bytes());
        hash.update(item);
    }
    for (name, value) in &req.headers {
        if !name.eq_ignore_ascii_case("authorization") {
            for item in [name.as_bytes(), value.as_bytes()] {
                hash.update(&(item.len() as u64).to_be_bytes());
                hash.update(item);
            }
        }
    }
    hash.finish().as_ref().to_vec()
}
impl OAuth2JsonCredentialAuth {
    pub(super) fn new(p: OAuth2JsonCredentialParams) -> Result<Self, AuthError> {
        if p.credential.is_empty()
            || p.credential.len() > 64
            || !p
                .credential
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            || !pointer(&p.field_pointer)
            || !pointer(&p.selector_pointer)
            || p.field_pointer == p.selector_pointer
            || p.selector_value.is_empty()
            || p.selector_value.len() > 128
            || p.selector_value.chars().any(char::is_control)
        {
            return Err(invalid());
        }
        let value = serde_json::to_value(&p.oauth2).map_err(|_| invalid())?;
        let oauth2 = super::build(
            "oauth2_client_credentials",
            value.as_object().ok_or_else(invalid)?,
        )?;
        if oauth2.credential_fields().contains(&p.credential) {
            return Err(invalid());
        }
        Ok(Self {
            p,
            oauth2,
            injected: Default::default(),
            limit: 128,
        })
    }
}
#[async_trait::async_trait]
impl AuthPlugin for OAuth2JsonCredentialAuth {
    fn credential_fields(&self) -> Vec<String> {
        let mut fields = self.oauth2.credential_fields();
        fields.push(self.p.credential.clone());
        fields
    }
    fn token_endpoints(&self) -> Vec<String> {
        self.oauth2.token_endpoints()
    }
    fn derived_secrets(&self) -> Vec<String> {
        self.oauth2.derived_secrets()
    }
    fn retry_unauthorized(&self) -> bool {
        self.oauth2.retry_unauthorized()
    }
    async fn invalidate(&self, req: &OutboundRequest) -> bool {
        self.oauth2.invalidate(req).await
    }
    fn set_request_limit(&mut self, max: u32) {
        self.oauth2.set_request_limit(max);
        self.limit = (max as usize).min(4096);
    }
    async fn apply(
        &self,
        req: &mut OutboundRequest,
        cx: &AuthContext<'_>,
    ) -> Result<(), AuthError> {
        if !matches!(
            req.method,
            http::Method::POST | http::Method::PUT | http::Method::PATCH
        ) {
            return self.oauth2.apply(req, cx).await;
        }
        if req.body.len() > 1024 * 1024
            || req
                .headers
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                .count()
                != 1
            || !req
                .headers
                .iter()
                .any(|(k, v)| k.eq_ignore_ascii_case("content-type") && v == "application/json")
        {
            return Err(invalid());
        }
        let mut body: Value = serde_json::from_slice(&req.body).map_err(|_| invalid())?;
        if !body.is_object() {
            return Err(invalid());
        }
        let selected = body
            .pointer(&self.p.selector_pointer)
            .and_then(Value::as_str)
            .ok_or_else(invalid)?;
        if selected != self.p.selector_value {
            return self.oauth2.apply(req, cx).await;
        }
        let secret = cx.creds.get(&self.p.credential)?;
        if !(crate::secrets::MIN_SECRET_LEN..=16384).contains(&secret.len())
            || matches!(self.p.format, JsonCredentialFormat::SixDigitPin)
                && (secret.len() != 6 || !secret.bytes().all(|b| b.is_ascii_digit()))
        {
            return Err(invalid());
        }
        for name in self.oauth2.credential_fields() {
            if cx.creds.get(&name)? == secret {
                return Err(invalid());
            }
        }
        let already_injected = body.pointer(&self.p.field_pointer).is_some();
        if already_injected {
            let known = self
                .injected
                .lock()
                .map_err(|_| invalid())?
                .contains(&fingerprint(req, &req.body));
            if !known || body.pointer(&self.p.field_pointer).and_then(Value::as_str) != Some(secret)
            {
                return Err(invalid());
            }
        } else {
            let (parent, field) = self.p.field_pointer.rsplit_once('/').ok_or_else(invalid)?;
            let object = if parent.is_empty() {
                body.as_object_mut()
            } else {
                body.pointer_mut(parent).and_then(Value::as_object_mut)
            }
            .ok_or_else(invalid)?;
            object.insert(field.into(), Value::String(secret.into()));
        }
        let bytes = serde_json::to_vec(&body).map_err(|_| invalid())?;
        if bytes.len() > 1024 * 1024 {
            return Err(invalid());
        }
        let hash = fingerprint(req, &bytes);
        // Reserve retention before fetching any token. Bound memory across the
        // connection, including concurrent actions and explicit auth retries.
        if !already_injected {
            let mut records = self.injected.lock().map_err(|_| invalid())?;
            if !records.contains(&hash) {
                if records.len() >= self.limit {
                    return Err(invalid());
                }
                records.push(hash);
            }
        }
        self.oauth2.apply(req, cx).await?;
        req.body = bytes.into();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        auth::{Credentials, TokenFetch},
        template::Scope,
    };
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Fetch(AtomicUsize);
    #[async_trait::async_trait]
    impl TokenFetch for Fetch {
        async fn post_form(
            &self,
            url: &str,
            form: &[(String, String)],
        ) -> Result<(u16, Vec<u8>), String> {
            assert_eq!(url, "https://api.example.com/token");
            assert!(form.contains(&("client_id".into(), "synthetic-client-id".into())));
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok((
                200,
                br#"{"access_token":"synthetic-access-token","expires_in":3600}"#.to_vec(),
            ))
        }
    }
    fn params() -> Value {
        json!({"oauth2":{"token_url":"https://api.example.com/token","client_id_credential":"ID","client_secret_credential":"SECRET"},"credential":"PIN","field_pointer":"/command/pin","selector_pointer":"/command/type","selector_value":"LOCK","format":"six_digit_pin"})
    }
    fn plugin() -> Box<dyn AuthPlugin> {
        super::super::build("oauth2_json_credential", params().as_object().unwrap()).unwrap()
    }
    fn creds(pin: &str) -> Credentials {
        Credentials::new(
            [
                ("ID".into(), "synthetic-client-id".into()),
                ("SECRET".into(), "synthetic-client-secret".into()),
                ("PIN".into(), pin.into()),
            ]
            .into(),
        )
    }
    fn request(body: Value) -> OutboundRequest {
        OutboundRequest {
            method: http::Method::POST,
            url: url::Url::parse("https://api.example.com/commands").unwrap(),
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: serde_json::to_vec(&body).unwrap().into(),
        }
    }
    #[test]
    fn bounded_literal_scope_and_non_aliasing_are_required() {
        for (key, value) in [
            ("field_pointer", json!("/command/~1pin")),
            ("field_pointer", json!("/command/0/pin")),
            ("selector_pointer", json!("/command/0/type")),
            ("field_pointer", json!("")),
            ("selector_pointer", json!("/command/pin")),
            ("credential", json!("ID")),
            ("selector_value", json!("\n")),
            ("unknown", json!(true)),
        ] {
            let mut p = params();
            p[key] = value;
            assert!(super::super::build("oauth2_json_credential", p.as_object().unwrap()).is_err());
        }
    }
    #[tokio::test]
    async fn scoped_injection_caches_existing_oauth_and_only_allows_exact_reapplication() {
        let p = plugin();
        let fetch = Fetch(AtomicUsize::new(0));
        let scope = Scope::default();
        let creds = creds("824671");
        let cx = AuthContext {
            creds: &creds,
            fetch: &fetch,
            scope: &scope,
            now: chrono::Utc::now(),
            feed_id: None,
        };
        let mut req = request(json!({"command":{"type":"LOCK"}}));
        p.apply(&mut req, &cx).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&req.body).unwrap()["command"]["pin"],
            "824671"
        );
        p.apply(&mut req, &cx).await.unwrap();
        assert_eq!(fetch.0.load(Ordering::SeqCst), 1);
        let mut changed = req.clone();
        changed.url.set_path("/other");
        assert!(p.apply(&mut changed, &cx).await.is_err());
        let fresh = plugin();
        assert!(fresh.apply(&mut req, &cx).await.is_err());
        let mut other = request(json!({"command":{"type":"RESTART"}}));
        p.apply(&mut other, &cx).await.unwrap();
        assert!(
            serde_json::from_slice::<Value>(&other.body).unwrap()["command"]
                .get("pin")
                .is_none()
        );
        assert_eq!(fetch.0.load(Ordering::SeqCst), 1);
    }
    #[tokio::test]
    async fn invalid_secret_override_shape_and_memory_bound_fail_before_token_io() {
        let fetch = Fetch(AtomicUsize::new(0));
        let scope = Scope::default();
        for pin in ["12345", "1234567", "abcdef", "synthetic-client-id"] {
            let c = creds(pin);
            let cx = AuthContext {
                creds: &c,
                fetch: &fetch,
                scope: &scope,
                now: chrono::Utc::now(),
                feed_id: None,
            };
            assert!(
                plugin()
                    .apply(&mut request(json!({"command":{"type":"LOCK"}})), &cx)
                    .await
                    .is_err()
            );
        }
        let c = creds("824671");
        let cx = AuthContext {
            creds: &c,
            fetch: &fetch,
            scope: &scope,
            now: chrono::Utc::now(),
            feed_id: None,
        };
        for body in [
            json!([]),
            json!({}),
            json!({"command":{"type":"LOCK","pin":"824671"}}),
        ] {
            assert!(plugin().apply(&mut request(body), &cx).await.is_err());
        }
        let mut p = plugin();
        p.set_request_limit(0);
        assert!(
            p.apply(&mut request(json!({"command":{"type":"LOCK"}})), &cx)
                .await
                .is_err()
        );
        assert_eq!(fetch.0.load(Ordering::SeqCst), 0);
    }
}
