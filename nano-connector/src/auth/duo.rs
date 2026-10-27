//! Duo v5 signing shared by its Admin, Auth and Device APIs.
//! Protocol: https://duo.com/docs/adminapi#authentication (SHA-512/JSON).
use super::{AuthContext, AuthError, AuthPlugin, OutboundRequest, aws_encode, set_header};
use aws_lc_rs::{digest, hmac};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Mutex};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DuoHmacParams {
    pub integration_key_credential: String,
    pub secret_key_credential: String,
}

pub(super) struct DuoHmacAuth {
    params: DuoHmacParams,
    signatures: Mutex<Vec<[String; 3]>>,
    max_requests: usize,
}
impl DuoHmacAuth {
    pub(super) fn new(params: DuoHmacParams) -> Result<Self, AuthError> {
        for name in [
            &params.integration_key_credential,
            &params.secret_key_credential,
        ] {
            if name.is_empty()
                || name.len() > 64
                || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                return Err(AuthError::Params("invalid Duo credential field".into()));
            }
        }
        Ok(Self {
            params,
            signatures: Default::default(),
            max_requests: crate::spec::Limits::default().max_requests as usize,
        })
    }
}
fn invalid() -> AuthError {
    AuthError::Signing("invalid Duo v5 request".into())
}
fn sha512(bytes: &[u8]) -> String {
    hex::encode(digest::digest(&digest::SHA512, bytes).as_ref())
}
fn query(url: &url::Url) -> Result<String, AuthError> {
    let raw = url.query().unwrap_or_default().as_bytes();
    if raw.len() > 16 * 1024 {
        return Err(invalid());
    }
    // Url's forgiving query decoder must not turn malformed UTF-8/escapes
    // into a different signed parameter. Duplicate keys have no Duo meaning.
    let mut decoded = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        match raw[i] {
            b'%' => {
                let pair = raw.get(i + 1..i + 3).ok_or_else(invalid)?;
                let digit = |b: u8| {
                    (b as char)
                        .to_digit(16)
                        .map(|n| n as u8)
                        .ok_or_else(invalid)
                };
                decoded.push(digit(pair[0])? * 16 + digit(pair[1])?);
                i += 3;
            }
            b => {
                decoded.push(b);
                i += 1;
            }
        }
    }
    std::str::from_utf8(&decoded).map_err(|_| invalid())?;
    let mut parameters = BTreeMap::new();
    for (key, value) in url.query_pairs() {
        if key.is_empty()
            || parameters
                .insert(key.into_owned(), value.into_owned())
                .is_some()
        {
            return Err(invalid());
        }
    }
    Ok(parameters
        .iter()
        .map(|(k, v)| format!("{}={}", aws_encode(k), aws_encode(v)))
        .collect::<Vec<_>>()
        .join("&"))
}
fn headers(request: &OutboundRequest) -> Result<String, AuthError> {
    let mut selected = BTreeMap::new();
    for (name, value) in &request.headers {
        let name = name.to_ascii_lowercase();
        if name.starts_with("x-duo-") {
            if value.chars().any(|c| c.is_control())
                || selected.insert(name, value.trim()).is_some()
            {
                return Err(invalid());
            }
        }
    }
    let parts = selected
        .iter()
        .flat_map(|(k, v)| [k.as_str(), *v])
        .collect::<Vec<_>>();
    Ok(sha512(parts.join("\0").as_bytes()))
}
#[async_trait::async_trait]
impl AuthPlugin for DuoHmacAuth {
    fn credential_fields(&self) -> Vec<String> {
        vec![
            self.params.integration_key_credential.clone(),
            self.params.secret_key_credential.clone(),
        ]
    }
    fn set_request_limit(&mut self, limit: u32) {
        self.max_requests = limit as usize;
    }
    fn derived_secrets(&self) -> Vec<String> {
        self.signatures
            .lock()
            .expect("Duo signatures")
            .iter()
            .flatten()
            .cloned()
            .collect()
    }
    async fn apply(
        &self,
        request: &mut OutboundRequest,
        context: &AuthContext<'_>,
    ) -> Result<(), AuthError> {
        if request.body.len() > 1024 * 1024 {
            return Err(invalid());
        }
        match request.method {
            http::Method::GET | http::Method::DELETE if request.body.is_empty() => {}
            http::Method::POST | http::Method::PUT | http::Method::PATCH => {
                let types = request
                    .headers
                    .iter()
                    .filter(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                    .collect::<Vec<_>>();
                if types.len() != 1
                    || types[0].1 != "application/json"
                    || !serde_json::from_slice::<serde_json::Value>(&request.body)
                        .is_ok_and(|v| v.is_object())
                {
                    return Err(invalid());
                }
            }
            _ => return Err(invalid()),
        }
        let integration = context.creds.get(&self.params.integration_key_credential)?;
        let secret = context.creds.get(&self.params.secret_key_credential)?;
        if integration.len() > 256
            || !integration.bytes().all(|b| b.is_ascii_alphanumeric())
            || secret.len() > 4096
        {
            return Err(invalid());
        }
        let date = context.now.to_rfc2822();
        let canonical = [
            date.as_str(),
            request.method.as_str(),
            request.url.host_str().ok_or_else(invalid)?,
            request.url.path(),
            &query(&request.url)?,
            &sha512(&request.body),
            &headers(request)?,
        ]
        .join("\n");
        let signature = hex::encode(
            hmac::sign(
                &hmac::Key::new(hmac::HMAC_SHA512, secret.as_bytes()),
                canonical.as_bytes(),
            )
            .as_ref(),
        );
        let encoded = STANDARD.encode(format!("{integration}:{signature}"));
        let authorization = format!("Basic {encoded}");
        let mut signatures = self.signatures.lock().expect("Duo signatures");
        // Retain every issued signature through the run's final response. Never
        // evict an earlier secret to make room for an unbounded signing loop.
        if signatures.len() >= self.max_requests {
            return Err(AuthError::Signing("Duo request cap reached".into()));
        }
        signatures.push([signature, encoded, authorization.clone()]);
        set_header(request, "Date", date);
        set_header(request, "Authorization", authorization);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn bounded_signatures_keep_early_secrets_and_refuse_an_extra_request() {
        let mut plugin = DuoHmacAuth::new(DuoHmacParams {
            integration_key_credential: "IKEY".into(),
            secret_key_credential: "SKEY".into(),
        })
        .unwrap();
        plugin.set_request_limit(1);
        struct NoToken;
        #[async_trait::async_trait]
        impl super::super::TokenFetch for NoToken {
            async fn post_form(
                &self,
                _: &str,
                _: &[(String, String)],
            ) -> Result<(u16, Vec<u8>), String> {
                panic!("Duo never requests a token")
            }
        }
        let credentials = super::super::Credentials::new(std::collections::HashMap::from([
            ("IKEY".into(), "DIABCDEFGHIJKLMNOPQR".into()),
            ("SKEY".into(), "synthetic-duo-key".into()),
        ]));
        let scope = crate::template::Scope::default();
        let context = AuthContext {
            creds: &credentials,
            fetch: &NoToken,
            scope: &scope,
            now: chrono::Utc::now(),
            feed_id: None,
        };
        let mut request = OutboundRequest {
            method: http::Method::GET,
            url: "https://api-example.duosecurity.com/admin/v1/users"
                .parse()
                .unwrap(),
            headers: vec![],
            body: Default::default(),
        };
        plugin.apply(&mut request, &context).await.unwrap();
        let first = plugin.derived_secrets();
        assert_eq!(first.len(), 3);
        assert!(plugin.apply(&mut request, &context).await.is_err());
        assert_eq!(first, plugin.derived_secrets());
    }
}
