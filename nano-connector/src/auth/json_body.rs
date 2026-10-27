//! Native credential injection; secrets never enter spec templates or config.
use super::{AuthContext, AuthError, AuthPlugin, OutboundRequest};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JsonBodyCredentialParams {
    pub credential: String,
    pub field: String,
}

pub(super) struct JsonBodyCredentialAuth(JsonBodyCredentialParams);
impl JsonBodyCredentialAuth {
    pub(super) fn new(p: JsonBodyCredentialParams) -> Result<Self, AuthError> {
        for value in [&p.credential, &p.field] {
            if value.is_empty()
                || value.len() > 64
                || !value
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'_')
            {
                return Err(AuthError::Params("invalid JSON credential field".into()));
            }
        }
        Ok(Self(p))
    }
}

#[async_trait::async_trait]
impl AuthPlugin for JsonBodyCredentialAuth {
    fn credential_fields(&self) -> Vec<String> {
        vec![self.0.credential.clone()]
    }

    async fn apply(
        &self,
        req: &mut OutboundRequest,
        cx: &AuthContext<'_>,
    ) -> Result<(), AuthError> {
        let invalid =
            || AuthError::Params("JSON credential requires a bounded JSON object mutation".into());
        if !matches!(
            req.method,
            http::Method::POST | http::Method::PUT | http::Method::PATCH
        ) || req.body.len() > 1024 * 1024
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
        let object = body.as_object_mut().ok_or_else(invalid)?;
        // Refuse an input/template attempting to choose the authentication key.
        if object.contains_key(&self.0.field) {
            return Err(invalid());
        }
        let credential = cx.creds.get(&self.0.credential)?.to_string();
        if credential.is_empty() || credential.len() > 16 * 1024 {
            return Err(invalid());
        }
        object.insert(self.0.field.clone(), Value::String(credential));
        let bytes = serde_json::to_vec(&body).map_err(|_| invalid())?;
        if bytes.len() > 1024 * 1024 {
            return Err(invalid());
        }
        req.body = bytes.into();
        Ok(())
    }
}
