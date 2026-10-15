//! `{{namespace.path}}` templates. No expressions, no filters: logic belongs in
//! VRL. There is no `credentials` namespace, so a template can never place a
//! secret in a URL, query or body.

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::Value;

/// Values a template may read.
#[derive(Debug, Clone, Default)]
pub struct Scope {
    pub config: Value,
    pub state: Value,
    pub item: Value,
    pub input: Value,
    pub window: Value,
    pub now: String,
    /// NAN-3697: the stream's first cursor (activation − overlap), RFC 3339.
    /// Read as `{{initial_cursor}}`; `{{backfill_from}}` is a deprecated
    /// alias with the same value (there is no operator backfill).
    pub initial_cursor: Option<String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TemplateError {
    #[error("unterminated template in {0:?}")]
    Unterminated(String),
    #[error("templates cannot read `{0}`; secrets are applied by the engine's auth, never by templates")]
    Forbidden(String),
    #[error("unknown template namespace `{0}` (use config, state, item, input, window, now, initial_cursor)")]
    Unknown(String),
    #[error("a URL host may only be a single {{{{config.X}}}} reference")]
    Host,
    #[error("URL template is invalid: {0}")]
    Url(String),
}

const NAMESPACES: &[&str] = &["config", "state", "item", "input", "window", "now", "initial_cursor", "backfill_from"];
const FORBIDDEN: &[&str] = &["credentials", "credential", "secrets", "secret", "auth", "env"];

/// Path segment: encode everything that could change the URL's structure.
const SEGMENT: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'_').remove(b'.').remove(b'~');

/// Every `{{…}}` reference in `t`, validated against the namespaces.
pub fn references(t: &str) -> Result<Vec<String>, TemplateError> {
    let mut out = Vec::new();
    let mut rest = t;
    while let Some(start) = rest.find("{{") {
        let after = &rest[start + 2..];
        let end = after
            .find("}}")
            .ok_or_else(|| TemplateError::Unterminated(t.to_string()))?;
        let path = after[..end].trim().to_string();
        let ns = path.split('.').next().unwrap_or_default();
        if FORBIDDEN.contains(&ns.to_ascii_lowercase().as_str()) {
            return Err(TemplateError::Forbidden(path));
        }
        if !NAMESPACES.contains(&ns) {
            return Err(TemplateError::Unknown(ns.to_string()));
        }
        out.push(path);
        rest = &after[end + 2..];
    }
    Ok(out)
}

fn lookup(path: &str, scope: &Scope) -> Value {
    let mut parts = path.split('.');
    let root = match parts.next().unwrap_or_default() {
        "config" => &scope.config,
        "state" => &scope.state,
        "item" => &scope.item,
        "input" => &scope.input,
        "window" => &scope.window,
        "now" => return Value::String(scope.now.clone()),
        "initial_cursor" | "backfill_from" => {
            return scope
                .initial_cursor
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null);
        }
        _ => return Value::Null,
    };
    let mut cur = root;
    for p in parts {
        cur = match cur {
            Value::Object(m) => m.get(p).unwrap_or(&Value::Null),
            Value::Array(a) => p
                .parse::<usize>()
                .ok()
                .and_then(|i| a.get(i))
                .unwrap_or(&Value::Null),
            _ => &Value::Null,
        };
    }
    cur.clone()
}

/// Scalar rendering: strings raw, numbers/bools as JSON, null as "".
pub fn value_to_string(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn render_with(t: &str, scope: &Scope, enc: impl Fn(String) -> String) -> Result<String, TemplateError> {
    references(t)?;
    let mut out = String::new();
    let mut rest = t;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after.find("}}").ok_or_else(|| TemplateError::Unterminated(t.into()))?;
        out.push_str(&enc(value_to_string(&lookup(after[..end].trim(), scope))));
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Render a plain string template.
pub fn render_str(t: &str, scope: &Scope) -> Result<String, TemplateError> {
    render_with(t, scope, |s| s)
}

/// Render a JSON template: string leaves are templates. A leaf that is exactly
/// one reference keeps the referenced value's JSON type.
pub fn render_json(t: &Value, scope: &Scope) -> Result<Value, TemplateError> {
    Ok(match t {
        Value::String(s) => {
            let trimmed = s.trim();
            let refs = references(s)?;
            if refs.len() == 1 && trimmed.starts_with("{{") && trimmed.ends_with("}}") && trimmed[2..].find("{{").is_none() {
                lookup(&refs[0], scope)
            } else {
                Value::String(render_str(s, scope)?)
            }
        }
        Value::Array(a) => Value::Array(a.iter().map(|v| render_json(v, scope)).collect::<Result<_, _>>()?),
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, v)| Ok((k.clone(), render_json(v, scope)?)))
                .collect::<Result<_, TemplateError>>()?,
        ),
        other => other.clone(),
    })
}

/// Render a URL template. The host may be a literal or exactly one
/// `{{config.X}}`; path templates are encoded as a single segment each.
pub fn render_url(t: &str, scope: &Scope) -> Result<url::Url, TemplateError> {
    let (scheme, rest) = t
        .split_once("://")
        .ok_or_else(|| TemplateError::Url(format!("{t:?} is not absolute")))?;
    if scheme.contains("{{") {
        return Err(TemplateError::Url("scheme cannot be templated".into()));
    }
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if path.contains('?') || path.contains('#') {
        return Err(TemplateError::Url("put query parameters in `query`, not the URL".into()));
    }
    let host = if authority.contains("{{") {
        let refs = references(authority)?;
        let a = authority.trim();
        if refs.len() != 1 || !refs[0].starts_with("config.") || !(a.starts_with("{{") && a.ends_with("}}")) {
            return Err(TemplateError::Host);
        }
        let v = value_to_string(&lookup(&refs[0], scope));
        // The value must be a bare host; HostPolicy validates it further.
        if v.is_empty() || v.contains(['/', '@', '?', '#', ':', '\\', ' ']) {
            return Err(TemplateError::Url(format!("config host {v:?} is not a bare host name")));
        }
        v
    } else {
        authority.to_string()
    };
    let path = render_with(path, scope, |s| utf8_percent_encode(&s, SEGMENT).to_string())?;
    url::Url::parse(&format!("{scheme}://{host}{path}")).map_err(|e| TemplateError::Url(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn scope() -> Scope {
        Scope {
            config: json!({"DOMAIN": "acme.okta.com", "EVIL": "evil.com/x"}),
            state: json!({"after": "a b/../c", "n": 5}),
            ..Default::default()
        }
    }

    #[test]
    fn credentials_are_not_a_namespace() {
        assert!(matches!(references("{{credentials.API_KEY}}"), Err(TemplateError::Forbidden(_))));
        assert!(matches!(references("{{ secrets.x }}"), Err(TemplateError::Forbidden(_))));
        assert!(matches!(references("{{foo}}"), Err(TemplateError::Unknown(_))));
    }

    #[test]
    fn path_values_cannot_change_url_structure() {
        let u = render_url("https://api.x.com/v1/{{state.after}}/z", &scope()).unwrap();
        assert_eq!(u.path(), "/v1/a%20b%2F..%2Fc/z");
    }

    #[test]
    fn host_only_from_config_and_must_be_bare() {
        assert_eq!(render_url("https://{{config.DOMAIN}}/api", &scope()).unwrap().host_str(), Some("acme.okta.com"));
        assert!(render_url("https://{{config.EVIL}}/api", &scope()).is_err());
        assert!(render_url("https://{{state.after}}/api", &scope()).is_err());
        assert!(render_url("https://x{{config.DOMAIN}}/api", &scope()).is_err());
    }

    #[test]
    fn json_single_reference_keeps_type() {
        assert_eq!(render_json(&json!({"n": "{{state.n}}", "s": "p{{state.n}}"}), &scope()).unwrap(), json!({"n": 5, "s": "p5"}));
    }
}
