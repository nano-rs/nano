//! `{{namespace.path}}` templates and a closed set of bounded value helpers.
//! No general-purpose expression language or credential namespace. Native
//! authentication owns secrets; templates cannot read credentials.

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::Value;

mod expression;
pub use expression::{evaluate, expression_references};

/// Values a template may read.
#[derive(Debug, Clone, Default)]
pub struct Scope {
    /// Supplied by the trusted request runner, never by template data.
    pub secret_guard: Option<SecretGuard>,
    pub config: Value,
    pub state: Value,
    pub item: Value,
    pub input: Value,
    pub window: Value,
    pub steps: Value,
    pub poll: Value,
    pub run: Value,
    pub alert: Value,
    pub case: Value,
    /// Planning mode: retain response-dependent expressions as placeholders.
    pub defer_responses: bool,
    pub now: String,
    /// NAN-3697: the stream's first cursor (activation − overlap), RFC 3339.
    /// Read as `{{initial_cursor}}`; `{{backfill_from}}` is a deprecated
    /// alias with the same value (there is no operator backfill).
    pub initial_cursor: Option<String>,
}

/// Check every evaluated value, before an outer helper can transform it again.
/// Opaque Debug prevents credential-matching patterns from entering diagnostics.
#[derive(Clone)]
pub struct SecretGuard {
    connection: crate::secrets::SecretSet,
    caller: crate::secrets::SecretSet,
    raw_preview: bool,
}
impl std::fmt::Debug for SecretGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretGuard([REDACTED])")
    }
}
impl SecretGuard {
    pub(crate) fn new(connection: crate::secrets::SecretSet, caller: crate::secrets::SecretSet) -> Self {
        Self { connection, caller, raw_preview: false }
    }
    pub(crate) fn for_preview(mut self) -> Self {
        self.raw_preview = true;
        self
    }
    pub(super) fn allows_raw_preview(&self) -> bool {
        self.raw_preview
    }
    pub(super) fn contains(&self, bytes: &[u8]) -> bool {
        self.connection.contains_decoded(bytes) || self.caller.contains_decoded(bytes)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TemplateError {
    #[error("unterminated template in {0:?}")]
    Unterminated(String),
    #[error("templates cannot read `{0}`; secrets are applied by the engine's auth, never by templates")]
    Forbidden(String),
    #[error("unknown template namespace `{0}`")]
    Unknown(String),
    #[error("a URL host may only be a single {{{{config.X}}}} reference")]
    Host,
    #[error("URL template is invalid: {0}")]
    Url(String),
    #[error("invalid template expression: {0}")]
    Expression(String),
}

const NAMESPACES: &[&str] = &["config", "state", "item", "input", "window", "steps", "poll", "run", "alert", "case", "now", "initial_cursor", "backfill_from"];
const FORBIDDEN: &[&str] = &["credentials", "credential", "secrets", "secret", "auth", "env"];
pub const MAX_RENDER_BYTES: usize = 4 * 1024 * 1024;

fn charge(remaining: &mut usize, bytes: usize) -> Result<(), TemplateError> {
    *remaining = remaining.checked_sub(bytes).ok_or_else(|| TemplateError::Expression("rendered value exceeds 4 MiB".into()))?;
    Ok(())
}

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
        expression_references(&path)?;
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
        "steps" => &scope.steps,
        "poll" => &scope.poll,
        "run" => &scope.run,
        "alert" => &scope.alert,
        "case" => &scope.case,
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
    let mut remaining = MAX_RENDER_BYTES;
    let mut rest = t;
    while let Some(start) = rest.find("{{") {
        charge(&mut remaining, start)?;
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after.find("}}").ok_or_else(|| TemplateError::Unterminated(t.into()))?;
        let rendered = enc(value_to_string(&evaluate(after[..end].trim(), scope)?));
        charge(&mut remaining, rendered.len())?;
        out.push_str(&rendered);
        rest = &after[end + 2..];
    }
    charge(&mut remaining, rest.len())?;
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
    let mut remaining = MAX_RENDER_BYTES;
    render_json_inner(t, scope, &mut remaining)
}

fn render_json_inner(t: &Value, scope: &Scope, remaining: &mut usize) -> Result<Value, TemplateError> {
    let rendered = match t {
        Value::String(s) => {
            let trimmed = s.trim();
            let refs = references(s)?;
            if refs.len() == 1 && trimmed.starts_with("{{") && trimmed.find("}}") == Some(trimmed.len() - 2) {
                evaluate(&refs[0], scope)?
            } else {
                Value::String(render_str(s, scope)?)
            }
        }
        Value::Array(a) => {
            charge(remaining, a.len().saturating_add(2))?;
            return a.iter().map(|v| render_json_inner(v, scope, remaining)).collect::<Result<Vec<_>, _>>().map(Value::Array);
        }
        Value::Object(m) => {
            charge(remaining, m.len().saturating_mul(2).saturating_add(2))?;
            let mut out = serde_json::Map::new();
            for (key,value) in m {
                charge(remaining, serde_json::to_string(key).map_err(|_| TemplateError::Expression("invalid JSON key".into()))?.len())?;
                out.insert(key.clone(), render_json_inner(value, scope, remaining)?);
            }
            return Ok(Value::Object(out));
        }
        other => other.clone(),
    };
    charge(remaining, rendered.to_string().len())?;
    Ok(rendered)
}

/// Render a URL template. The host may be a literal or exactly one
/// `{{config.X}}`; path templates are encoded as a single segment each.
pub fn render_url(t: &str, scope: &Scope) -> Result<url::Url, TemplateError> {
    // A config-supplied base URL is an origin, never an arbitrary URL prefix.
    // Keep path substitution segment-encoded, just as for literal hosts.
    if let Some(after) = t.strip_prefix("{{") {
        let end = after.find("}}").ok_or_else(|| TemplateError::Unterminated(t.into()))?;
        let reference = after[..end].trim();
        if !reference.starts_with("config.") || expression_references(reference)?.len() != 1 {
            return Err(TemplateError::Host);
        }
        let origin = value_to_string(&evaluate(reference, scope)?);
        let host = config_host(&origin)?;
        let path = &after[end + 2..];
        if !path.is_empty() && !path.starts_with('/') {
            return Err(TemplateError::Host);
        }
        return render_url(&format!("https://{host}{path}"), scope);
    }
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
    for expr in references(path)? {
        let value = value_to_string(&evaluate(&expr, scope)?);
        if value == "." || value == ".." { return Err(TemplateError::Url("path substitution cannot be a dot segment".into())); }
    }
    let path = render_with(path, scope, |s| utf8_percent_encode(&s, SEGMENT).to_string())?;
    url::Url::parse(&format!("{scheme}://{host}{path}")).map_err(|e| TemplateError::Url(e.to_string()))
}

/// Resolve either a bare host or an HTTPS origin from non-secret config.
pub fn config_host(value: &str) -> Result<String, TemplateError> {
    if !value.contains("://") {
        if value.is_empty() || value.contains(['/', '@', '?', '#', ':', '\\', ' ']) {
            return Err(TemplateError::Host);
        }
        return Ok(value.to_string());
    }
    let url = url::Url::parse(value).map_err(|e| TemplateError::Url(e.to_string()))?;
    if url.scheme() != "https" || url.path() != "/" || url.query().is_some() || url.fragment().is_some()
        || !url.username().is_empty() || url.password().is_some() || url.port_or_known_default() != Some(443)
    {
        return Err(TemplateError::Host);
    }
    url.host_str().map(str::to_owned).ok_or(TemplateError::Host)
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
