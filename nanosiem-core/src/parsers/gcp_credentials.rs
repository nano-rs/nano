// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shape validation for `gcp_pubsub` credential payloads (NAN-4935).
//!
//! The payload is `{"credentials_json": "<credentials file contents>"}`. nano
//! writes the string verbatim to a file and renders it as the Vector
//! `gcp_pubsub` source's `credentials_path`. The nano-rs Vector fork
//! (0.61.0-nano.3 and later) accepts these Application Default Credentials
//! shapes:
//!
//! * `service_account`: a key file. Many orgs block creating these.
//! * `authorized_user`: `gcloud auth application-default login`.
//! * `external_account`: workload identity federation, with a `file` or `url`
//!   credential source. AWS (`environment_id`) and `executable` sources are
//!   refused because the fork refuses them.
//! * `impersonated_service_account` with `authorized_user` source credentials.
//!
//! None of the non-key shapes carry a `project_id`. The project always comes
//! from the source configuration's `connection_config.project`, never from
//! the credential.
//!
//! Error messages name fields only. They never quote a value from the
//! payload, because the payload is secret.
//!
//! Egress (NAN-4935 review P1) mirrors the fork's `src/gcp/egress.rs` so a bad
//! credential is a 400 here instead of a Vector-side refusal. The fork enforces
//! it regardless:
//! * `token_uri` / `token_url` / `service_account_impersonation_url`: https,
//!   default port, no userinfo or query, host `googleapis.com` or a subdomain,
//!   and the exact Google path.
//! * `credential_source.file`: an absolute path without `.`/`..` under the
//!   workload-identity token root (`NANOSIEM_GCP_WIF_FILE_ROOT`, default
//!   [`DEFAULT_WIF_FILE_ROOT`]; keep it equal to Vector's
//!   `VECTOR_GCP_WIF_FILE_ROOT`).
//! * `credential_source.url`: https to a DNS host that passes the shared SSRF
//!   validator, or the metadata server only when the operator sets
//!   `NANOSIEM_GCP_WIF_ALLOW_METADATA` (Vector also needs
//!   `VECTOR_GCP_WIF_ALLOW_METADATA`).

use std::path::{Component, Path};

use serde_json::Value;
use url::{Host, Url};

use crate::inputlookup::SsrfValidator;

/// Default directory for `external_account` file credential sources.
pub const DEFAULT_WIF_FILE_ROOT: &str = "/var/run/secrets/nano-gcp-wif";
const WIF_FILE_ROOT_ENV: &str = "NANOSIEM_GCP_WIF_FILE_ROOT";
const WIF_ALLOW_METADATA_ENV: &str = "NANOSIEM_GCP_WIF_ALLOW_METADATA";
const METADATA_HOSTS: &[&str] = &["metadata.google.internal", "169.254.169.254"];
const DEFAULT_TOKEN_URI: &str = "https://oauth2.googleapis.com/token";

#[derive(Clone, Copy)]
enum GoogleEndpoint {
    OAuthToken,
    StsToken,
    Impersonation,
}

impl GoogleEndpoint {
    fn field(self) -> &'static str {
        match self {
            Self::OAuthToken => "token_uri",
            Self::StsToken => "token_url",
            Self::Impersonation => "service_account_impersonation_url",
        }
    }

    fn path_allowed(self, path: &str) -> bool {
        match self {
            Self::OAuthToken => path == "/token",
            Self::StsToken => path == "/v1/token",
            Self::Impersonation => path
                .strip_prefix("/v1/projects/-/serviceAccounts/")
                .and_then(|rest| rest.strip_suffix(":generateAccessToken"))
                .is_some_and(|account| {
                    !account.is_empty()
                        && account
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || "@.-_".contains(c))
                }),
        }
    }
}

fn is_googleapis_host(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host == "googleapis.com"
        || host.strip_suffix(".googleapis.com").is_some_and(|label| {
            !label.is_empty()
                && label.split('.').all(|l| {
                    !l.is_empty() && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                })
        })
}

fn check_google_endpoint(raw: &str, kind: GoogleEndpoint) -> Result<(), String> {
    let field = kind.field();
    let bad = |why: &str| Err(format!("'{field}' {why}"));
    let Ok(url) = Url::parse(raw) else {
        return bad("is not a valid URL");
    };
    if url.scheme() != "https" {
        return bad("must use https");
    }
    if !url.username().is_empty() || url.password().is_some() {
        return bad("must not carry userinfo");
    }
    if url.port().is_some_and(|p| p != 443) {
        return bad("must use the default https port");
    }
    match url.host() {
        Some(Host::Domain(host)) if is_googleapis_host(host) => {}
        _ => return bad("must be a googleapis.com host"),
    }
    if url.query().is_some() || url.fragment().is_some() {
        return bad("must not carry a query or fragment");
    }
    if !kind.path_allowed(url.path()) {
        return bad("is not the Google endpoint path");
    }
    Ok(())
}

fn env_flag(name: &str) -> bool {
    std::env::var(name).is_ok_and(|v| {
        matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

fn wif_file_root() -> String {
    std::env::var(WIF_FILE_ROOT_ENV)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_WIF_FILE_ROOT.to_string())
}

fn check_subject_file(raw: &str, root: &str) -> Result<(), String> {
    let path = Path::new(raw);
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(
            "credential_source.file must be an absolute path without . or .. segments".to_string(),
        );
    }
    if !path.starts_with(root) {
        return Err(format!(
            "credential_source.file must be under {root} (the workload identity token directory)"
        ));
    }
    Ok(())
}

fn check_subject_url(raw: &str, allow_metadata: bool) -> Result<(), String> {
    let Ok(url) = Url::parse(raw) else {
        return Err("credential_source.url is not a valid URL".to_string());
    };
    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    if METADATA_HOSTS.contains(&host.as_str()) {
        if !allow_metadata {
            return Err(format!(
                "credential_source.url may name the metadata server only when the operator \
                 sets {WIF_ALLOW_METADATA_ENV}"
            ));
        }
        if url.scheme() != "http" || url.port().is_some_and(|p| p != 80) {
            return Err(
                "credential_source.url reaches the metadata server over http on port 80"
                    .to_string(),
            );
        }
        return Ok(());
    }
    if !matches!(url.host(), Some(Host::Domain(_))) {
        return Err("credential_source.url must name a DNS host, not an IP address".to_string());
    }
    SsrfValidator::default_secure()
        .validate_url(raw)
        .map(|_| ())
        .map_err(|e| format!("credential_source.url is not allowed: {e}"))
}

/// The `type` of a GCP credentials file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GcpCredentialKind {
    ServiceAccount,
    AuthorizedUser,
    ExternalAccount,
    ImpersonatedServiceAccount,
}

impl GcpCredentialKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ServiceAccount => "service_account",
            Self::AuthorizedUser => "authorized_user",
            Self::ExternalAccount => "external_account",
            Self::ImpersonatedServiceAccount => "impersonated_service_account",
        }
    }
}

/// Every field goauth (the fork's service-account path) deserializes. A real
/// key always has all of them; a missing one would only fail at Vector load.
const SERVICE_ACCOUNT_FIELDS: &[&str] = &[
    "project_id",
    "private_key_id",
    "private_key",
    "client_email",
    "client_id",
    "auth_uri",
    "token_uri",
    "auth_provider_x509_cert_url",
    "client_x509_cert_url",
];
const AUTHORIZED_USER_FIELDS: &[&str] = &["client_id", "client_secret", "refresh_token"];
const EXTERNAL_ACCOUNT_FIELDS: &[&str] = &["audience", "subject_token_type", "token_url"];

/// Test seam: the credential_source policy with an explicit root and metadata flag.
#[cfg(test)]
pub(crate) fn validate_credential_source_with(
    source: &Value,
    file_root: &str,
    allow_metadata: bool,
) -> Result<(), String> {
    validate_credential_source(Some(source), file_root, allow_metadata)
}

/// Validate a whole `gcp_pubsub` credential payload (`{"credentials_json": "..."}`).
pub fn validate_gcp_pubsub_payload(payload: &Value) -> Result<GcpCredentialKind, String> {
    match payload.get("credentials_json") {
        None | Some(Value::Null) => {
            Err("GCP Pub/Sub credentials must include 'credentials_json'".to_string())
        }
        // The deploy path reads it with `as_str()` and silently skips anything
        // else, which would deploy a source with no credentials at all.
        Some(Value::String(raw)) => classify_gcp_credentials_json(raw),
        Some(_) => Err(
            "'credentials_json' must be the credentials file contents as a JSON string".to_string(),
        ),
    }
}

/// The credentials file contents a deploy writes for a `gcp_pubsub` source, after full
/// validation. Source generation calls this and fails closed on `Err`, so a stored payload
/// that predates the shape rules never deploys a source without `credentials_path`.
pub fn credentials_file_contents(payload: &Value) -> Result<&str, String> {
    validate_gcp_pubsub_payload(payload)?;
    Ok(payload
        .get("credentials_json")
        .and_then(Value::as_str)
        .unwrap_or_default())
}

/// Classify a GCP credentials file and check that the fields the Vector fork
/// needs for that kind are present.
pub fn classify_gcp_credentials_json(raw: &str) -> Result<GcpCredentialKind, String> {
    let value: Value = serde_json::from_str(raw.trim()).map_err(|e| {
        format!(
            "'credentials_json' is not valid JSON (line {}, column {})",
            e.line(),
            e.column()
        )
    })?;
    let obj = value
        .as_object()
        .ok_or_else(|| "'credentials_json' must be a JSON object".to_string())?;

    let kind = match obj.get("type").and_then(Value::as_str) {
        None | Some("service_account") => GcpCredentialKind::ServiceAccount,
        Some("authorized_user") => GcpCredentialKind::AuthorizedUser,
        Some("external_account") => GcpCredentialKind::ExternalAccount,
        Some("impersonated_service_account") => GcpCredentialKind::ImpersonatedServiceAccount,
        Some(other) => {
            let shown: String = other.chars().take(64).collect();
            return Err(format!(
                "unsupported GCP credentials type '{shown}': use service_account, \
                 authorized_user, external_account or impersonated_service_account"
            ));
        }
    };

    match kind {
        GcpCredentialKind::ServiceAccount => {
            require(obj, kind, SERVICE_ACCOUNT_FIELDS)?;
            check_google_endpoint(str_field(obj, "token_uri"), GoogleEndpoint::OAuthToken)?;
        }
        GcpCredentialKind::AuthorizedUser => {
            require(obj, kind, AUTHORIZED_USER_FIELDS)?;
            check_authorized_user_token_uri(obj)?;
        }
        GcpCredentialKind::ExternalAccount => {
            require(obj, kind, EXTERNAL_ACCOUNT_FIELDS)?;
            check_google_endpoint(str_field(obj, "token_url"), GoogleEndpoint::StsToken)?;
            if let Some(url) = obj.get("service_account_impersonation_url") {
                check_google_endpoint(url.as_str().unwrap_or_default(), GoogleEndpoint::Impersonation)?;
            }
            validate_credential_source(
                obj.get("credential_source"),
                &wif_file_root(),
                env_flag(WIF_ALLOW_METADATA_ENV),
            )?;
        }
        GcpCredentialKind::ImpersonatedServiceAccount => {
            require(obj, kind, &["service_account_impersonation_url"])?;
            check_google_endpoint(
                str_field(obj, "service_account_impersonation_url"),
                GoogleEndpoint::Impersonation,
            )?;
            let source = obj
                .get("source_credentials")
                .and_then(Value::as_object)
                .ok_or_else(|| {
                    "impersonated_service_account credentials are missing 'source_credentials'"
                        .to_string()
                })?;
            match source.get("type").and_then(Value::as_str) {
                Some("authorized_user") => {
                    require(source, GcpCredentialKind::AuthorizedUser, AUTHORIZED_USER_FIELDS)?;
                    check_authorized_user_token_uri(source)?;
                }
                _ => {
                    return Err("impersonated_service_account is supported only with \
                                authorized_user source_credentials"
                        .to_string())
                }
            }
        }
    }
    Ok(kind)
}

fn str_field<'a>(obj: &'a serde_json::Map<String, Value>, field: &str) -> &'a str {
    obj.get(field).and_then(Value::as_str).unwrap_or_default()
}

fn check_authorized_user_token_uri(obj: &serde_json::Map<String, Value>) -> Result<(), String> {
    match obj.get("token_uri") {
        None | Some(Value::Null) => Ok(()),
        Some(Value::String(s)) if s.is_empty() => {
            check_google_endpoint(DEFAULT_TOKEN_URI, GoogleEndpoint::OAuthToken)
        }
        Some(v) => check_google_endpoint(v.as_str().unwrap_or_default(), GoogleEndpoint::OAuthToken),
    }
}

fn require(
    obj: &serde_json::Map<String, Value>,
    kind: GcpCredentialKind,
    fields: &[&str],
) -> Result<(), String> {
    let missing: Vec<&str> = fields
        .iter()
        .copied()
        .filter(|f| {
            !obj.get(*f)
                .and_then(Value::as_str)
                .is_some_and(|s| !s.trim().is_empty())
        })
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{} credentials are missing {}",
            kind.as_str(),
            missing
                .iter()
                .map(|f| format!("'{f}'"))
                .collect::<Vec<_>>()
                .join(", ")
        ))
    }
}

fn validate_credential_source(
    source: Option<&Value>,
    file_root: &str,
    allow_metadata: bool,
) -> Result<(), String> {
    let source = source.and_then(Value::as_object).ok_or_else(|| {
        "external_account credentials are missing 'credential_source'".to_string()
    })?;
    if source.contains_key("environment_id") {
        return Err("external_account with an AWS credential_source (environment_id) is not \
                    supported; use a file or url credential_source"
            .to_string());
    }
    if source.contains_key("executable") {
        return Err("external_account with an executable credential_source is not supported; \
                    use a file or url credential_source"
            .to_string());
    }
    let has = |k: &str| source.get(k).and_then(Value::as_str).is_some_and(|s| !s.is_empty());
    if has("file") == has("url") {
        return Err("external_account credential_source must set exactly one of 'file' or 'url'"
            .to_string());
    }
    if let Some(file) = source.get("file").and_then(Value::as_str) {
        check_subject_file(file, file_root)?;
    }
    if let Some(url) = source.get("url").and_then(Value::as_str) {
        check_subject_url(url, allow_metadata)?;
    }
    if let Some(format) = source.get("format") {
        match format.get("type").and_then(Value::as_str) {
            None | Some("text") => {}
            Some("json") => {
                if format
                    .get("subject_token_field_name")
                    .and_then(Value::as_str)
                    .is_none()
                {
                    return Err("credential_source.format type 'json' needs \
                                'subject_token_field_name'"
                        .to_string());
                }
            }
            Some(_) => {
                return Err("credential_source.format type must be 'text' or 'json'".to_string())
            }
        }
    }
    Ok(())
}
