// SPDX-License-Identifier: AGPL-3.0-or-later
//! Origin grants shared by the hosted and open-core Squid paths (NAN-4402).
//! The principal identifies a tenant AND a purpose. It never grants a host by
//! itself: the check service must compile that tenant's current approved sources.

use base64::{Engine, engine::general_purpose::STANDARD};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeSet;
use uuid::Uuid;

pub const PROXY_URL: &str = "http://search-storage-proxy.nano-egress-proxy.svc.cluster.local:3128";
pub const LOCAL_TENANT: Uuid = Uuid::from_u128(1);
pub const INSECURE_HTTP_WARNING: &str = "This receiver uses insecure plain HTTP. Notification data and credentials are sent without encryption. Use HTTPS when available.";

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, utoipa::ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Purpose {
    /// Read-only inventory; SOAR tunnels retain their connection/revision grant.
    Soar,
    Webhook,
    Connector,
    Pull,
    ThreatIntel,
    Feed,
    Storage,
    Catalog,
    Converter,
    Registry,
    Telemetry,
    CustomEnrichment,
    Ai,
    Platform,
    Supervisor,
}
impl Purpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Soar => "soar",
            Self::Webhook => "webhook",
            Self::Connector => "connector",
            Self::Pull => "pull",
            Self::ThreatIntel => "threat_intel",
            Self::Feed => "feed",
            Self::Storage => "storage",
            Self::Catalog => "catalog",
            Self::Converter => "converter",
            Self::Registry => "registry",
            Self::Telemetry => "telemetry",
            Self::CustomEnrichment => "custom_enrichment",
            Self::Ai => "ai",
            Self::Platform => "platform",
            Self::Supervisor => "supervisor",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        serde_json::from_value(serde_json::Value::String(s.to_owned())).ok()
    }
}

/// Only origins can leave this module. Paths, queries, userinfo and fragments
/// are never retained, including when the input is a credential-bearing URL.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, utoipa::ToSchema,
)]
#[serde(try_from = "String", into = "String")]
pub struct Origin(String);
impl Origin {
    pub fn from_url(raw: &str, purpose: Purpose) -> Result<Self, &'static str> {
        let url = url::Url::parse(raw).map_err(|_| "invalid destination")?;
        if raw.chars().any(char::is_control)
            || raw.contains('\\')
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err("invalid destination");
        }
        let host = match url.host() {
            Some(url::Host::Ipv4(ip))
                if purpose == Purpose::Webhook
                    && !ip.is_private()
                    && !ip.is_loopback()
                    && !ip.is_link_local()
                    && !ip.is_unspecified()
                    && !ip.is_multicast()
                    && !ip.is_broadcast()
                    && !ip.is_documentation()
                    && ip.octets()[0] != 0
                    && ip.octets()[0] < 224
                    && !(ip.octets()[0] == 100 && (64..=127).contains(&ip.octets()[1]))
                    && !(ip.octets()[0] == 198 && (18..=19).contains(&ip.octets()[1]))
                    && !(ip.octets()[0] == 192 && ip.octets()[1] == 0 && ip.octets()[2] == 0) =>
            {
                return Ok(Self(format!(
                    "{}://{}:{}",
                    url.scheme(),
                    ip,
                    match (url.scheme(), url.port_or_known_default()) {
                        ("https", Some(443)) => 443,
                        ("http", Some(80)) => 80,
                        _ => return Err("transport is not authorized for this purpose"),
                    }
                )));
            }
            Some(url::Host::Domain(h))
                if h.contains('.')
                    && !h.ends_with('.')
                    && h.len() <= 253
                    && h.split('.').all(|l| {
                        !l.is_empty()
                            && l.len() <= 63
                            && !l.starts_with('-')
                            && !l.ends_with('-')
                            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                    }) =>
            {
                h
            }
            _ => return Err("destination must be an exact public DNS host"),
        };
        let port = url.port_or_known_default().ok_or("invalid destination")?;
        match (url.scheme(), port, purpose) {
            ("https", 443, _) | ("http", 80, Purpose::Webhook) => {}
            _ => return Err("transport is not authorized for this purpose"),
        }
        Ok(Self(format!("{}://{host}:{port}", url.scheme())))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn host(&self) -> &str {
        self.0
            .split("://")
            .nth(1)
            .unwrap()
            .rsplit_once(':')
            .unwrap()
            .0
    }
}
impl From<Origin> for String {
    fn from(value: Origin) -> Self {
        value.0
    }
}
impl TryFrom<String> for Origin {
    type Error = &'static str;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        // Wire decoding permits HTTP; the purpose boundary is rechecked by
        // Grants::compile. Never trust an origin independently of its purpose.
        let origin = Self::from_url(&value, Purpose::Webhook)?;
        if origin.0 != value {
            return Err("noncanonical origin");
        }
        Ok(origin)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub tenant_id: Uuid,
    pub purpose: Purpose,
    pub origin: Origin,
    /// Immutable spec digest/revision or the authoritative configuration row.
    pub revision: String,
    pub workload: String,
}

/// Constructed only after trusted spec/config resolution. No suffix or shared
/// IP appears in the ACL; the complete key is tenant, purpose, scheme, host, port.
pub struct Grants {
    entries: BTreeSet<(Uuid, Purpose, Origin)>,
}
impl Grants {
    pub fn compile(grants: &[Grant]) -> Result<Self, &'static str> {
        let mut entries = BTreeSet::new();
        for grant in grants {
            let validated = (|| {
                if grant.tenant_id.is_nil() || grant.revision.is_empty() || grant.workload.is_empty()
                    || grant.revision.len() > 256 || grant.workload.len() > 253
                    || grant.revision.chars().any(char::is_control) || grant.workload.chars().any(char::is_control) {
                    return Err("invalid grant provenance");
                }
                Origin::from_url(grant.origin.as_str(), grant.purpose)
            })();
            match validated {
                Ok(origin) => { entries.insert((grant.tenant_id, grant.purpose, origin)); }
                Err(_) if grant.purpose == Purpose::Webhook => invalid_webhook_row(),
                Err(error) => return Err(error),
            }
        }
        Ok(Self { entries })
    }
    pub fn permits(&self, tenant: Uuid, purpose: Purpose, origin: &Origin) -> bool {
        self.entries.contains(&(tenant, purpose, origin.clone()))
    }
}

/// Never log the rejected URL, ciphertext, path, or token.
pub fn invalid_webhook_row() {
    metrics::counter!("nano_egress_invalid_rows_total", "purpose" => "webhook").increment(1);
    tracing::warn!(purpose="webhook", "invalid receiver row omitted from egress authority");
}

#[async_trait::async_trait]
pub trait Source: Send + Sync {
    /// Implementations must read current authority in a tenant-fenced
    /// transaction and return no credentials or configuration bodies.
    async fn grants(&self, tenant: Uuid, purpose: Purpose) -> Result<Vec<Grant>, &'static str>;
    async fn tenant_ids(&self) -> Result<Vec<Uuid>, &'static str> {
        Err("tenant inventory unavailable")
    }
}

/// Coded provider destinations, shared by the native publisher and policy
/// generation. R2 and explicitly approved redirects are added from deployment
/// authority by the caller, never inferred from vendor response URLs.
pub const FEED_HOSTS: &[&str] = &[
    "api.doppler.com",
    "ipinfo.io",
    "check.torproject.org",
    "threatfox-api.abuse.ch",
];

pub fn host_grants(
    tenant: Uuid,
    purpose: Purpose,
    hosts: impl IntoIterator<Item = String>,
    revision: &str,
    workload: &str,
) -> Result<Vec<Grant>, &'static str> {
    let grants = hosts
        .into_iter()
        .map(|host| {
            Ok(Grant {
                tenant_id: tenant,
                purpose,
                origin: Origin::from_url(&format!("https://{host}"), purpose)?,
                revision: revision.into(),
                workload: workload.into(),
            })
        })
        .collect::<Result<Vec<_>, &'static str>>()?;
    Grants::compile(&grants)?;
    Ok(grants)
}

fn password(key: &[u8], tenant: Uuid, purpose: Purpose) -> Option<String> {
    if key.len() < 32 || tenant.is_nil() {
        return None;
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(key).ok()?;
    mac.update(format!("nano-proxy-principal-v1|{tenant}|{}", purpose.as_str()).as_bytes());
    Some(hex::encode(mac.finalize().into_bytes()))
}

/// Never Debug/Serialize this value: the proxy URL or Basic field is a secret.
pub struct Principal {
    pub tenant: Uuid,
    pub purpose: Purpose,
    password: String,
}
impl Principal {
    pub fn new(key: &[u8], tenant: Uuid, purpose: Purpose) -> Result<Self, &'static str> {
        Ok(Self {
            tenant,
            purpose,
            password: password(key, tenant, purpose).ok_or("invalid proxy authority")?,
        })
    }
    pub fn username(&self) -> String {
        format!("{}/{}", self.tenant, self.purpose.as_str())
    }
    pub fn proxy_url(&self) -> String {
        let mut url = url::Url::parse(PROXY_URL).expect("coded proxy URL");
        url.set_username(&self.username()).expect("coded username");
        url.set_password(Some(&self.password))
            .expect("coded password");
        url.to_string()
    }
    pub fn proxy(&self) -> Result<reqwest::Proxy, &'static str> {
        Ok(reqwest::Proxy::all(PROXY_URL)
            .map_err(|_| "invalid proxy endpoint")?
            .basic_auth(&self.username(), &self.password))
    }
    pub fn basic(&self) -> String {
        format!(
            "Basic {}",
            STANDARD.encode(format!("{}:{}", self.username(), self.password))
        )
    }
    pub fn verify(key: &[u8], header: &str) -> Option<(Uuid, Purpose)> {
        if header.len() > 256 {
            return None;
        }
        let bytes = STANDARD.decode(header.strip_prefix("Basic ")?).ok()?;
        let decoded = std::str::from_utf8(&bytes).ok()?;
        let (user, supplied) = decoded.split_once(':')?;
        let (tenant, purpose) = user.split_once('/')?;
        let tenant = Uuid::parse_str(tenant).ok()?;
        let purpose = Purpose::parse(purpose)?;
        let expected = password(key, tenant, purpose)?;
        if !crate::inputlookup::egress_auth::service_token_matches(
            expected.as_bytes(),
            supplied.as_bytes(),
        ) {
            return None;
        }
        Some((tenant, purpose))
    }
}

/// Deployment mode is the existing explicit product boundary. Standard proxy
/// configuration is installed only by an accepted regional rollout stage.
pub fn shared_deployment() -> bool {
    std::env::var("DEPLOYMENT_MODE").as_deref() == Ok("enterprise_shared")
}
pub fn hosted_proxy_configured() -> bool {
    EgressAuthority::from_env().hosted_proxy_configured()
}
pub fn key_from_env() -> Result<Vec<u8>, &'static str> {
    let key = std::env::var("NANOSIEM_INPUTLOOKUP_EGRESS_HMAC_KEY").map_err(|_| "proxy authority is unavailable")?;
    checked_key(key.into_bytes())
}
fn checked_key(key: Vec<u8>) -> Result<Vec<u8>, &'static str> {
    if key.len() < 32 { return Err("invalid proxy authority"); }
    Ok(key)
}
pub fn runtime_tenant(tenant: Uuid) -> Uuid {
    EgressAuthority::from_env().runtime_tenant(tenant)
}

pub fn client_builder(
    tenant: Uuid,
    purpose: Purpose,
) -> Result<reqwest::ClientBuilder, &'static str> {
    EgressAuthority::from_env().client_builder(tenant, purpose)
}

/// The process egress configuration as a value (NAN-4563): deployment mode,
/// whether the hosted proxy is installed, and the proxy HMAC authority.
/// Production reads it once from the environment ([`Self::from_env`]); callers
/// that hold a client for its lifetime capture it at construction, so tests
/// can pass an explicit authority instead of mutating process-global env.
#[derive(Clone)]
pub struct EgressAuthority {
    shared: bool,
    proxy_configured: bool,
    key: Result<Vec<u8>, &'static str>,
}
impl std::fmt::Debug for EgressAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EgressAuthority")
            .field("shared", &self.shared)
            .field("proxy_configured", &self.proxy_configured)
            .field("key", &self.key.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}
impl EgressAuthority {
    /// `DEPLOYMENT_MODE`, `HTTPS_PROXY` and `NANOSIEM_INPUTLOOKUP_EGRESS_HMAC_KEY`
    /// exactly as the free functions above read them.
    pub fn from_env() -> Self {
        let shared = shared_deployment();
        let proxy_configured = shared && std::env::var_os("HTTPS_PROXY").is_some();
        // The key is only needed (and only reported missing) on the hosted path.
        let key = if proxy_configured { key_from_env() } else { Err("proxy authority is unavailable") };
        Self { shared, proxy_configured, key }
    }
    /// Hosted-shared deployment with the regional proxy installed.
    pub fn hosted(key: Vec<u8>) -> Result<Self, &'static str> {
        Ok(Self { shared: true, proxy_configured: true, key: Ok(checked_key(key)?) })
    }
    /// Open-core / dedicated: direct transport, the local tenant principal.
    pub fn local() -> Self {
        Self { shared: false, proxy_configured: false, key: Err("proxy authority is unavailable") }
    }
    pub fn hosted_proxy_configured(&self) -> bool {
        self.proxy_configured
    }
    pub fn runtime_tenant(&self, tenant: Uuid) -> Uuid {
        if self.shared { tenant } else { LOCAL_TENANT }
    }
    pub fn client_builder(&self, tenant: Uuid, purpose: Purpose) -> Result<reqwest::ClientBuilder, &'static str> {
        if !self.proxy_configured { return Ok(reqwest::Client::builder().redirect(reqwest::redirect::Policy::none())); }
        let key = self.key.as_ref().map_err(|error| *error)?;
        Ok(reqwest::Client::builder()
            .no_proxy()
            .proxy(Principal::new(key, self.runtime_tenant(tenant), purpose)?.proxy()?)
            .redirect(reqwest::redirect::Policy::none()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn runtime_authority_scopes_open_core_and_hosted_without_a_direct_fallback() {
        for source in ["installation", "hosted", "missing"] {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command
                .args(["--exact", "egress::tests::runtime_scope_probe", "--ignored"])
                .env_remove("NANOSIEM_INPUTLOOKUP_EGRESS_HMAC_KEY")
                .env_remove("NANOSIEM_ENCRYPTION_KEY")
                .env_remove("DEPLOYMENT_MODE").env_remove("HTTPS_PROXY");
            if source == "installation" {
                command.env(
                    "NANOSIEM_ENCRYPTION_KEY",
                    "fixture-installation-encryption-authority",
                );
            }
            if source != "installation" { command.env("DEPLOYMENT_MODE", "enterprise_shared").env("HTTPS_PROXY", PROXY_URL); }
            if source == "hosted" {
                command.env(
                    "NANOSIEM_INPUTLOOKUP_EGRESS_HMAC_KEY",
                    "fixture-hosted-proxy-authority-32-bytes",
                );
            }
            let output = command.output().unwrap();
            assert!(
                output.status.success(),
                "runtime authority source {source} failed"
            );
        }
    }
    #[test]
    fn explicit_authority_needs_no_process_env() {
        let tenant = Uuid::from_u128(10);
        let local = EgressAuthority::local();
        assert!(!local.hosted_proxy_configured());
        assert_eq!(local.runtime_tenant(tenant), LOCAL_TENANT);
        assert!(local.client_builder(tenant, Purpose::Ai).is_ok());
        let hosted = EgressAuthority::hosted(b"fixture-hosted-proxy-authority-32-bytes".to_vec()).unwrap();
        assert!(hosted.hosted_proxy_configured());
        assert_eq!(hosted.runtime_tenant(tenant), tenant);
        assert!(hosted.client_builder(tenant, Purpose::Ai).is_ok());
        assert!(EgressAuthority::hosted(b"short".to_vec()).is_err(), "short keys stay refused");
        assert!(!format!("{hosted:?}").contains("fixture-hosted"), "the key is redacted");
    }
    #[test]
    #[ignore = "invoked in isolated subprocesses by the runtime authority test"]
    fn runtime_scope_probe() {
        let tenant = Uuid::from_u128(10);
        if shared_deployment() && std::env::var_os("NANOSIEM_INPUTLOOKUP_EGRESS_HMAC_KEY").is_some() {
            assert_eq!(runtime_tenant(tenant), tenant);
            assert!(client_builder(tenant, Purpose::Storage).is_ok());
        } else if !shared_deployment() {
            assert_eq!(runtime_tenant(tenant), LOCAL_TENANT);
            assert!(client_builder(tenant, Purpose::Storage).is_ok());
        } else {
            assert!(client_builder(tenant, Purpose::Storage).is_err());
        }
    }
    #[test]
    fn compiled_authority_is_tenant_purpose_origin_and_transport_bound() {
        let a = Uuid::from_u128(10);
        let b = Uuid::from_u128(11);
        let https = Origin::from_url(
            "https://receiver.example/private?token=secret",
            Purpose::Webhook,
        )
        .unwrap();
        let http = Origin::from_url("http://receiver.example/private", Purpose::Webhook).unwrap();
        assert_eq!(https.as_str(), "https://receiver.example:443");
        let grant = Grant {
            tenant_id: a,
            purpose: Purpose::Webhook,
            origin: http.clone(),
            revision: "row-1".into(),
            workload: "api".into(),
        };
        let policy = Grants::compile(&[grant.clone()]).unwrap();
        assert!(policy.permits(a, Purpose::Webhook, &http));
        assert!(!policy.permits(b, Purpose::Webhook, &http));
        assert!(!policy.permits(a, Purpose::Pull, &http));
        assert!(!policy.permits(a, Purpose::Webhook, &https));
        assert!(!policy.permits(
            a,
            Purpose::Webhook,
            &Origin::from_url("http://unlisted.example", Purpose::Webhook).unwrap()
        ));
        assert!(
            Grants::compile(&[Grant {
                purpose: Purpose::Pull,
                ..grant
            }])
            .is_err()
        );
        for bad in [
            "https://*.example.com",
            "https://127.0.0.1",
            "https://a.example:444",
            "http://a.example:443",
            "https://u:p@a.example",
            "https://a.example\\evil",
            "https://a.example\n",
        ] {
            assert!(Origin::from_url(bad, Purpose::Webhook).is_err(), "{bad}");
        }
        assert!(Origin::from_url("http://a.example", Purpose::Feed).is_err());
        assert_eq!(
            Origin::from_url("http://8.8.8.8/receiver", Purpose::Webhook)
                .unwrap()
                .as_str(),
            "http://8.8.8.8:80"
        );
        assert!(Origin::from_url("http://8.8.8.8/receiver", Purpose::Connector).is_err());
    }
    #[test]
    fn one_invalid_webhook_grant_cannot_disable_other_receivers() {
        let tenant = Uuid::from_u128(10);
        let good = Grant {tenant_id:tenant, purpose:Purpose::Webhook, origin:Origin::from_url("https://receiver.example",Purpose::Webhook).unwrap(), revision:"current".into(),workload:"api".into()};
        let bad = Grant {origin:Origin("https://127.0.0.1:443".into()),..good.clone()};
        let acl = Grants::compile(&[bad, good.clone()]).unwrap();
        assert!(acl.permits(tenant,Purpose::Webhook,&good.origin));
        assert!(!acl.permits(Uuid::from_u128(11),Purpose::Webhook,&good.origin));
    }
    #[test]
    fn proxy_credentials_cannot_be_moved_between_tenants_or_purposes() {
        let key = [7; 32];
        let tenant = Uuid::from_u128(10);
        let principal = Principal::new(&key, tenant, Purpose::Connector).unwrap();
        assert_eq!(
            Principal::verify(&key, &principal.basic()),
            Some((tenant, Purpose::Connector))
        );
        assert!(Principal::verify(&[8; 32], &principal.basic()).is_none());
        let decoded = format!("{}:{}", principal.username(), principal.password);
        for changed in [
            decoded.replace("connector", "webhook"),
            decoded.replace(&tenant.to_string(), &Uuid::from_u128(11).to_string()),
        ] {
            assert!(
                Principal::verify(&key, &format!("Basic {}", STANDARD.encode(changed))).is_none()
            );
        }
        assert!(Principal::verify(&key, "Basic malformed").is_none());
        assert!(Principal::new(&key, Uuid::nil(), Purpose::Feed).is_err());
    }
}

/// Code-owned in-cluster transports only. Tenant webhook URLs never use this
/// bypass; the webhook path always applies its public-destination validator.
pub fn is_internal_service(url: &url::Url) -> bool {
    match url.host_str() {
        Some(host) => {
            [
                "localhost",
                "127.0.0.1",
                "::1",
                "postgres",
                "dragonfly",
                "vector",
                "lake-object-store",
                "lake-catalog",
                "lake-cell",
                "lean-otel",
                "lean-enrichment",
            ]
            .contains(&host)
                || host.ends_with(".svc")
                || host.ends_with(".svc.cluster.local")
        }
        None => false,
    }
}

/// HTTP clients in single-purpose workers consume only the delegated URL.
/// Missing delegation fails closed; internal service clients remain separate.
pub fn delegated_proxy_url(purpose: Purpose) -> Result<String, &'static str> {
    let raw = std::env::var("HTTPS_PROXY").map_err(|_| "proxy delegation unavailable")?;
    validate_delegated_proxy_url(&raw, purpose)?;
    Ok(raw)
}

pub fn validate_delegated_proxy_url(raw: &str, purpose: Purpose) -> Result<&str, &'static str> {
    let url = url::Url::parse(raw).map_err(|_| "invalid proxy delegation")?;
    let expected = url::Url::parse(PROXY_URL).expect("coded URL");
    let (tenant, scope) = url
        .username()
        .split_once("%2F")
        .ok_or("invalid proxy delegation")?;
    if url.scheme() != "http"
        || url.host_str() != expected.host_str()
        || url.port() != Some(3128)
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || scope != purpose.as_str()
        || Uuid::parse_str(tenant)
            .map_err(|_| "invalid proxy delegation")?
            .is_nil()
        || !url.password().is_some_and(|password| {
            password.len() == 64 && password.bytes().all(|b| b.is_ascii_hexdigit())
        })
    {
        return Err("invalid proxy delegation");
    }
    Ok(raw)
}
