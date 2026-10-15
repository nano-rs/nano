// SPDX-License-Identifier: AGPL-3.0-or-later
//! Shared Search deliberately performs bounded object-store reads in Nano's
//! tenant view: the lake worker cannot run Nano's CSV/JSON post-processing.
//! No worker leases, cloud credentials, event interpolation or proxy inheritance.
use super::{
    shared_parser::parse_shared_response,
    storage_policy::{validate_storage_url, STORAGE_POLICY_ERROR},
    InputLookupParams, SsrfConfig, SsrfValidator,
};
use async_trait::async_trait;

mod proxy;
use proxy::FetchRoute;

use reqwest::{Client, Response};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, SocketAddr},
    sync::{Arc, LazyLock, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;
use url::Url;
use uuid::Uuid;

pub const MAX_SHARED_BYTES: usize = 50 * 1024 * 1024;
pub const MAX_SHARED_TIMEOUT: u32 = 30;
pub const MAX_SHARED_ROWS: usize = 100_000;
pub const MAX_SHARED_CACHE_TTL: u32 = 900;

#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct StorageLookupSettings {
    #[serde(default)]
    pub entries: Vec<StorageLookupEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct StorageLookupEntry {
    pub host: String,
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub created_by: Uuid,
    #[serde(default = "chrono::Utc::now")]
    pub created_at: chrono::DateTime<chrono::Utc>,
}
impl StorageLookupSettings {
    pub fn hosts(&self) -> Vec<String> {
        self.entries.iter().map(|e| e.host.clone()).collect()
    }
}

/// Implementations read current settings and persist audit through signed RLS.
/// Actors come from the authenticated task-local, never from URL/query input.
#[async_trait]
pub trait StorageLookupAuthority: Send + Sync {
    fn tenant_id(&self) -> Uuid;
    async fn settings(&self) -> Result<StorageLookupSettings, &'static str>;
    /// Verify audit storage before admitting outbound work.
    async fn audit_ready(&self) -> Result<(), &'static str>;
    async fn audit(&self, record: &FetchAudit) -> Result<(), &'static str>;
}

/// Deliberately contains no URL, request body, credential, or error text.
#[derive(Debug, Clone, Serialize)]
pub struct FetchAudit {
    pub tenant_id: Uuid,
    pub search_id: Option<Uuid>,
    pub host: String,
    pub decision: &'static str,
    pub http_status: Option<u16>,
    pub bytes: usize,
    pub duration_ms: u64,
    pub redirect_hops: u8,
    pub via_proxy: bool,
}

/// Only a normalized host survives the audit boundary, including policy-denied
/// IP/internal targets. Never apply the allowlist policy to audit metadata.
pub fn audit_host(raw: &str) -> String {
    if raw.is_empty()
        || raw.len() > 253
        || raw.contains(['/', '@', '?', '#', '%', '\\', '*'])
        || raw.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return "invalid".into();
    }
    if let Ok(ip) = raw.parse::<IpAddr>() {
        return ip.to_string();
    }
    match url::Host::parse(raw.strip_suffix('.').unwrap_or(raw)) {
        Ok(url::Host::Domain(host))
            if host.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            }) =>
        {
            host
        }
        Ok(url::Host::Ipv4(ip)) => ip.to_string(),
        Ok(url::Host::Ipv6(ip)) => ip.to_string(),
        _ => "invalid".into(),
    }
}

fn decision(error: Option<&'static str>) -> &'static str {
    match error {
        None => "allowed",
        Some(super::storage_policy::ALLOWLIST_ERROR) => "denied_allowlist",
        Some(
            STORAGE_POLICY_ERROR
            | proxy::CONFIG_ERROR
            | "inputlookup invalid redirect"
            | "inputlookup DNS resolved to a non-public address",
        ) => "denied_policy",
        Some("inputlookup proxy denied destination") => "proxy_denied",
        Some(proxy::UNREACHABLE) => "error_proxy",
        Some("inputlookup remote HTTP error") => "error_http",
        Some("inputlookup deadline exceeded") => "error_timeout",
        Some(error) if error.contains("limit") || error.contains("capacity") => "error_limit",
        Some(error) if error.contains("DNS") => "error_dns",
        Some(_) => "error_fetch",
    }
}

tokio::task_local! { static FETCH_SEARCH_ID: Uuid; }
pub fn fetch_search_id() -> Option<Uuid> {
    FETCH_SEARCH_ID.try_with(|id| *id).ok()
}
/// Untrusted request identifiers are hashed rather than copied into audit metadata.
pub fn audit_search_id(id: &str) -> Uuid {
    use sha2::{Digest, Sha256};
    Uuid::parse_str(id).unwrap_or_else(|_| {
        let digest = Sha256::digest(id.as_bytes());
        let mut bytes = [0; 16];
        bytes.copy_from_slice(&digest[..16]);
        Uuid::from_bytes(bytes)
    })
}
pub async fn with_fetch_search_id<F: std::future::Future>(id: Uuid, future: F) -> F::Output {
    FETCH_SEARCH_ID.scope(id, future).await
}

struct CachedBody {
    policy_hosts: Vec<String>,
    body: String,
    expires: Instant,
    created: Instant,
    _budget: tokio::sync::OwnedSemaphorePermit,
}
// Strict rolling-minute cap, rather than a token bucket's extra initial burst.
struct TenantRate {
    requests: Mutex<VecDeque<Instant>>,
}
impl TenantRate {
    fn new() -> Self {
        Self {
            requests: Mutex::new(VecDeque::new()),
        }
    }
    fn check(&self) -> Result<(), ()> {
        let mut requests = self
            .requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Instant::now();
        while requests
            .front()
            .is_some_and(|t| now.duration_since(*t) >= Duration::from_secs(60))
        {
            requests.pop_front();
        }
        if requests.len() >= 10 {
            return Err(());
        }
        requests.push_back(now);
        Ok(())
    }
}

struct TenantState {
    concurrency: Semaphore,
    rate: TenantRate,
    cache: Mutex<HashMap<String, CachedBody>>,
}
impl TenantState {
    fn new() -> Self {
        Self {
            concurrency: Semaphore::new(2),
            rate: TenantRate::new(),
            cache: Mutex::new(HashMap::new()),
        }
    }
    #[cfg(test)]
    fn cached(&self, key: &str, ttl: u32) -> Option<String> {
        self.cached_authorized(key, ttl, None).ok().flatten()
    }
    fn cached_authorized(
        &self,
        key: &str,
        ttl: u32,
        allowed: Option<&[String]>,
    ) -> Result<Option<String>, &'static str> {
        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cache.retain(|_, v| v.expires > Instant::now());
        let entry = cache.get(key).filter(|v| {
            v.created.elapsed() < Duration::from_secs(ttl.min(MAX_SHARED_CACHE_TTL) as u64)
        });
        if entry.is_some_and(|v| {
            allowed.is_some_and(|entries| {
                v.policy_hosts
                    .iter()
                    .any(|host| !super::storage_policy::host_allowed(host, entries))
            })
        }) {
            return Err(super::storage_policy::ALLOWLIST_ERROR);
        }
        Ok(entry.map(|v| v.body.clone()))
    }
    #[cfg(test)]
    fn insert(&self, key: String, body: String, ttl: u32) {
        let hosts = Url::parse(&key)
            .ok()
            .and_then(|u| u.host_str().map(str::to_owned))
            .into_iter()
            .collect();
        self.insert_with_hosts(key, body, ttl, hosts);
    }
    fn insert_with_hosts(&self, key: String, body: String, ttl: u32, policy_hosts: Vec<String>) {
        if ttl == 0 {
            return;
        }
        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cache.retain(|_, v| v.expires > Instant::now());
        // Bound aggregate cached bytes, not just the size of a single response.
        if cache.len() >= 16
            || cache.values().map(|v| v.body.len()).sum::<usize>() + body.len() > MAX_SHARED_BYTES
        {
            cache.clear();
        }
        let Ok(budget) = Arc::clone(&CACHE_BUDGET).try_acquire_many_owned(body.len() as u32) else {
            return;
        };
        cache.insert(
            key,
            CachedBody {
                policy_hosts,
                _budget: budget,
                created: Instant::now(),
                body,
                expires: Instant::now() + Duration::from_secs(ttl.min(MAX_SHARED_CACHE_TTL) as u64),
            },
        );
    }
}
static TENANTS: LazyLock<Mutex<HashMap<Uuid, Arc<TenantState>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static CACHE_BUDGET: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(256 * 1024 * 1024)));
static AUDITED_FETCH_BUDGET: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(64)));
static FETCH_BUDGET: Semaphore = Semaphore::const_new(8);

#[derive(Clone)]
pub struct SharedStorageLookup {
    authority: Arc<dyn StorageLookupAuthority>,
    state: Arc<TenantState>,
    #[cfg(test)]
    endpoint: Option<TestEndpoint>,
    #[cfg(test)]
    route: Option<FetchRoute>,
}
impl SharedStorageLookup {
    pub fn new(authority: Arc<dyn StorageLookupAuthority>) -> Result<Self, &'static str> {
        let tenant = authority.tenant_id();
        if tenant.is_nil() {
            return Err("inputlookup requires a tenant");
        }
        let mut tenants = TENANTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if tenants.len() >= 4096 && !tenants.contains_key(&tenant) {
            return Err("inputlookup tenant capacity exceeded");
        }
        let state = tenants
            .entry(tenant)
            .or_insert_with(|| Arc::new(TenantState::new()))
            .clone();
        Ok(Self {
            authority,
            state,
            #[cfg(test)]
            endpoint: None,
            #[cfg(test)]
            route: None,
        })
    }
    pub fn tenant_id(&self) -> Uuid {
        self.authority.tenant_id()
    }

    pub async fn fetch(&self, params: &InputLookupParams) -> Result<Vec<Value>, &'static str> {
        let permit = Arc::clone(&AUDITED_FETCH_BUDGET)
            .acquire_owned()
            .await
            .map_err(|_| "inputlookup audit admission unavailable")?;
        let lookup = self.clone();
        let params = params.clone();
        let search_id = FETCH_SEARCH_ID.try_with(|id| *id).ok();
        // The bounded task owns both fetch and audit. Dropping a cancelled search
        // cannot cancel its completion record; authenticated actor scope follows it.
        tokio::spawn(crate::search::request_actor::inherit(async move {
            let _permit = permit;
            let started = Instant::now();
            let host = Url::parse(&params.url.template)
                .ok()
                .and_then(|url| url.host_str().map(audit_host))
                .unwrap_or_else(|| "invalid".into());
            let mut record = FetchAudit {
                tenant_id: lookup.tenant_id(),
                search_id,
                host,
                decision: "error_fetch",
                http_status: None,
                bytes: 0,
                duration_ms: 0,
                redirect_hops: 0,
                via_proxy: true,
            };
            let result =
                match tokio::time::timeout(Duration::from_secs(5), lookup.authority.audit_ready())
                    .await
                {
                    Ok(Ok(())) => lookup.fetch_inner(&params, &mut record).await,
                    Ok(Err(error)) => Err(error),
                    Err(_) => Err("inputlookup audit deadline exceeded"),
                };
            record.decision = decision(result.as_ref().err().copied());
            record.duration_ms = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
            tokio::time::timeout(Duration::from_secs(5), lookup.authority.audit(&record))
                .await
                .map_err(|_| "inputlookup audit deadline exceeded")??;
            result
        }))
        .await
        .map_err(|_| "inputlookup task failed")?
    }

    async fn fetch_inner(
        &self,
        params: &InputLookupParams,
        record: &mut FetchAudit,
    ) -> Result<Vec<Value>, &'static str> {
        if params.key_field.is_some()
            || params.url.has_placeholders()
            || params.timeout_secs == 0
            || params.max_rows == 0
            || params.max_rows > MAX_SHARED_ROWS
        {
            return Err(STORAGE_POLICY_ERROR);
        }
        let _global_permit = FETCH_BUDGET
            .try_acquire()
            .map_err(|_| "inputlookup global concurrency limit exceeded")?;
        let _permit = self
            .state
            .concurrency
            .try_acquire()
            .map_err(|_| "inputlookup tenant concurrency limit (2) exceeded")?;
        if self.state.rate.check().is_err() {
            return Err("inputlookup tenant fetch rate limit (10/minute) exceeded");
        }
        let settings = tokio::time::timeout(Duration::from_secs(5), self.authority.settings())
            .await
            .map_err(|_| "inputlookup settings deadline exceeded")??;
        let allowed_hosts = settings.hosts();
        let url = validate_storage_url(&params.url.template, &allowed_hosts)?;
        #[cfg(not(test))]
        let route = FetchRoute::from_env()?;
        #[cfg(test)]
        let route = self
            .route
            .clone()
            .map(Ok)
            .unwrap_or_else(FetchRoute::from_env)?;
        record.via_proxy = route.is_proxy();
        // Policy is refreshed before cache lookup, so removing a host revokes cached reads.
        let key = url.as_str().to_string();
        if params.cache_ttl_secs > 0 {
            if let Some(body) =
                self.state
                    .cached_authorized(&key, params.cache_ttl_secs, Some(&allowed_hosts))?
            {
                record.bytes = body.len();
                return parse_shared_response(&body, params.format, params.max_rows);
            }
        }
        let timeout = Duration::from_secs(params.timeout_secs.min(MAX_SHARED_TIMEOUT) as u64);
        // One deadline covers DNS, all redirects, and the entire streaming body.
        let mut policy_hosts = Vec::new();
        let body = tokio::time::timeout(
            timeout,
            fetch_body(
                url,
                &allowed_hosts,
                &mut policy_hosts,
                record,
                &route,
                self.tenant_id(),
                #[cfg(test)]
                self.endpoint.as_ref(),
            ),
        )
        .await
        .map_err(|_| {
            if route.is_proxy() {
                proxy::UNREACHABLE
            } else {
                "inputlookup deadline exceeded"
            }
        })??;
        let rows = parse_shared_response(&body, params.format, params.max_rows)?;
        self.state
            .insert_with_hosts(key.to_string(), body, params.cache_ttl_secs, policy_hosts);
        Ok(rows)
    }
}

fn client_builder() -> reqwest::ClientBuilder {
    Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .https_only(true)
        .connect_timeout(Duration::from_secs(10))
        // Default TLS verification and URL-host SNI/Host are intentionally retained.
        .user_agent("NanoSIEM/1.0 InputLookup")
}

/// All final A/AAAA answers must be public. Conservatively refuse IPv6
/// translation/tunnelling ranges too; they can embed internal IPv4 addresses.
fn validate_addresses(addrs: &[SocketAddr]) -> Result<(), &'static str> {
    if addrs.is_empty() {
        return Err("inputlookup DNS returned no addresses");
    }
    let validator = SsrfValidator::new(SsrfConfig::default());
    for addr in addrs {
        validator
            .validate_ip_address(addr.ip())
            .map_err(|_| "inputlookup DNS resolved to a non-public address")?;
        match addr.ip() {
            IpAddr::V4(ip) => {
                let [a, b, c, _] = ip.octets();
                if a == 0
                    || a >= 224
                    || (a == 192 && b == 0)
                    || (a == 192 && b == 88 && c == 99)
                    || (a == 198 && (b == 18 || b == 19))
                    || ip.is_documentation()
                    || ip.is_broadcast()
                {
                    return Err("inputlookup DNS resolved to a non-public address");
                }
            }
            IpAddr::V6(ip) => {
                let s = ip.segments();
                // Only global unicast; reject 2001 special assignments / Teredo,
                // documentation and 6to4 (2002), NAT64, compatible/mapped v4.
                if s[0] & 0xe000 != 0x2000
                    || s[0] == 0x2002
                    || s[0] == 0x3ffe
                    || s[0] == 0x3fff
                    || (s[0] == 0x2001 && (s[1] < 0x0200 || s[1] == 0x0db8))
                {
                    return Err("inputlookup DNS resolved to a non-public address");
                }
            }
        }
    }
    Ok(())
}

async fn resolve(url: &Url) -> Result<Vec<SocketAddr>, &'static str> {
    let host = url.host_str().ok_or(STORAGE_POLICY_ERROR)?;
    // Exactly one DNS lookup per hop. No preliminary lookup or fallback client.
    let addrs: Vec<_> = tokio::net::lookup_host((host, 443))
        .await
        .map_err(|_| "inputlookup DNS resolution failed")?
        .collect();
    validate_addresses(&addrs)?;
    Ok(addrs)
}
/// Proxy DNS is authoritative. A bounded local check rejects known private
/// answers, but resolver unavailability must not disable proxy-resolved access.
async fn precheck_dns(
    url: &Url,
    route: &FetchRoute,
) -> Result<Option<Vec<SocketAddr>>, &'static str> {
    if !route.is_proxy() {
        return resolve(url).await.map(Some);
    }
    match tokio::time::timeout(Duration::from_millis(250), resolve(url)).await {
        Ok(Ok(addrs)) => Ok(Some(addrs)),
        Ok(Err("inputlookup DNS resolution failed")) | Err(_) => Ok(None),
        Ok(Err(error)) => Err(error),
    }
}
async fn fetch_body(
    mut url: Url,
    extras: &[String],
    policy_hosts: &mut Vec<String>,
    record: &mut FetchAudit,
    route: &FetchRoute,
    tenant: Uuid,
    #[cfg(test)] endpoint: Option<&TestEndpoint>,
) -> Result<String, &'static str> {
    for hop in 0..=3 {
        url = validate_storage_url(url.as_str(), extras)?;
        policy_hosts.push(url.host_str().ok_or(STORAGE_POLICY_ERROR)?.to_owned());
        #[cfg(not(test))]
        let addrs = precheck_dns(&url, route).await?;
        #[cfg(test)]
        let addrs = if let Some(endpoint) = endpoint {
            if let Some(answers) = &endpoint.answers {
                answers.lock().unwrap().remove(0)
            } else {
                vec!["93.184.216.34:443".parse().unwrap()]
            }
        } else {
            precheck_dns(&url, route).await?.unwrap_or_default()
        };
        #[cfg(test)]
        let addrs = if endpoint.is_none() && addrs.is_empty() && route.is_proxy() {
            None
        } else {
            Some(addrs)
        };
        if let Some(addrs) = &addrs {
            validate_addresses(addrs)?;
        }
        let (response, _connection) = if let FetchRoute::Proxy(proxy_url) = route {
            let (response, connection) = proxy::request(
                proxy_url,
                &url,
                tenant,
                &mut record.http_status,
                #[cfg(test)]
                endpoint,
            )
            .await?;
            (response, Some(connection))
        } else {
            let host = url.host_str().ok_or(STORAGE_POLICY_ERROR)?;
            let builder = client_builder().resolve_to_addrs(
                host,
                addrs
                    .as_deref()
                    .ok_or("inputlookup DNS resolution failed")?,
            );
            #[cfg(test)]
            let builder = if let Some(endpoint) = endpoint {
                builder
                    .add_root_certificate(endpoint.cert.clone())
                    .resolve_to_addrs(host, &[endpoint.addr])
            } else {
                builder
            };
            let client = builder
                .build()
                .map_err(|_| "inputlookup transport unavailable")?;
            #[cfg(not(test))]
            let request_url = url.clone();
            #[cfg(test)]
            let request_url = {
                let mut request_url = url.clone();
                if let Some(endpoint) = endpoint {
                    request_url.set_port(Some(endpoint.addr.port())).unwrap();
                }
                request_url
            };
            let response = client
                .get(request_url)
                .header(reqwest::header::ACCEPT_ENCODING, "identity")
                .send()
                .await
                .map_err(|_| "inputlookup HTTPS request failed")?;
            (response, None)
        };
        record.http_status = Some(response.status().as_u16());
        if response.status().is_redirection() {
            record.redirect_hops = (hop + 1).min(3);
            if hop == 3 {
                return Err("inputlookup exceeded 3 redirects");
            }
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|h| h.to_str().ok())
                .ok_or("inputlookup invalid redirect")?;
            // Reject raw ambiguities before join() normalizes a relative path.
            if location.contains('\\')
                || location.contains(['{', '}'])
                || location.chars().any(char::is_control)
                || location.to_ascii_lowercase().contains("%2e")
                || location.to_ascii_lowercase().contains("%2f")
                || location.to_ascii_lowercase().contains("%5c")
                || location.split('/').any(|s| s == "." || s == "..")
            {
                return Err("inputlookup invalid redirect");
            }
            // Absolute/network-path references need validation before URL join
            // erases an empty userinfo component or normalizes dot segments.
            if location.starts_with("//") {
                validate_storage_url(&format!("https:{location}"), extras)?;
            } else if Url::parse(location).is_ok() {
                validate_storage_url(location, extras)?;
            }
            url = validate_storage_url(
                url.join(location)
                    .map_err(|_| "inputlookup invalid redirect")?
                    .as_str(),
                extras,
            )?;
            continue;
        }
        if !response.status().is_success() {
            return Err("inputlookup remote HTTP error");
        }
        return read_body(response, &mut record.bytes, MAX_SHARED_BYTES).await;
    }
    Err("inputlookup exceeded 3 redirects")
}
async fn read_body(
    mut response: Response,
    bytes: &mut usize,
    cap: usize,
) -> Result<String, &'static str> {
    if response
        .headers()
        .get(reqwest::header::CONTENT_ENCODING)
        .is_some_and(|v| v.as_bytes() != b"identity")
    {
        return Err("inputlookup compressed responses are not supported");
    }
    if response.content_length().is_some_and(|n| n > cap as u64) {
        return Err("inputlookup response exceeds byte limit");
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "inputlookup response read failed")?
    {
        *bytes = bytes.saturating_add(chunk.len());
        if chunk.len() > cap.saturating_sub(body.len()) {
            return Err("inputlookup response exceeds byte limit");
        }
        body.extend_from_slice(&chunk);
    }
    if body.starts_with(&[0x1f, 0x8b])
        || body.starts_with(b"PK\x03\x04")
        || body.starts_with(&[0x28, 0xb5, 0x2f, 0xfd])
    {
        return Err("inputlookup compressed responses are not supported");
    }
    String::from_utf8(body).map_err(|_| "inputlookup response is not UTF-8")
}

#[cfg(test)]
#[derive(Clone)]
struct TestEndpoint {
    addr: SocketAddr,
    cert: reqwest::Certificate,
    answers: Option<Arc<Mutex<Vec<Vec<SocketAddr>>>>>,
}
#[cfg(test)]
mod tests;
