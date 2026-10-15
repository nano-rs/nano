//! NAN-3763: declarative threat-intel lookup specs (VirusTotal, AbuseIPDB,
//! GreyNoise, URLhaus, ThreatFox, MalwareBazaar, Shodan).
//!
//! A lookup spec is pure data: per artifact type, one request template, and a
//! declarative mapping from the provider's JSON answer to a normalized
//! verdict (`malicious | suspicious | benign | unknown | not_found`), a 0-100
//! score, a few summary facts and a link. There is no VRL and no tenant code:
//! every request is compiled to an `agent_enrichment` [`ConnectorSpec`] with
//! one program-less stream and run through [`engine::run`], so the broker's
//! allowlist, egress deny, DNS-rebinding checks, auth plugins and secret
//! redaction apply exactly as for any connector. Because no stream has a
//! program, a lookup never needs a VRL worker and can run inside the API.
//!
//! The official specs ship in this crate (`lookups/*.yaml`) and are the only
//! specs a hosted tenant can enable: tenants configure credentials and limits,
//! never requests.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};

use base64::Engine as _;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::auth::Credentials;
use crate::engine::{self, EngineConfig, EngineError, MemorySink, MemoryStore, RunInput};
use crate::paging::get_path;
use crate::spec::{AllowRule, AuthConfig, ConnectorSpec, RequestTemplate};
use crate::template::{self, Scope};

pub const LOOKUP_SPEC_VERSION: u32 = 1;
/// Largest artifact accepted (URLs).
pub const MAX_ARTIFACT_LEN: usize = 2048;
/// Summary string values are cut to this many characters.
const MAX_SUMMARY_STRING: usize = 256;
/// Summary arrays keep at most this many entries.
const MAX_SUMMARY_ITEMS: usize = 10;
const MAX_TAGS: usize = 16;

// ---------------------------------------------------------------------------
// Artifacts
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactType {
    Hash,
    Domain,
    Ip,
    Url,
}

impl ArtifactType {
    pub const ALL: [ArtifactType; 4] = [Self::Hash, Self::Domain, Self::Ip, Self::Url];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hash => "hash",
            Self::Domain => "domain",
            Self::Ip => "ip",
            Self::Url => "url",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "hash" | "file_hash" | "md5" | "sha1" | "sha256" => Some(Self::Hash),
            "domain" | "hostname" | "fqdn" => Some(Self::Domain),
            "ip" | "ipv4" | "ipv6" | "ip_address" => Some(Self::Ip),
            "url" | "uri" => Some(Self::Url),
            _ => None,
        }
    }
}

/// Why an artifact is not sent to any provider.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ArtifactError {
    #[error("artifact must be 1-{MAX_ARTIFACT_LEN} printable characters")]
    Shape,
    #[error("`{0}` is not a valid {1}")]
    Invalid(String, &'static str),
    #[error("could not tell whether the artifact is a hash, domain, IP or URL")]
    Undetected,
    /// Internal addresses and names are never sent to a third party.
    #[error("{0} is internal and is never sent to an external provider")]
    Internal(&'static str),
}

/// A validated, normalized artifact.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Artifact {
    pub kind: ArtifactType,
    /// Normalized value (lowercased hash/domain, canonical IP, parsed URL).
    pub value: String,
}

const INTERNAL_SUFFIXES: &[&str] = &[
    ".local", ".localhost", ".internal", ".intranet", ".lan", ".corp", ".home", ".home.arpa", ".localdomain", ".in-addr.arpa", ".ip6.arpa",
];

fn is_internal_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
                || o[0] == 0
                || (o[0] == 100 && (64..128).contains(&o[1])) // CGNAT
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19)) // benchmarking
                || o[0] >= 240
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_internal_ip(IpAddr::V4(v4));
            }
            let s = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // ULA
                || (s[0] & 0xffc0) == 0xfe80 // link local
                || s[0] == 0x2001 && s[1] == 0x0db8 // documentation
        }
    }
}

fn normalize_hash(v: &str) -> Option<String> {
    let v = v.trim().to_ascii_lowercase();
    (matches!(v.len(), 32 | 40 | 64) && v.bytes().all(|b| b.is_ascii_hexdigit())).then_some(v)
}

fn normalize_domain(v: &str) -> Result<String, ArtifactError> {
    let d = v.trim().trim_end_matches('.').to_ascii_lowercase();
    let ok = !d.is_empty()
        && d.len() <= 253
        && d.contains('.')
        && d.split('.').all(|l| {
            !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-') && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
        // A TLD is never all digits (that is an IP).
        && !d.rsplit('.').next().unwrap_or_default().bytes().all(|b| b.is_ascii_digit());
    if !ok {
        return Err(ArtifactError::Invalid(truncate(v, 80), "domain"));
    }
    if INTERNAL_SUFFIXES.iter().any(|s| d.ends_with(s) || d == s[1..]) {
        return Err(ArtifactError::Internal("this domain"));
    }
    Ok(d)
}

fn normalize_ip(v: &str) -> Result<String, ArtifactError> {
    let ip: IpAddr = v.trim().trim_start_matches('[').trim_end_matches(']').parse().map_err(|_| ArtifactError::Invalid(truncate(v, 80), "IP address"))?;
    if is_internal_ip(ip) {
        return Err(ArtifactError::Internal("a private or reserved address"));
    }
    Ok(ip.to_string())
}

fn normalize_url(v: &str) -> Result<String, ArtifactError> {
    let u = url::Url::parse(v.trim()).map_err(|_| ArtifactError::Invalid(truncate(v, 80), "URL"))?;
    if !matches!(u.scheme(), "http" | "https") {
        return Err(ArtifactError::Invalid(truncate(v, 80), "http(s) URL"));
    }
    match u.host() {
        Some(url::Host::Domain(d)) => {
            normalize_domain(d)?;
        }
        Some(url::Host::Ipv4(ip)) => {
            normalize_ip(&ip.to_string())?;
        }
        Some(url::Host::Ipv6(ip)) => {
            normalize_ip(&ip.to_string())?;
        }
        None => return Err(ArtifactError::Invalid(truncate(v, 80), "URL")),
    }
    if !u.username().is_empty() || u.password().is_some() {
        // Credentials in a URL are never forwarded to a third party.
        return Err(ArtifactError::Internal("a URL with embedded credentials"));
    }
    Ok(u.to_string())
}

impl Artifact {
    /// Validate and normalize. `kind` = `None` detects the type.
    pub fn parse(raw: &str, kind: Option<ArtifactType>) -> Result<Self, ArtifactError> {
        let raw = raw.trim();
        if raw.is_empty() || raw.len() > MAX_ARTIFACT_LEN || raw.chars().any(char::is_control) {
            return Err(ArtifactError::Shape);
        }
        let kind = match kind {
            Some(k) => k,
            None => Self::detect(raw).ok_or(ArtifactError::Undetected)?,
        };
        let value = match kind {
            ArtifactType::Hash => normalize_hash(raw).ok_or_else(|| ArtifactError::Invalid(truncate(raw, 80), "MD5/SHA-1/SHA-256 hash"))?,
            ArtifactType::Domain => normalize_domain(raw)?,
            ArtifactType::Ip => normalize_ip(raw)?,
            ArtifactType::Url => normalize_url(raw)?,
        };
        Ok(Self { kind, value })
    }

    pub fn detect(raw: &str) -> Option<ArtifactType> {
        let raw = raw.trim();
        if normalize_hash(raw).is_some() {
            return Some(ArtifactType::Hash);
        }
        if raw.trim_start_matches('[').trim_end_matches(']').parse::<IpAddr>().is_ok() {
            return Some(ArtifactType::Ip);
        }
        if raw.contains("://") {
            return Some(ArtifactType::Url);
        }
        if raw.contains('.') && !raw.contains('/') && !raw.contains(' ') {
            return Some(ArtifactType::Domain);
        }
        None
    }

    /// The `input.*` template values a spec may read.
    pub fn template_input(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("artifact".into(), Value::String(self.value.clone()));
        m.insert("artifact_type".into(), Value::String(self.kind.as_str().into()));
        // VirusTotal URL ids: unpadded base64url of the URL.
        m.insert("artifact_b64url".into(), Value::String(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.value.as_bytes())));
        // For query strings in links (templates do not encode).
        m.insert("artifact_q".into(), Value::String(utf8_percent_encode(&self.value, NON_ALPHANUMERIC).to_string()));
        m
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max).collect();
    out.push('…');
    out
}

// ---------------------------------------------------------------------------
// Spec
// ---------------------------------------------------------------------------

/// One provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LookupSpec {
    pub version: u32,
    /// Slug, matching the marketplace catalog entry (e.g. `virustotal`).
    pub name: String,
    pub display_name: String,
    #[serde(default)]
    pub description: String,
    /// Where to get a key.
    #[serde(default)]
    pub homepage: Option<String>,
    pub allow: Vec<AllowRule>,
    #[serde(default)]
    pub auth: AuthConfig,
    /// Credential fields the tenant supplies (names match `auth`).
    #[serde(default)]
    pub credentials: Vec<CredentialField>,
    pub defaults: ProviderDefaults,
    /// Per artifact type: the request and its mapping. A type not listed is
    /// unsupported by this provider.
    pub types: BTreeMap<ArtifactType, TypeSpec>,
    /// HTTP statuses that mean "quota exhausted" (default 429).
    #[serde(default = "default_quota_status")]
    pub quota_status: Vec<u16>,
    /// HTTP statuses that mean "this artifact is unknown to the provider".
    #[serde(default = "default_not_found_status")]
    pub not_found_status: Vec<u16>,
}

fn default_quota_status() -> Vec<u16> {
    vec![429]
}
fn default_not_found_status() -> Vec<u16> {
    vec![404]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialField {
    pub name: String,
    pub label: String,
    #[serde(default = "yes")]
    pub required: bool,
}

fn yes() -> bool {
    true
}

/// Free-tier defaults. A tenant may lower them, or raise them up to the
/// platform ceilings for a paid key.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderDefaults {
    pub cache_ttl_secs: u64,
    pub per_minute: u32,
    pub per_day: u32,
}

/// Platform ceilings on tenant overrides.
pub const MAX_PER_MINUTE: u32 = 600;
pub const MAX_PER_DAY: u32 = 200_000;
pub const MIN_CACHE_TTL_SECS: u64 = 300;
pub const MAX_CACHE_TTL_SECS: u64 = 30 * 86_400;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypeSpec {
    pub request: RequestTemplate,
    pub result: ResultMapping,
    /// Link template (`{{input.*}}`, `{{item.*}}` = summary values).
    #[serde(default)]
    pub link: Option<String>,
    /// A body path holding a link (wins over `link` when present).
    #[serde(default)]
    pub link_path: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultMapping {
    #[serde(default)]
    pub score: Option<ScoreSpec>,
    /// First matching rule wins.
    #[serde(default)]
    pub rules: Vec<Rule>,
    /// Applied when no rule matched and a score was computed.
    #[serde(default)]
    pub thresholds: Option<Thresholds>,
    /// When nothing else decided.
    #[serde(default = "unknown_verdict")]
    pub default_verdict: Verdict,
    /// Summary facts: name -> dotted body path.
    #[serde(default)]
    pub summary: BTreeMap<String, String>,
    /// Paths of string or string-array values collected as tags.
    #[serde(default)]
    pub tags: Vec<String>,
}

fn unknown_verdict() -> Verdict {
    Verdict::Unknown
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScoreSpec {
    /// A 0-100 number in the body.
    #[serde(default)]
    pub path: Option<String>,
    /// `100 * sum(weight * numerator) / sum(denominator)`.
    #[serde(default)]
    pub ratio: Option<Ratio>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ratio {
    pub numerator: Vec<Weighted>,
    pub denominator: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Weighted {
    pub path: String,
    #[serde(default = "one")]
    pub weight: f64,
}

fn one() -> f64 {
    1.0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// Every condition must hold.
    pub when: Vec<Condition>,
    pub verdict: Verdict,
    /// Overrides the computed score.
    #[serde(default)]
    pub score: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Condition {
    pub path: String,
    #[serde(default)]
    pub equals: Option<Value>,
    #[serde(default, rename = "in")]
    pub one_of: Option<Vec<Value>>,
    #[serde(default)]
    pub gte: Option<f64>,
    #[serde(default)]
    pub lt: Option<f64>,
    /// Array contains this value, or string contains this substring
    /// (case-insensitive).
    #[serde(default)]
    pub contains: Option<Value>,
    /// Present and not null / empty string / empty array / empty object
    /// (`true`), or the opposite (`false`).
    #[serde(default)]
    pub non_empty: Option<bool>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Thresholds {
    #[serde(default)]
    pub malicious: Option<f64>,
    #[serde(default)]
    pub suspicious: Option<f64>,
    /// Verdict below every threshold (default `benign`).
    #[serde(default = "benign_verdict")]
    pub below: Verdict,
}

fn benign_verdict() -> Verdict {
    Verdict::Benign
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Malicious,
    Suspicious,
    Benign,
    #[default]
    Unknown,
    NotFound,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Malicious => "malicious",
            Self::Suspicious => "suspicious",
            Self::Benign => "benign",
            Self::Unknown => "unknown",
            Self::NotFound => "not_found",
        }
    }
    /// Severity order for a combined verdict (worst first).
    pub fn severity(self) -> u8 {
        match self {
            Self::Malicious => 4,
            Self::Suspicious => 3,
            Self::Benign => 1,
            Self::Unknown => 2,
            Self::NotFound => 0,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LookupSpecError {
    #[error("lookup spec is not valid YAML: {0}")]
    Yaml(String),
    #[error("lookup spec `{0}`: {1}")]
    Invalid(String, String),
}

impl LookupSpec {
    pub fn from_yaml(text: &str) -> Result<Self, LookupSpecError> {
        let spec: Self = serde_yaml::from_str(text).map_err(|e| LookupSpecError::Yaml(e.to_string()))?;
        spec.validate()?;
        Ok(spec)
    }

    pub fn validate(&self) -> Result<(), LookupSpecError> {
        let bad = |m: String| LookupSpecError::Invalid(self.name.clone(), m);
        if self.version != LOOKUP_SPEC_VERSION {
            return Err(bad(format!("version must be {LOOKUP_SPEC_VERSION}")));
        }
        if self.name.is_empty() || !self.name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_') {
            return Err(bad("name must be a lowercase slug".into()));
        }
        if self.types.is_empty() {
            return Err(bad("at least one artifact type is required".into()));
        }
        let d = self.defaults;
        if d.per_minute == 0 || d.per_minute > MAX_PER_MINUTE || d.per_day == 0 || d.per_day > MAX_PER_DAY {
            return Err(bad("defaults.per_minute / per_day are out of range".into()));
        }
        if !(MIN_CACHE_TTL_SECS..=MAX_CACHE_TTL_SECS).contains(&d.cache_ttl_secs) {
            return Err(bad("defaults.cache_ttl_secs is out of range".into()));
        }
        // Lookup specs name fixed vendor hosts: no templated allow hosts.
        if self.allow.is_empty() || self.allow.iter().any(|r| r.host.as_deref().is_none_or(|h| h.is_empty() || h.contains("{{"))) {
            return Err(bad("allow must list literal hosts".into()));
        }
        for (t, ts) in &self.types {
            // The request host is literal and allowlisted up front, so a spec
            // can never be loaded that points anywhere else (the engine
            // re-checks every request at run time).
            let url = &ts.request.url;
            let rest = url.strip_prefix("https://").ok_or_else(|| bad(format!("{}: request url must be https", t.as_str())))?;
            let (host, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
            let literal_path = &path[..path.find("{{").unwrap_or(path.len())];
            let allowed = self.allow.iter().any(|r| {
                r.host.as_deref() == Some(host)
                    && (r.path_prefixes.is_empty()
                        || r.path_prefixes.iter().any(|p| literal_path == p.as_str() || literal_path.starts_with(&format!("{}/", p.trim_end_matches('/')))))
            });
            if host.contains("{{") || !allowed {
                return Err(bad(format!("{}: request url is not on the allowlist", t.as_str())));
            }
            // Compiling also checks templates, allowlist and auth.
            let spec = self.connector_spec(*t).map_err(|e| bad(format!("{}: {e}", t.as_str())))?;
            engine::compile(&spec, &engine::default_ceilings()).map_err(|e| bad(format!("{}: {e}", t.as_str())))?;
            if let Some(link) = &ts.link {
                template::references(link).map_err(|e| bad(format!("{} link: {e}", t.as_str())))?;
            }
            if let Some(s) = &ts.result.score {
                if s.path.is_some() == s.ratio.is_some() {
                    return Err(bad(format!("{}: score needs exactly one of path or ratio", t.as_str())));
                }
            }
        }
        Ok(())
    }

    pub fn supports(&self, t: ArtifactType) -> bool {
        self.types.contains_key(&t)
    }

    pub fn supported_types(&self) -> Vec<ArtifactType> {
        self.types.keys().copied().collect()
    }

    /// The single-request `agent_enrichment` connector spec for one type.
    pub fn connector_spec(&self, t: ArtifactType) -> Result<ConnectorSpec, String> {
        let ts = self.types.get(&t).ok_or_else(|| format!("{} does not look up {}", self.name, t.as_str()))?;
        let v = json!({
            "version": 1,
            "name": format!("{}_{}", self.name, t.as_str()),
            "kind": "agent_enrichment",
            "allow": self.allow,
            "auth": self.auth,
            "limits": {
                "max_run_secs": 20, "max_pages": 1, "max_requests": 3, "max_events": 1,
                "max_event_bytes": 8 * 1024 * 1024, "max_response_bytes": 4 * 1024 * 1024,
                "max_decompressed_bytes": 8 * 1024 * 1024, "vrl_timeout_ms": 1000, "max_redirects": 2,
                "max_checkpoint_bytes": 1024 * 1024, "max_identity_memberships": 1
            },
            // A 429 is the quota answer, never retried: the tenant's limiter
            // and the caller decide what happens next.
            "rate_limit": { "min_interval_ms": 0, "max_retries_429": 0, "max_retries_5xx": 1, "backoff_ms": 500, "max_wait_ms": 2000, "remaining_floor": 0 },
            "streams": [{ "id": "lookup", "request": ts.request }],
        });
        serde_json::from_value(v).map_err(|e| e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Official specs
// ---------------------------------------------------------------------------

const OFFICIAL: &[(&str, &str)] = &[
    ("virustotal", include_str!("../lookups/virustotal.yaml")),
    ("abuseipdb", include_str!("../lookups/abuseipdb.yaml")),
    ("greynoise", include_str!("../lookups/greynoise.yaml")),
    ("urlhaus", include_str!("../lookups/urlhaus.yaml")),
    ("threatfox", include_str!("../lookups/threatfox.yaml")),
    ("malwarebazaar", include_str!("../lookups/malwarebazaar.yaml")),
    ("shodan", include_str!("../lookups/shodan.yaml")),
];

/// The official lookup specs, parsed and validated once. A spec that fails
/// to parse is a build defect (covered by tests) and is left out.
pub fn official_specs() -> &'static [Arc<LookupSpec>] {
    static SPECS: OnceLock<Vec<Arc<LookupSpec>>> = OnceLock::new();
    SPECS.get_or_init(|| {
        OFFICIAL
            .iter()
            .filter_map(|(name, text)| match LookupSpec::from_yaml(text) {
                Ok(s) if s.name == *name => Some(Arc::new(s)),
                Ok(s) => {
                    tracing::error!(target: "nano_connector::lookup", expected = name, got = %s.name, "official lookup spec name mismatch");
                    None
                }
                Err(e) => {
                    tracing::error!(target: "nano_connector::lookup", spec = name, error = %e, "official lookup spec is invalid");
                    None
                }
            })
            .collect()
    })
}

pub fn official_spec(name: &str) -> Option<Arc<LookupSpec>> {
    official_specs().iter().find(|s| s.name == name).cloned()
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

/// A provider's normalized answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LookupVerdict {
    pub verdict: Verdict,
    /// 0-100, when the provider gives a basis for one.
    pub score: Option<u8>,
    pub link: Option<String>,
    pub tags: Vec<String>,
    pub summary: Map<String, Value>,
}

fn num(v: Option<&Value>) -> Option<f64> {
    match v? {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse().ok(),
        Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        _ => None,
    }
}

fn non_empty(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(m)) => !m.is_empty(),
        Some(_) => true,
    }
}

fn loose_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::String(x), Value::String(y)) => x.eq_ignore_ascii_case(y),
        (Value::Number(_), _) | (_, Value::Number(_)) => num(Some(a)).zip(num(Some(b))).is_some_and(|(x, y)| (x - y).abs() < f64::EPSILON),
        _ => a == b,
    }
}

impl Condition {
    fn holds(&self, body: &Value) -> bool {
        let v = get_path(body, &self.path);
        if let Some(want) = &self.equals {
            if !v.is_some_and(|v| loose_eq(v, want)) {
                return false;
            }
        }
        if let Some(set) = &self.one_of {
            if !v.is_some_and(|v| set.iter().any(|w| loose_eq(v, w))) {
                return false;
            }
        }
        if let Some(g) = self.gte {
            if !num(v).is_some_and(|n| n >= g) {
                return false;
            }
        }
        if let Some(l) = self.lt {
            if !num(v).is_some_and(|n| n < l) {
                return false;
            }
        }
        if let Some(c) = &self.contains {
            let hit = match (v, c) {
                (Some(Value::Array(a)), _) => a.iter().any(|x| loose_eq(x, c)),
                (Some(Value::String(s)), Value::String(n)) => s.to_ascii_lowercase().contains(&n.to_ascii_lowercase()),
                _ => false,
            };
            if !hit {
                return false;
            }
        }
        if let Some(want) = self.non_empty {
            if non_empty(v) != want {
                return false;
            }
        }
        true
    }
}

fn compute_score(spec: &ScoreSpec, body: &Value) -> Option<f64> {
    if let Some(p) = &spec.path {
        return num(get_path(body, p));
    }
    let r = spec.ratio.as_ref()?;
    let den: f64 = r.denominator.iter().filter_map(|p| num(get_path(body, p))).sum();
    if den <= 0.0 {
        return None;
    }
    let n: f64 = r.numerator.iter().filter_map(|w| num(get_path(body, &w.path)).map(|x| x * w.weight)).sum();
    Some(100.0 * n / den)
}

fn clamp_summary(v: &Value) -> Value {
    match v {
        Value::String(s) => Value::String(truncate(s, MAX_SUMMARY_STRING)),
        Value::Array(a) => Value::Array(a.iter().take(MAX_SUMMARY_ITEMS).map(clamp_summary).collect()),
        Value::Object(m) => {
            // Objects become their keys (e.g. VirusTotal categories): bounded
            // and never a nested blob.
            Value::Array(m.keys().take(MAX_SUMMARY_ITEMS).map(|k| Value::String(truncate(k, MAX_SUMMARY_STRING))).collect())
        }
        other => other.clone(),
    }
}

/// Apply a type's mapping to a 2xx body.
pub fn evaluate(ts: &TypeSpec, artifact: &Artifact, body: &Value) -> LookupVerdict {
    let m = &ts.result;
    let mut score = m.score.as_ref().and_then(|s| compute_score(s, body));
    let rule = m.rules.iter().find(|r| r.when.iter().all(|c| c.holds(body)));
    let verdict = match rule {
        Some(r) => {
            if let Some(s) = r.score {
                score = Some(f64::from(s));
            }
            r.verdict
        }
        None => match (score, m.thresholds) {
            (Some(s), Some(t)) => {
                if t.malicious.is_some_and(|x| s >= x) {
                    Verdict::Malicious
                } else if t.suspicious.is_some_and(|x| s >= x) {
                    Verdict::Suspicious
                } else {
                    t.below
                }
            }
            _ => m.default_verdict,
        },
    };
    let score = score.map(|s| s.round().clamp(0.0, 100.0) as u8);

    let mut summary = Map::new();
    for (k, p) in &m.summary {
        if let Some(v) = get_path(body, p).filter(|v| !v.is_null()) {
            summary.insert(k.clone(), clamp_summary(v));
        }
    }
    let mut tags: Vec<String> = Vec::new();
    for p in &m.tags {
        let mut push = |s: &str| {
            let s = truncate(s.trim(), 64);
            if !s.is_empty() && tags.len() < MAX_TAGS && !tags.iter().any(|t| t.eq_ignore_ascii_case(&s)) {
                tags.push(s);
            }
        };
        match get_path(body, p) {
            Some(Value::String(s)) => push(s),
            Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).for_each(&mut push),
            _ => {}
        }
    }

    let link = ts
        .link_path
        .as_deref()
        .and_then(|p| get_path(body, p))
        .and_then(Value::as_str)
        .filter(|s| s.starts_with("https://"))
        .map(|s| truncate(s, 512))
        .or_else(|| render_link(ts.link.as_deref()?, artifact, &summary));
    LookupVerdict { verdict, score, link, tags, summary }
}

fn render_link(t: &str, artifact: &Artifact, summary: &Map<String, Value>) -> Option<String> {
    if t.is_empty() {
        return None;
    }
    let scope = Scope { input: Value::Object(artifact.template_input()), item: Value::Object(summary.clone()), ..Default::default() };
    // A reference that resolves empty would leave a dangling link: none.
    for r in template::references(t).ok()? {
        let probe = template::render_str(&format!("{{{{{r}}}}}"), &scope).ok()?;
        if probe.is_empty() {
            return None;
        }
    }
    let s = template::render_str(t, &scope).ok()?;
    s.starts_with("https://").then(|| truncate(&s, 512))
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

/// What one provider answered for one artifact.
#[derive(Debug, Clone, PartialEq)]
pub enum LookupOutcome {
    /// A 2xx (or not-found status) answer, mapped.
    Answered(LookupVerdict),
    /// The provider refused for quota (HTTP 429 or a configured status).
    QuotaExhausted { retry_after_secs: Option<u64> },
    /// 401/403: the configured credential is wrong or lacks access.
    AuthFailed,
    /// The provider does not look up this artifact type.
    Unsupported,
    /// Anything else (network, 5xx, policy). The message is secret-free.
    Failed(String),
}

fn not_found(ts: &TypeSpec, artifact: &Artifact) -> LookupVerdict {
    LookupVerdict { verdict: Verdict::NotFound, score: None, link: render_link(ts.link.as_deref().unwrap_or_default(), artifact, &Map::new()), tags: vec![], summary: Map::new() }
}

/// Run one lookup through the connector engine.
pub async fn execute(cfg: &EngineConfig, spec: &LookupSpec, artifact: &Artifact, credentials: HashMap<String, String>, tenant: Option<String>) -> LookupOutcome {
    let Some(ts) = spec.types.get(&artifact.kind) else {
        return LookupOutcome::Unsupported;
    };
    let cs = match spec.connector_spec(artifact.kind) {
        Ok(cs) => cs,
        Err(e) => return LookupOutcome::Failed(format!("spec: {e}")),
    };
    // Secret values, to scrub from any error text that reaches the caller.
    let secrets: Vec<String> = credentials.values().filter(|v| v.len() >= 4).cloned().collect();
    let input = RunInput {
        credentials: Credentials::new(credentials),
        artifact: Some((artifact.value.clone(), artifact.kind.as_str().to_string())),
        artifact_extra: artifact.template_input(),
        tenant,
        ..Default::default()
    };
    let out = engine::run(cfg, &cs, input, Arc::new(MemorySink::default()), Arc::new(MemoryStore::default())).await;
    match out {
        Ok(o) => {
            let body = o.result.unwrap_or(Value::Null);
            if body.is_null() {
                return LookupOutcome::Answered(not_found(ts, artifact));
            }
            LookupOutcome::Answered(evaluate(ts, artifact, &body))
        }
        Err(EngineError::Upstream { status, .. }) if spec.quota_status.contains(&status) => LookupOutcome::QuotaExhausted { retry_after_secs: None },
        Err(EngineError::Upstream { status, .. }) if spec.not_found_status.contains(&status) => LookupOutcome::Answered(not_found(ts, artifact)),
        Err(EngineError::Upstream { status: 401 | 403, .. }) => LookupOutcome::AuthFailed,
        Err(EngineError::Upstream { status, .. }) => LookupOutcome::Failed(format!("provider returned HTTP {status}")),
        Err(EngineError::Auth(e)) => LookupOutcome::Failed(scrub(&format!("credential: {e}"), &secrets)),
        Err(e) => LookupOutcome::Failed(scrub(&e.to_string(), &secrets)),
    }
}

/// Error text for callers, audit and the notebook: query strings dropped
/// (a key may ride in one, e.g. Shodan `?key=`), any credential value
/// redacted, length capped.
fn scrub(message: &str, secrets: &[String]) -> String {
    let mut out = String::with_capacity(message.len());
    let mut in_query = false;
    for c in message.chars() {
        if in_query {
            if c.is_whitespace() || matches!(c, ')' | '"' | '\'' | ',' | ';') {
                in_query = false;
                out.push(c);
            }
            continue;
        }
        if c == '?' {
            in_query = true;
            out.push_str("?…");
            continue;
        }
        out.push(c);
    }
    for secret in secrets {
        out = out.replace(secret.as_str(), "[redacted]");
    }
    truncate(&out, 200)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::preview::{Recorded, ReplayTransport};

    fn cfg_with(entries: Vec<Recorded>) -> (EngineConfig, Arc<ReplayTransport>) {
        let t = Arc::new(ReplayTransport::new(entries));
        let mut cfg = EngineConfig::with_sandbox(
            std::path::PathBuf::from("/nonexistent"),
            crate::sandbox::SandboxPolicy::strict(),
            crate::vrl_exec::PoolConfig::default(),
        );
        cfg.transport = Some(t.clone());
        (cfg, t)
    }

    fn rec(host: &str, path: &str, status: u16, body: Value) -> Recorded {
        serde_json::from_value(json!({"host": host, "path": path, "status": status, "body": body})).unwrap()
    }

    fn creds(k: &str) -> HashMap<String, String> {
        HashMap::from([(k.to_string(), "test-key-0123456789".to_string())])
    }

    #[test]
    fn every_official_spec_parses_compiles_and_matches_its_name() {
        let names: Vec<&str> = official_specs().iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, OFFICIAL.iter().map(|(n, _)| *n).collect::<Vec<_>>(), "a shipped spec failed to load");
        for s in official_specs() {
            for t in s.supported_types() {
                let cs = s.connector_spec(t).unwrap();
                assert!(cs.streams.iter().all(|st| st.program.is_none()), "{}: lookup specs never carry VRL", s.name);
                engine::compile(&cs, &engine::default_ceilings()).unwrap();
            }
        }
        let vt = official_spec("virustotal").unwrap();
        assert_eq!(vt.supported_types(), vec![ArtifactType::Hash, ArtifactType::Domain, ArtifactType::Ip, ArtifactType::Url]);
        assert_eq!((vt.defaults.per_minute, vt.defaults.per_day), (4, 500));
        assert_eq!(official_spec("abuseipdb").unwrap().supported_types(), vec![ArtifactType::Ip]);
        assert_eq!(official_spec("malwarebazaar").unwrap().supported_types(), vec![ArtifactType::Hash]);
    }

    #[test]
    fn artifacts_are_normalized_and_internal_values_refused() {
        assert_eq!(Artifact::parse(" 44D88612FEA8A8F36DE82E1278ABB02F ", None).unwrap(), Artifact { kind: ArtifactType::Hash, value: "44d88612fea8a8f36de82e1278abb02f".into() });
        assert_eq!(Artifact::parse("Evil.Example.COM.", None).unwrap().value, "evil.example.com");
        assert_eq!(Artifact::parse("8.8.8.8", None).unwrap().kind, ArtifactType::Ip);
        assert_eq!(Artifact::parse("http://evil.example.com/a b", None).unwrap().value, "http://evil.example.com/a%20b");
        for internal in ["10.1.2.3", "192.168.0.1", "127.0.0.1", "::1", "fd00::1", "100.64.1.1", "169.254.169.254", "::ffff:10.0.0.1"] {
            assert!(matches!(Artifact::parse(internal, Some(ArtifactType::Ip)), Err(ArtifactError::Internal(_))), "{internal}");
        }
        for internal in ["dc01.corp", "printer.local", "metadata.google.internal", "host.home.arpa"] {
            assert!(matches!(Artifact::parse(internal, Some(ArtifactType::Domain)), Err(ArtifactError::Internal(_))), "{internal}");
        }
        assert!(matches!(Artifact::parse("http://10.0.0.5/x", None), Err(ArtifactError::Internal(_))));
        assert!(matches!(Artifact::parse("https://user:pw@evil.example.com/", None), Err(ArtifactError::Internal(_))));
        assert!(Artifact::parse("not a thing", None).is_err());
        assert!(Artifact::parse("abc", Some(ArtifactType::Hash)).is_err());
        assert!(Artifact::parse("ftp://x.example.com/", None).is_err());
        assert!(Artifact::parse(&"a".repeat(3000), None).is_err());
    }

    #[tokio::test]
    async fn virustotal_hash_is_mapped_and_cited() {
        let body = json!({"data": {"attributes": {
            "last_analysis_stats": {"malicious": 60, "suspicious": 0, "undetected": 10, "harmless": 0},
            "tags": ["eicar"], "reputation": -50, "type_description": "Text",
            "popular_threat_classification": {"suggested_threat_label": "eicar/test"}, "names": ["eicar.com"]
        }}});
        let (cfg, t) = cfg_with(vec![rec("www.virustotal.com", "/api/v3/files/44d88612fea8a8f36de82e1278abb02f", 200, body)]);
        let vt = official_spec("virustotal").unwrap();
        let a = Artifact::parse("44d88612fea8a8f36de82e1278abb02f", None).unwrap();
        let LookupOutcome::Answered(v) = execute(&cfg, &vt, &a, creds("API_KEY"), None).await else { panic!() };
        assert_eq!(v.verdict, Verdict::Malicious);
        assert_eq!(v.score, Some(86));
        assert_eq!(v.link.as_deref(), Some("https://www.virustotal.com/gui/file/44d88612fea8a8f36de82e1278abb02f"));
        assert_eq!(v.summary["threat_label"], "eicar/test");
        assert!(v.tags.contains(&"eicar".to_string()));
        assert_eq!(t.log.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn virustotal_url_uses_the_unpadded_base64url_id() {
        let url = "http://evil.example.com/payload";
        let id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(url);
        let body = json!({"data": {"id": "abc123", "attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0, "undetected": 5, "harmless": 60}}}});
        let (cfg, _) = cfg_with(vec![rec("www.virustotal.com", &format!("/api/v3/urls/{id}"), 200, body)]);
        let a = Artifact::parse(url, None).unwrap();
        let LookupOutcome::Answered(v) = execute(&cfg, &official_spec("virustotal").unwrap(), &a, creds("API_KEY"), None).await else { panic!() };
        assert_eq!((v.verdict, v.score), (Verdict::Benign, Some(0)));
        assert_eq!(v.link.as_deref(), Some("https://www.virustotal.com/gui/url/abc123"));
    }

    #[tokio::test]
    async fn not_found_quota_and_auth_statuses_are_distinct_outcomes() {
        let vt = official_spec("virustotal").unwrap();
        let a = Artifact::parse("44d88612fea8a8f36de82e1278abb02f", None).unwrap();
        let path = "/api/v3/files/44d88612fea8a8f36de82e1278abb02f";
        let (cfg, _) = cfg_with(vec![rec("www.virustotal.com", path, 404, json!({"error": {"code": "NotFoundError"}}))]);
        let LookupOutcome::Answered(v) = execute(&cfg, &vt, &a, creds("API_KEY"), None).await else { panic!() };
        assert_eq!(v.verdict, Verdict::NotFound);
        assert!(v.link.is_some());

        let (cfg, t) = cfg_with(vec![rec("www.virustotal.com", path, 429, json!({"error": {"code": "QuotaExceededError"}}))]);
        assert_eq!(execute(&cfg, &vt, &a, creds("API_KEY"), None).await, LookupOutcome::QuotaExhausted { retry_after_secs: None });
        assert_eq!(t.log.lock().unwrap().len(), 1, "a 429 is never retried");

        let (cfg, _) = cfg_with(vec![rec("www.virustotal.com", path, 401, json!({"error": {"code": "WrongCredentialsError"}}))]);
        assert_eq!(execute(&cfg, &vt, &a, creds("API_KEY"), None).await, LookupOutcome::AuthFailed);

        // Missing credential: refused before any request.
        let (cfg, t) = cfg_with(vec![]);
        assert!(matches!(execute(&cfg, &vt, &a, HashMap::new(), None).await, LookupOutcome::Failed(_)));
        assert!(t.log.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn every_provider_maps_a_recorded_answer() {
        let ip = Artifact::parse("185.220.101.1", None).unwrap();
        let cases: Vec<(&str, &str, Artifact, Recorded, Verdict, Option<u8>)> = vec![
            ("abuseipdb", "API_KEY", ip.clone(),
                rec("api.abuseipdb.com", "/api/v2/check", 200, json!({"data": {"abuseConfidenceScore": 100, "totalReports": 900, "isWhitelisted": false, "countryCode": "DE"}})),
                Verdict::Malicious, Some(100)),
            ("greynoise", "API_KEY", ip.clone(),
                rec("api.greynoise.io", "/v3/community/185.220.101.1", 200, json!({"ip": "185.220.101.1", "noise": true, "riot": false, "classification": "malicious", "name": "unknown", "link": "https://viz.greynoise.io/ip/185.220.101.1"})),
                Verdict::Malicious, Some(90)),
            ("shodan", "API_KEY", ip.clone(),
                rec("api.shodan.io", "/shodan/host/185.220.101.1", 200, json!({"org": "Tor", "ports": [80, 443], "vulns": ["CVE-2021-44228"], "tags": []})),
                Verdict::Suspicious, Some(40)),
            ("threatfox", "AUTH_KEY", ip.clone(),
                rec("threatfox-api.abuse.ch", "/api/v1/", 200, json!({"query_status": "ok", "data": [{"threat_type": "botnet_cc", "malware_printable": "Cobalt Strike", "confidence_level": 100, "tags": ["c2"]}]})),
                Verdict::Malicious, Some(100)),
            ("urlhaus", "AUTH_KEY", Artifact::parse("http://evil.example.com/x.exe", None).unwrap(),
                rec("urlhaus-api.abuse.ch", "/v1/url/", 200, json!({"query_status": "ok", "url_status": "online", "threat": "malware_download", "urlhaus_reference": "https://urlhaus.abuse.ch/url/1/", "tags": ["exe"]})),
                Verdict::Malicious, Some(95)),
            ("malwarebazaar", "AUTH_KEY", Artifact::parse(&"a".repeat(64), None).unwrap(),
                rec("mb-api.abuse.ch", "/api/v1/", 200, json!({"query_status": "ok", "data": [{"sha256_hash": "a".repeat(64), "signature": "AgentTesla", "tags": ["exe"]}]})),
                Verdict::Malicious, Some(95)),
        ];
        for (name, cred, art, r, want, score) in cases {
            let (cfg, _) = cfg_with(vec![r]);
            let spec = official_spec(name).unwrap();
            let out = execute(&cfg, &spec, &art, creds(cred), None).await;
            let LookupOutcome::Answered(v) = out else { panic!("{name}: {out:?}") };
            assert_eq!((v.verdict, v.score), (want, score), "{name}");
            assert!(v.link.as_deref().is_some_and(|l| l.starts_with("https://")), "{name} has a citation link");
        }
        // abuse.ch "no result" bodies are 200s, mapped to not_found.
        let (cfg, _) = cfg_with(vec![rec("mb-api.abuse.ch", "/api/v1/", 200, json!({"query_status": "hash_not_found"}))]);
        let LookupOutcome::Answered(v) = execute(&cfg, &official_spec("malwarebazaar").unwrap(), &Artifact::parse(&"b".repeat(64), None).unwrap(), creds("AUTH_KEY"), None).await else { panic!() };
        assert_eq!(v.verdict, Verdict::NotFound);
        assert_eq!(v.link, None, "no sha256 in a not-found answer, so no dangling link");
    }

    #[tokio::test]
    async fn greynoise_runs_keyless_and_never_leaks_the_key_into_logs() {
        let (cfg, t) = cfg_with(vec![rec("api.greynoise.io", "/v3/community/1.1.1.1", 200, json!({"riot": true, "classification": "benign", "name": "Cloudflare"}))]);
        let a = Artifact::parse("1.1.1.1", None).unwrap();
        let LookupOutcome::Answered(v) = execute(&cfg, &official_spec("greynoise").unwrap(), &a, HashMap::new(), None).await else { panic!() };
        assert_eq!(v.verdict, Verdict::Benign);
        // Shodan puts its key in the query: the replay log keeps names only.
        let (cfg, t2) = cfg_with(vec![rec("api.shodan.io", "/shodan/host/1.1.1.1", 404, json!({"error": "No information available for that IP."}))]);
        let LookupOutcome::Answered(v) = execute(&cfg, &official_spec("shodan").unwrap(), &a, creds("API_KEY"), None).await else { panic!() };
        assert_eq!(v.verdict, Verdict::NotFound);
        let log = t2.log.lock().unwrap().join(" ");
        assert!(log.contains("key") && !log.contains("test-key-0123456789"), "{log}");
        drop(t);
    }

    #[test]
    fn error_text_never_carries_a_key_or_query() {
        let m = scrub("error sending request for url (https://api.shodan.io/shodan/host/1.1.1.1?key=SECRETKEY123) timed out", &["SECRETKEY123".into()]);
        assert!(!m.contains("SECRETKEY123") && !m.contains("key="), "{m}");
        assert!(m.contains("api.shodan.io/shodan/host/1.1.1.1?…)"), "{m}");
        assert_eq!(scrub("header carried tok-abcdef", &["tok-abcdef".into()]), "header carried [redacted]");
    }

    #[test]
    fn spec_validation_refuses_bad_specs() {
        let base = include_str!("../lookups/abuseipdb.yaml");
        // Host outside the allowlist.
        let bad = base.replace("url: \"https://api.abuseipdb.com/api/v2/check\"", "url: \"https://evil.example.com/api/v2/check\"");
        assert!(LookupSpec::from_yaml(&bad).is_err());
        // Credentials can never be templated.
        let bad = base.replace("ipAddress: \"{{input.artifact}}\"", "ipAddress: \"{{credentials.API_KEY}}\"");
        assert!(LookupSpec::from_yaml(&bad).is_err());
        // Limits above the platform ceiling.
        let bad = base.replace("per_minute: 30", "per_minute: 100000");
        assert!(LookupSpec::from_yaml(&bad).is_err());
        assert!(LookupSpec::from_yaml(base).is_ok());
    }

    #[test]
    fn conditions_and_thresholds() {
        let ts: TypeSpec = serde_yaml::from_str(r#"
request: { url: "https://x.example.com/a" }
result:
  score: { path: s }
  rules:
    - when: [{ path: tags, contains: C2 }]
      verdict: malicious
      score: 99
  thresholds: { malicious: 70, suspicious: 20 }
  summary: { big: blob }
"#).unwrap();
        let a = Artifact::parse("8.8.8.8", None).unwrap();
        assert_eq!(evaluate(&ts, &a, &json!({"s": 75})).verdict, Verdict::Malicious);
        assert_eq!(evaluate(&ts, &a, &json!({"s": "25"})).verdict, Verdict::Suspicious);
        assert_eq!(evaluate(&ts, &a, &json!({"s": 5})).verdict, Verdict::Benign);
        assert_eq!(evaluate(&ts, &a, &json!({})).verdict, Verdict::Unknown);
        let v = evaluate(&ts, &a, &json!({"s": 1, "tags": ["c2"], "blob": "x".repeat(10_000)}));
        assert_eq!((v.verdict, v.score), (Verdict::Malicious, Some(99)));
        assert!(v.summary["big"].as_str().unwrap().chars().count() <= MAX_SUMMARY_STRING + 1, "summary values are bounded");
    }
}
