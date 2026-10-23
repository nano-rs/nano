//! Outbound policy: which URLs a run may reach, and which IPs it may connect to.
//!
//! Two independent checks. The host/path allowlist comes from the spec (with
//! per-tenant hosts resolved from config at run start). The IP check is fixed:
//! only globally routable unicast addresses are reachable, whatever the
//! allowlist says.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::spec::AllowRule;
use crate::template::{self, Scope};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("URL is not valid: {0}")]
    BadUrl(String),
    #[error("only https is allowed (got {0})")]
    Scheme(String),
    #[error("host {0} is not in the connector allowlist")]
    HostNotAllowed(String),
    #[error("host {0} is denied by the tenant egress policy")]
    HostDenied(String),
    #[error("path {path} on {host} is outside the allowed prefixes")]
    PathNotAllowed { host: String, path: String },
    #[error("port {0} is not allowed")]
    Port(u16),
    #[error("URL carries userinfo")]
    Userinfo,
    #[error("URL exceeds {0} bytes")]
    UrlTooLong(usize),
    #[error("destination address {0} is not publicly routable")]
    IpBlocked(IpAddr),
    #[error("destination address {0} is denied by the egress policy")]
    IpDenied(IpAddr),
    #[error("host name {0} is reserved for internal use")]
    ReservedName(String),
    #[error("allow rule is invalid: {0}")]
    BadRule(String),
}

/// Longest URL the broker will send. Real vendor APIs stay far below this;
/// a longer URL is either a bug or an exfiltration attempt.
pub const MAX_URL_BYTES: usize = 8192;

/// A compiled allow rule: exact host (lowercased) or nothing, plus prefixes.
#[derive(Debug, Clone)]
pub struct HostRule {
    pub host: String,
    pub path_prefixes: Vec<String>,
}

/// An IP network, for deny lists (`10.0.0.0/8`, `fd00::/8`, `1.2.3.4`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    pub net: IpAddr,
    pub bits: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Result<Self, PolicyError> {
        let bad = || PolicyError::BadRule(format!("bad CIDR {s:?}"));
        let (ip, bits) = match s.trim().split_once('/') {
            Some((ip, b)) => (ip, Some(b.parse::<u8>().map_err(|_| bad())?)),
            None => (s.trim(), None),
        };
        let net: IpAddr = ip.parse().map_err(|_| bad())?;
        let max = if net.is_ipv4() { 32 } else { 128 };
        let bits = bits.unwrap_or(max);
        if bits > max {
            return Err(bad());
        }
        // `::ffff:10.0.0.0/104` is `10.0.0.0/8`: store mapped ranges as v4,
        // with the prefix rescaled.
        if let IpAddr::V6(v6) = net {
            if let (Some(v4), true) = (v6.to_ipv4_mapped(), bits >= 96) {
                return Ok(Self { net: IpAddr::V4(v4), bits: bits - 96 });
            }
        }
        Ok(Self { net, bits })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        // A v4 rule also matches the v4-mapped v6 form, and a v6 rule
        // covering the mapped space matches the v4 address.
        let ip = canonical(ip);
        let ip = match (self.net, ip) {
            (IpAddr::V6(_), IpAddr::V4(a)) => IpAddr::V6(a.to_ipv6_mapped()),
            _ => ip,
        };
        match (self.net, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                let mask = if self.bits == 0 { 0 } else { u32::MAX << (32 - u32::from(self.bits.min(32))) };
                u32::from(n) & mask == u32::from(a) & mask
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                let mask = if self.bits == 0 { 0 } else { u128::MAX << (128 - u32::from(self.bits.min(128))) };
                u128::from(n) & mask == u128::from(a) & mask
            }
            _ => false,
        }
    }
}

fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

/// Egress the platform or a tenant forbids on top of every spec allowlist.
/// A deny always wins over a spec's `allow`.
#[derive(Debug, Clone, Default)]
pub struct EgressDeny {
    /// Exact host names (`api.vendor.com`) or label-aligned suffixes
    /// (`.vendor.com`, which also denies `vendor.com` itself).
    pub hosts: Vec<String>,
    /// Address ranges no connection may reach, checked on the resolved IP.
    /// The platform puts its own ranges here (cluster service CIDR, node
    /// public IPs, the ingest endpoint).
    pub cidrs: Vec<Cidr>,
}

impl EgressDeny {
    pub fn parse(hosts: &[&str], cidrs: &[&str]) -> Result<Self, PolicyError> {
        Ok(Self {
            hosts: hosts.iter().map(|h| h.trim().trim_end_matches('.').to_ascii_lowercase()).filter(|h| !h.is_empty() && h != ".").collect(),
            cidrs: cidrs.iter().filter(|c| !c.trim().is_empty()).map(|c| Cidr::parse(c)).collect::<Result<_, _>>()?,
        })
    }

    /// Union of two policies (platform + tenant).
    pub fn merged(&self, other: &EgressDeny) -> EgressDeny {
        let mut out = self.clone();
        out.hosts.extend(other.hosts.iter().cloned());
        out.cidrs.extend(other.cidrs.iter().copied());
        out
    }

    pub fn denies_host(&self, host: &str) -> bool {
        self.hosts.iter().any(|d| match d.strip_prefix('.') {
            Some(suffix) => host == suffix || host.ends_with(d.as_str()),
            None => host == d,
        })
    }

    pub fn denies_ip(&self, ip: IpAddr) -> bool {
        self.cidrs.iter().any(|c| c.contains(ip))
    }
}

/// The run's allowlist, after `{{config.X}}` hosts were resolved, plus the
/// platform and tenant deny lists.
#[derive(Debug, Clone, Default)]
pub struct HostPolicy {
    rules: Vec<HostRule>,
    deny: EgressDeny,
}

impl HostPolicy {
    /// Resolve spec rules against config. A templated host must resolve to a
    /// plain host name ending in one of the rule's suffixes.
    pub fn compile(rules: &[AllowRule], scope: &Scope) -> Result<Self, PolicyError> {
        let mut out = Vec::new();
        for r in rules {
            let raw = r
                .host
                .as_deref()
                .ok_or_else(|| PolicyError::BadRule("allow rule needs `host`".into()))?;
            let host = if raw.contains("{{") {
                let v = template::render_str(raw, scope)
                    .map_err(|e| PolicyError::BadRule(e.to_string()))?;
                let v = template::config_host(&v).map_err(|e| PolicyError::BadRule(e.to_string()))?;
                let v = v.trim_end_matches('.').to_ascii_lowercase();
                if r.host_suffixes.is_empty() {
                    return Err(PolicyError::BadRule(format!(
                        "templated host {raw} needs host_suffixes"
                    )));
                }
                for s in &r.host_suffixes {
                    // Label-aligned only: "okta.com" would admit "evilokta.com".
                    if !s.starts_with('.') || !is_plain_hostname(&s[1..].to_ascii_lowercase()) {
                        return Err(PolicyError::BadRule(format!(
                            "host suffix {s:?} must be a dot-prefixed host name, e.g. \".okta.com\""
                        )));
                    }
                }
                if !r
                    .host_suffixes
                    .iter()
                    .any(|s| v.ends_with(&s.to_ascii_lowercase()) && v.len() > s.len())
                {
                    return Err(PolicyError::HostNotAllowed(v));
                }
                v
            } else {
                raw.to_ascii_lowercase()
            };
            if !is_plain_hostname(&host) {
                return Err(PolicyError::BadRule(format!("{host:?} is not a host name")));
            }
            check_reserved_name(&host)?;
            let mut prefixes = r.path_prefixes.clone();
            if prefixes.is_empty() {
                prefixes.push("/".into());
            }
            for p in &prefixes {
                if !p.starts_with('/') || p.contains("..") || p.contains('%') || p.contains('\\') {
                    return Err(PolicyError::BadRule(format!("bad path prefix {p:?}")));
                }
            }
            out.push(HostRule {
                host,
                path_prefixes: prefixes,
            });
        }
        Ok(Self { rules: out, deny: EgressDeny::default() })
    }

    /// Apply a deny list. Fails if it removes every allowed host, so a
    /// tenant-denied connector is refused at run start, before any request.
    pub fn with_deny(mut self, deny: EgressDeny) -> Result<Self, PolicyError> {
        if let Some(r) = self.rules.iter().find(|r| deny.denies_host(&r.host)) {
            if self.rules.iter().all(|r| deny.denies_host(&r.host)) {
                return Err(PolicyError::HostDenied(r.host.clone()));
            }
        }
        self.deny = deny;
        Ok(self)
    }

    pub fn hosts(&self) -> impl Iterator<Item = &str> {
        self.rules.iter().map(|r| r.host.as_str())
    }

    /// Check a URL. Returns (host, port) on success.
    pub fn check(&self, url: &url::Url) -> Result<(String, u16), PolicyError> {
        if url.as_str().len() > MAX_URL_BYTES {
            return Err(PolicyError::UrlTooLong(MAX_URL_BYTES));
        }
        if url.scheme() != "https" {
            return Err(PolicyError::Scheme(url.scheme().to_string()));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(PolicyError::Userinfo);
        }
        let host = match url.host() {
            Some(url::Host::Domain(d)) => d.trim_end_matches('.').to_ascii_lowercase(),
            Some(url::Host::Ipv4(ip)) => {
                check_ip(IpAddr::V4(ip))?;
                return Err(PolicyError::HostNotAllowed(ip.to_string()));
            }
            Some(url::Host::Ipv6(ip)) => {
                check_ip(IpAddr::V6(ip))?;
                return Err(PolicyError::HostNotAllowed(ip.to_string()));
            }
            None => return Err(PolicyError::BadUrl("no host".into())),
        };
        let port = url.port().unwrap_or(443);
        if port != 443 {
            return Err(PolicyError::Port(port));
        }
        // The URL parser already applied IDNA; anything but a plain ASCII
        // name here (percent signs, underscores, a numeric TLD) is refused.
        if !is_plain_hostname(&host) {
            return Err(PolicyError::HostNotAllowed(host));
        }
        check_reserved_name(&host)?;
        if self.deny.denies_host(&host) {
            return Err(PolicyError::HostDenied(host));
        }
        let rule = self
            .rules
            .iter()
            .find(|r| r.host == host)
            .ok_or_else(|| PolicyError::HostNotAllowed(host.clone()))?;
        let path = url.path();
        // `url` already removed dot segments; refuse encoded separators or dots
        // a server might decode into a traversal after our prefix check, and
        // encoded control bytes a server might split a request line on.
        let lower = path.to_ascii_lowercase();
        if lower.contains("%2f")
            || lower.contains("%5c")
            || lower.contains("%2e")
            || lower.contains("%00")
            || lower.contains("%0d")
            || lower.contains("%0a")
            || path.contains('\\')
        {
            return Err(PolicyError::PathNotAllowed {
                host,
                path: path.to_string(),
            });
        }
        if !rule.path_prefixes.iter().any(|p| path_has_prefix(path, p)) {
            return Err(PolicyError::PathNotAllowed {
                host,
                path: path.to_string(),
            });
        }
        Ok((host, port))
    }

    /// The fixed IP check plus the deny CIDRs. Run on every resolved
    /// address before a connection is made.
    pub fn check_ip(&self, ip: IpAddr) -> Result<(), PolicyError> {
        check_ip(ip)?;
        if self.deny.denies_ip(ip) {
            return Err(PolicyError::IpDenied(ip));
        }
        Ok(())
    }
}

fn path_has_prefix(path: &str, prefix: &str) -> bool {
    if prefix == "/" {
        return true;
    }
    let p = prefix.trim_end_matches('/');
    path == p || path.starts_with(&format!("{p}/"))
}

/// Lowercase ASCII LDH labels, at least two of them, not an IP, no numeric
/// TLD (so `1.2.3.4`-like and `0x7f.1`-like names never pass as names).
pub fn is_plain_hostname(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && h.contains('.')
        && h.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
                && !l.starts_with('-')
                && !l.ends_with('-')
        })
        && h.parse::<IpAddr>().is_err()
        && !h.split('.').next_back().is_some_and(|tld| tld.chars().all(|c| c.is_ascii_digit()))
}

fn check_reserved_name(host: &str) -> Result<(), PolicyError> {
    const RESERVED_SUFFIXES: &[&str] = &[
        ".internal",
        ".local",
        ".localhost",
        ".localdomain",
        ".svc",
        ".cluster.local",
        ".home.arpa",
        ".in-addr.arpa",
        ".ip6.arpa",
        ".onion",
        ".test",
        ".invalid",
        ".lan",
        ".intranet",
        ".corp",
        ".private",
    ];
    let h = format!(".{host}");
    if host == "localhost"
        || host == "metadata"
        || RESERVED_SUFFIXES.iter().any(|s| h.ends_with(s))
    {
        return Err(PolicyError::ReservedName(host.to_string()));
    }
    Ok(())
}

/// Only globally routable unicast addresses pass.
pub fn check_ip(ip: IpAddr) -> Result<(), PolicyError> {
    let blocked = match ip {
        IpAddr::V4(v4) => v4_blocked(v4),
        IpAddr::V6(v6) => v6_blocked(v6),
    };
    if blocked {
        Err(PolicyError::IpBlocked(ip))
    } else {
        Ok(())
    }
}

/// IPv4 ranges that are never a vendor API. The list is the IANA special
/// registry plus cloud metadata addresses that sit in public space.
pub const V4_BLOCKED: &[([u8; 4], u32)] = &[
    ([0, 0, 0, 0], 8),         // "this" network
    ([10, 0, 0, 0], 8),        // RFC 1918
    ([100, 64, 0, 0], 10),     // CGNAT (incl. Alibaba metadata 100.100.100.200)
    ([127, 0, 0, 0], 8),       // loopback
    ([169, 254, 0, 0], 16),    // link-local, AWS/GCP/Azure metadata
    ([172, 16, 0, 0], 12),     // RFC 1918
    ([192, 0, 0, 0], 24),      // IETF protocol assignments (incl. Oracle 192.0.0.192)
    ([192, 0, 2, 0], 24),      // TEST-NET-1
    ([192, 31, 196, 0], 24),   // AS112-v4
    ([192, 52, 193, 0], 24),   // AMT
    ([192, 88, 99, 0], 24),    // 6to4 relay anycast
    ([192, 168, 0, 0], 16),    // RFC 1918
    ([192, 175, 48, 0], 24),   // AS112 direct delegation
    ([198, 18, 0, 0], 15),     // benchmarking
    ([198, 51, 100, 0], 24),   // TEST-NET-2
    ([203, 0, 113, 0], 24),    // TEST-NET-3
    ([168, 63, 129, 16], 32),  // Azure WireServer (public space, host-only)
    ([224, 0, 0, 0], 3),       // multicast, reserved, broadcast
];

fn v4_blocked(ip: Ipv4Addr) -> bool {
    let n = u32::from(ip);
    V4_BLOCKED.iter().any(|(base, bits)| {
        let mask = if *bits == 0 { 0 } else { u32::MAX << (32 - bits) };
        (n & mask) == (u32::from(Ipv4Addr::from(*base)) & mask)
    })
}

/// IPv6: only global unicast (2000::/3) passes, minus the special blocks
/// inside it. Everything that embeds an IPv4 address (mapped, compatible,
/// translated, NAT64, 6to4, Teredo) is refused outright rather than decoded:
/// a vendor API never needs it, and decoding is where parser differentials
/// live.
fn v6_blocked(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    if (s[0] & 0xe000) != 0x2000 {
        // ::/8 (unspecified, loopback, v4-mapped/compatible/translated),
        // 64:ff9b::/96 and 64:ff9b:1::/48 (NAT64), 100::/64 (discard),
        // fc00::/7 (ULA, incl. AWS fd00:ec2::254), fe80::/10 (link-local),
        // fec0::/10, ff00::/8 (multicast) all fall outside 2000::/3.
        return true;
    }
    (s[0] == 0x2001 && s[1] < 0x0200)         // 2001::/23 IETF protocol assignments (Teredo, ORCHID, benchmarking, AMT...)
        || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
        || s[0] == 0x2002                     // 6to4 (embeds v4)
        || (s[0] & 0xfff0) == 0x3ff0          // 3fff::/20 documentation (RFC 9637)
        || (s[0] == 0x2620 && s[1] == 0x004f && s[2] == 0x8000) // AS112-v6
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_internal_ranges() {
        for ip in [
            "127.0.0.1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1",
            "169.254.169.254", "100.64.0.1", "100.127.255.254", "0.0.0.0", "255.255.255.255",
            "224.0.0.1", "::1", "::", "fe80::1", "fd00:ec2::254", "fc00::1",
            "::ffff:127.0.0.1", "::ffff:169.254.169.254", "64:ff9b::a00:1", "2002:a00:1::1",
            "::127.0.0.1",
        ] {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(check_ip(ip).is_err(), "{ip} must be blocked");
        }
        for ip in ["8.8.8.8", "93.184.215.14", "2606:4700:4700::1111", "100.128.0.1", "172.32.0.1"] {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(check_ip(ip).is_ok(), "{ip} must pass");
        }
    }

    fn policy() -> HostPolicy {
        let rules = vec![AllowRule {
            host: Some("api.example.com".into()),
            host_suffixes: vec![],
            path_prefixes: vec!["/v1/logs".into()],
        }];
        HostPolicy::compile(&rules, &Scope::default()).unwrap()
    }

    #[test]
    fn path_prefix_is_segment_aligned() {
        let p = policy();
        let ok = |u: &str| p.check(&url::Url::parse(u).unwrap());
        assert!(ok("https://api.example.com/v1/logs").is_ok());
        assert!(ok("https://api.example.com/v1/logs/x?y=1").is_ok());
        assert!(ok("https://api.example.com/v1/logsX").is_err());
        assert!(ok("https://api.example.com/v1/logs/../admin").is_err());
        assert!(ok("https://api.example.com/v1/logs/%2e%2e/admin").is_err());
        assert!(ok("https://api.example.com/v1/logs%2f..%2fadmin").is_err());
        assert!(ok("http://api.example.com/v1/logs").is_err());
        assert!(ok("https://api.example.com:8443/v1/logs").is_err());
        assert!(ok("https://user:pw@api.example.com/v1/logs").is_err());
        assert!(ok("https://API.EXAMPLE.COM./v1/logs").is_ok());
        assert!(ok("https://169.254.169.254/v1/logs").is_err());
        assert!(ok("https://[::1]/v1/logs").is_err());
        assert!(ok("https://evil.example.com/v1/logs").is_err());
    }

    #[test]
    fn templated_host_must_match_suffix() {
        let rules = vec![AllowRule {
            host: Some("{{config.OKTA_DOMAIN}}".into()),
            host_suffixes: vec![".okta.com".into()],
            path_prefixes: vec![],
        }];
        let scope = |d: &str| Scope {
            config: serde_json::json!({ "OKTA_DOMAIN": d }),
            ..Default::default()
        };
        assert!(HostPolicy::compile(&rules, &scope("acme.okta.com")).is_ok());
        for bad in ["okta.com.evil.io", "169.254.169.254", "metadata.google.internal", ".okta.com", "a/b.okta.com"] {
            assert!(HostPolicy::compile(&rules, &scope(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn suffixes_must_be_label_aligned_and_deny_wins() {
        let rules = vec![AllowRule {
            host: Some("{{config.D}}".into()),
            host_suffixes: vec!["okta.com".into()],
            path_prefixes: vec![],
        }];
        let scope = Scope { config: serde_json::json!({ "D": "evilokta.com" }), ..Default::default() };
        assert!(matches!(HostPolicy::compile(&rules, &scope), Err(PolicyError::BadRule(_))));

        let deny = EgressDeny::parse(&[".example.com"], &["10.0.0.0/8", "2606:4700::/32"]).unwrap();
        assert!(deny.denies_host("api.example.com") && deny.denies_host("example.com") && !deny.denies_host("notexample.com"));
        assert!(deny.denies_ip("10.1.2.3".parse().unwrap()) && deny.denies_ip("::ffff:10.1.2.3".parse().unwrap()));
        assert!(deny.denies_ip("2606:4700::1111".parse().unwrap()) && !deny.denies_ip("8.8.8.8".parse().unwrap()));
        assert!(matches!(policy().with_deny(deny), Err(PolicyError::HostDenied(_))));
        let p = policy().with_deny(EgressDeny::parse(&["other.example.com"], &["93.184.215.0/24"]).unwrap()).unwrap();
        assert!(matches!(p.check_ip("93.184.215.14".parse().unwrap()), Err(PolicyError::IpDenied(_))));
        assert!(p.check(&url::Url::parse("https://api.example.com/v1/logs").unwrap()).is_ok());
    }

    #[test]
    fn mapped_v6_deny_ranges_keep_their_width() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let d = EgressDeny::parse(&[], &["::ffff:10.0.0.0/104"]).unwrap();
        for a in ["10.0.0.0", "10.200.3.4", "::ffff:10.9.9.9"] {
            assert!(d.denies_ip(ip(a)), "{a}");
        }
        assert!(!d.denies_ip(ip("11.0.0.1")));
        // A v6 range wider than the mapped space covers v4 addresses too.
        let d = EgressDeny::parse(&[], &["::/0"]).unwrap();
        assert!(d.denies_ip(ip("8.8.8.8")) && d.denies_ip(ip("2606:4700::1")));
        let d = EgressDeny::parse(&["", " "], &["", "::ffff:0:0/96"]).unwrap();
        assert!(d.hosts.is_empty() && d.denies_ip(ip("1.2.3.4")) && !d.denies_ip(ip("2606:4700::1")));
    }
}
