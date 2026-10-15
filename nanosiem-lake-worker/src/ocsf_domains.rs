// SPDX-License-Identifier: AGPL-3.0-or-later
//! The ONE list of OCSF fields that carry a domain (NAN-3039).
//!
//! IOC matching (`enrichment::artifact_candidates`), prevalence stamping, the
//! lean part-ingest / parts-adopt prevalence observations and the generation
//! prevalence builder all used to keep their own copies of "which fields hold a
//! domain". They drifted: IOC matching read only `url.hostname`,
//! `query.hostname` and `http_request.url.hostname`, so a domain indicator on
//! `dst_endpoint.hostname` (the canonical destination of every network row)
//! was never stamped while prevalence counted exactly that field.
//!
//! Every consumer now derives its paths from [`DOMAIN_FIELDS`]:
//!
//! * IOC matching reads every entry (scalar hostnames, DNS answer records,
//!   e-mail addresses and TLS SNI).
//! * Lean prevalence (ingest / parts-adopt partials, the ingest stamper, the
//!   detail path) reads only the `prevalence_indexed` entries, filtered by
//!   [`is_prevalence_domain`], and counts hosts by [`PREVALENCE_OBSERVER_PATHS`]
//!   (NAN-3213). The generation builder keeps its own v3-frozen superset.
//! * Prevalence reads only the `prevalence_indexed` entries
//!   ([`PREVALENCE_DOMAIN_PATHS`]). That subset is content-addressed into the
//!   prevalence derivative contract, and the ingest stamper must stay a SUBSET
//!   of what the builder ingests (an artifact the builder never sees is
//!   permanently "new"), so widening it is a deliberate contract change, not a
//!   side effect of widening IOC coverage.

use nanosiem_core::internal_domains::InternalDomains;
use serde_json::{Map, Value};

/// How a domain is carried by an OCSF field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DomainFieldKind {
    /// A bare hostname / FQDN string.
    Hostname,
    /// An e-mail address (`local@domain`, optionally `Name <local@domain>`):
    /// both the full address and its domain are candidates.
    EmailAddress,
    /// A DNS answer `rdata`: a hostname for CNAME/NS/MX/PTR answers, an
    /// address for A/AAAA answers. Either is a valid indicator candidate.
    DnsRdata,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct DomainField {
    /// Dotted OCSF path. A segment that names an array is traversed element
    /// by element (`answers.rdata`, `email.to`).
    pub path: &'static str,
    pub kind: DomainFieldKind,
    /// Part of the prevalence artifact contract (see module docs).
    pub prevalence_indexed: bool,
}

const fn field(path: &'static str, kind: DomainFieldKind, prevalence_indexed: bool) -> DomainField {
    DomainField { path, kind, prevalence_indexed }
}

use DomainFieldKind::{DnsRdata, EmailAddress, Hostname};

/// Every OCSF field that carries a domain.
pub(crate) const DOMAIN_FIELDS: &[DomainField] = &[
    // Endpoint hostnames: the canonical source / destination of network rows.
    // NAN-3213: the SOURCE hostname is the observing machine, not something
    // it looked up. Indexing it made every workstation (`ws-legal-066.corp.local`)
    // a "domain" seen by exactly one host (itself), i.e. permanently rare and,
    // with more than two labels, a "subdomain". It stays an IOC candidate and
    // is the prevalence OBSERVER identity (see `PREVALENCE_OBSERVER_PATHS`).
    field("src_endpoint.hostname", Hostname, false),
    field("dst_endpoint.hostname", Hostname, true),
    // HTTP / URL objects.
    field("http_request.url.hostname", Hostname, true),
    field("url.hostname", Hostname, true),
    // DNS Activity: the question and its answers.
    field("query.hostname", Hostname, true),
    field("answers.rdata", DnsRdata, false),
    // TLS server name indication.
    field("tls.sni", Hostname, false),
    // Email Activity: sender and recipient addresses.
    field("email.from", EmailAddress, false),
    field("email.reply_to", EmailAddress, false),
    field("email.smtp_from", EmailAddress, false),
    field("email.to", EmailAddress, false),
    field("email.cc", EmailAddress, false),
    field("email.smtp_to", EmailAddress, false),
];

/// The prevalence-indexed subset of [`DOMAIN_FIELDS`], in the same order.
/// A `const` slice because the generation builder renders it into SQL and the
/// Arrow partials compile it per batch; `prevalence_paths_match_domain_fields`
/// pins it to the flags above.
pub(crate) const PREVALENCE_DOMAIN_PATHS: &[&str] = &[
    "dst_endpoint.hostname",
    "http_request.url.hostname",
    "url.hostname",
    "query.hostname",
];

/// NAN-3213: who OBSERVED an artifact. A prevalence row's host set is the
/// distinct devices whose events carried the artifact: the event's own device,
/// else (network rows without a device) its source endpoint. Never the
/// artifact's peer: keying a source IP on its destinations counted every IP a
/// workstation contacted as a "host" and saturated at 1,000. One identity for
/// every artifact kind, so the same machine fingerprints the same way whether
/// it saw an IP, a domain or a hash. Lean ingest and parts-adopt partials share
/// this list.
pub(crate) const PREVALENCE_OBSERVER_PATHS: &[&str] = &["device.hostname", "src_endpoint.hostname", "src_endpoint.ip"];

/// NAN-3226: the internal-suffix set this process applies (built-ins from
/// `nanosiem_core::internal_domains`, dedicated parity
/// `clickhouse/111_filter_internal_tlds_domain_prevalence.sql`, UNIONED with
/// the tenant's own list). A lean ingest process serves exactly one tenant;
/// its cell loop installs the tenant list it reads from the tenant enrichment
/// prefix (`internal_domains_snapshot`) and every later part / stamp uses it.
/// `fileserver.corp.local` or `db1.prod` on `dst_endpoint.hostname` is an
/// internal host, not a domain whose spread across the estate means anything.
static INTERNAL_DOMAINS: std::sync::RwLock<Option<std::sync::Arc<InternalDomains>>> = std::sync::RwLock::new(None);

/// The process's current internal-suffix set (built-ins until a tenant list
/// is installed).
pub(crate) fn current_internal_domains() -> std::sync::Arc<InternalDomains> {
    INTERNAL_DOMAINS
        .read()
        .ok()
        .and_then(|guard| guard.clone())
        .unwrap_or_else(|| std::sync::Arc::new(InternalDomains::builtin()))
}

/// Install the tenant's internal-suffix set for every later part and stamp of
/// this (single-tenant) process. Returns whether it changed.
pub(crate) fn set_internal_domains(next: std::sync::Arc<InternalDomains>) -> bool {
    let Ok(mut guard) = INTERNAL_DOMAINS.write() else { return false };
    if guard.as_deref() == Some(next.as_ref()) {
        return false;
    }
    *guard = Some(next);
    true
}

/// Whether a `lower-trim-v1` value is indexed as a DOMAIN prevalence artifact:
/// dotted, not an IP literal, and not under an internal suffix (built-in or
/// the process tenant's). The lean partials (what is indexed) and the ingest
/// stamper (what is looked up) both use this, so the stamper never looks up a
/// value the partials never index.
#[cfg(test)]
pub(crate) fn is_prevalence_domain(host: &str) -> bool {
    is_prevalence_domain_with(host, &current_internal_domains())
}

/// [`is_prevalence_domain`] against an explicit internal-suffix set (a part
/// writer pins one set for the whole part).
pub(crate) fn is_prevalence_domain_with(host: &str, internal: &InternalDomains) -> bool {
    if !host.contains('.') || host.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    let tld = host.trim_end_matches('.').rsplit('.').next().unwrap_or_default();
    !tld.is_empty() && !internal.is_internal(host)
}

/// Every string at `path`, descending into arrays at any segment.
fn strings_at<'a>(event: &'a Map<String, Value>, path: &str, out: &mut Vec<&'a str>) {
    fn walk<'a>(value: &'a Value, parts: &[&str], out: &mut Vec<&'a str>) {
        match value {
            Value::Array(items) => items.iter().for_each(|item| walk(item, parts, out)),
            Value::Object(object) => {
                if let Some((head, rest)) = parts.split_first() {
                    if let Some(child) = object.get(*head) {
                        walk(child, rest, out);
                    }
                }
            }
            Value::String(text) if parts.is_empty() => out.push(text.as_str()),
            _ => {}
        }
    }
    let parts: Vec<&str> = path.split('.').collect();
    if let Some((head, rest)) = parts.split_first() {
        if let Some(value) = event.get(*head) {
            walk(value, rest, out);
        }
    }
}

/// `lower(trim(x))`, the prevalence builder's normalization
/// (`lower-trim-v1`). IOC matching additionally drops the root-label dot
/// (`evil.example.` in a DNS question is `evil.example`); prevalence keeps it
/// so the stamper looks up exactly the value the builder indexed.
fn normalize_host(raw: &str, strip_root_dot: bool) -> Option<String> {
    let mut host = raw.trim().to_ascii_lowercase();
    if strip_root_dot {
        host = host.trim_end_matches('.').to_string();
    }
    (!host.is_empty()).then_some(host)
}

/// `Name <local@domain>` / `local@domain` → `(address, domain)`.
fn email_parts(raw: &str) -> Option<(String, String)> {
    let raw = raw.trim();
    let address = match (raw.rfind('<'), raw.rfind('>')) {
        (Some(open), Some(close)) if open < close => &raw[open + 1..close],
        _ => raw,
    }
    .trim()
    .to_ascii_lowercase();
    let (local, domain) = address.rsplit_once('@')?;
    let domain = normalize_host(domain, true)?;
    (!local.is_empty() && domain.contains('.')).then(|| (address.clone(), domain))
}

/// `(path, normalized value)` for every domain-bearing value on the event.
/// `prevalence_only` restricts to [`PREVALENCE_DOMAIN_PATHS`].
pub(crate) fn domain_candidates(event: &Map<String, Value>, prevalence_only: bool) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let internal = prevalence_only.then(current_internal_domains);
    for field in DOMAIN_FIELDS.iter().filter(|f| !prevalence_only || f.prevalence_indexed) {
        let mut raw = Vec::new();
        strings_at(event, field.path, &mut raw);
        for value in raw {
            match field.kind {
                Hostname | DnsRdata => {
                    let Some(host) = normalize_host(value, !prevalence_only) else { continue };
                    // The prevalence builder only indexes dotted, non-IP
                    // names as domains (`position(entity, '.') > 0 AND
                    // isNull(toIPv6OrNull(entity))`, and the same rule in the
                    // lean partials). Looking up anything else would stamp it
                    // `is_new` forever: bare NetBIOS names like `host-a` on
                    // `src_endpoint.hostname` are the common case.
                    // NAN-3213 / NAN-3226: and never an internal name.
                    if internal.as_deref().is_some_and(|internal| !is_prevalence_domain_with(&host, internal)) {
                        continue;
                    }
                    out.push((field.path.to_string(), host));
                }
                EmailAddress => {
                    if let Some((address, domain)) = email_parts(value) {
                        out.push((field.path.to_string(), address));
                        out.push((field.path.to_string(), domain));
                    }
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn event(value: Value) -> Map<String, Value> {
        value.as_object().unwrap().clone()
    }

    #[test]
    fn prevalence_paths_match_domain_fields() {
        let flagged: Vec<&str> = DOMAIN_FIELDS.iter().filter(|f| f.prevalence_indexed).map(|f| f.path).collect();
        assert_eq!(flagged, PREVALENCE_DOMAIN_PATHS);
        // Scalar hostnames only: the builder renders them as plain columns.
        assert!(DOMAIN_FIELDS.iter().filter(|f| f.prevalence_indexed).all(|f| f.kind == Hostname));
    }

    #[test]
    fn every_domain_bearing_field_yields_a_candidate() {
        let e = event(json!({
            "src_endpoint": {"hostname": "Src.Example.COM."},
            "dst_endpoint": {"hostname": "dst.example.com"},
            "http_request": {"url": {"hostname": "http.example.com"}},
            "url": {"hostname": "url.example.com"},
            "query": {"hostname": "q.example.com"},
            "answers": [{"rdata": "cname.example.com"}, {"rdata": "203.0.113.9"}],
            "tls": {"sni": "sni.example.com"},
            "email": {
                "from": "Mallory <Mallory@Phish.Example>",
                "reply_to": "r@reply.example",
                "smtp_from": "bounce@smtp.example",
                "to": ["a@to.example", "b@to2.example"],
                "cc": ["c@cc.example"],
                "smtp_to": ["d@smtpto.example"]
            }
        }));
        let got = domain_candidates(&e, false);
        let has = |path: &str, value: &str| got.iter().any(|(p, v)| p == path && v == value);
        assert!(has("src_endpoint.hostname", "src.example.com"), "{got:?}");
        assert!(has("dst_endpoint.hostname", "dst.example.com"));
        assert!(has("http_request.url.hostname", "http.example.com"));
        assert!(has("url.hostname", "url.example.com"));
        assert!(has("query.hostname", "q.example.com"));
        assert!(has("answers.rdata", "cname.example.com"));
        assert!(has("answers.rdata", "203.0.113.9"));
        assert!(has("tls.sni", "sni.example.com"));
        assert!(has("email.from", "mallory@phish.example") && has("email.from", "phish.example"));
        assert!(has("email.reply_to", "reply.example"));
        assert!(has("email.smtp_from", "smtp.example"));
        assert!(has("email.to", "to.example") && has("email.to", "to2.example"));
        assert!(has("email.cc", "cc.example"));
        assert!(has("email.smtp_to", "smtpto.example"));
    }

    #[test]
    fn prevalence_subset_excludes_ioc_only_fields() {
        let e = event(json!({
            "dst_endpoint": {"hostname": "dst.example.com"},
            "tls": {"sni": "sni.example.com"},
            "answers": [{"rdata": "cname.example.com"}],
            "email": {"from": "a@phish.example"}
        }));
        assert_eq!(
            domain_candidates(&e, true),
            vec![("dst_endpoint.hostname".to_string(), "dst.example.com".to_string())]
        );
    }

    #[test]
    fn malformed_and_empty_values_are_ignored() {
        let e = event(json!({
            "dst_endpoint": {"hostname": "  "},
            "email": {"from": "not-an-address", "to": ["x@nodot", 7, null]},
            "answers": [{"rdata": null}, "scalar"]
        }));
        assert!(domain_candidates(&e, false).is_empty());
    }

    #[test]
    fn prevalence_skips_names_the_builder_never_indexes() {
        let e = event(json!({
            "src_endpoint": {"hostname": "HOST-A"},
            "dst_endpoint": {"hostname": "10.0.0.5"},
            "url": {"hostname": "cdn.example"}
        }));
        assert_eq!(
            domain_candidates(&e, true),
            vec![("url.hostname".to_string(), "cdn.example".to_string())]
        );
        // IOC matching still sees every value (an IP IOC may sit in a hostname field).
        assert_eq!(domain_candidates(&e, false).len(), 3);
    }

    /// NAN-3213: the event's own source hostname (a multi-label workstation
    /// FQDN) is the observer, never a domain/subdomain artifact, and an
    /// internal-TLD destination is not a domain either. Both stay IOC candidates.
    #[test]
    fn source_hostname_and_internal_tlds_are_not_prevalence_domains() {
        let e = event(json!({
            "src_endpoint": {"hostname": "ws-legal-066.corp.local"},
            "dst_endpoint": {"hostname": "fileserver.corp.local"},
            "query": {"hostname": "login.microsoftonline.com"}
        }));
        assert_eq!(
            domain_candidates(&e, true),
            vec![("query.hostname".to_string(), "login.microsoftonline.com".to_string())]
        );
        assert_eq!(domain_candidates(&e, false).len(), 3);
        assert!(!PREVALENCE_DOMAIN_PATHS.contains(&"src_endpoint.hostname"));
        assert!(is_prevalence_domain("a.b.example.com") && is_prevalence_domain("evil.example."));
        for name in ["ws-1.corp.local", "dc01.ad.internal", "x.home", "4.3.2.1.in-addr.arpa", "host-a", "10.0.0.5"] {
            assert!(!is_prevalence_domain(name), "{name}");
        }
    }

    /// NAN-3226: tenant suffixes are honored on DNS label boundaries and
    /// unioned with the built-ins; the explicit form never touches the
    /// process-wide set (tests run in parallel).
    #[test]
    fn tenant_internal_suffixes_are_not_prevalence_domains() {
        let tenant = InternalDomains::with_tenant(["prod", "corp.example.com"]);
        for name in ["db1.prod", "DB1.PROD.".to_ascii_lowercase().as_str(), "hr.corp.example.com", "ws-1.corp.local"] {
            assert!(!is_prevalence_domain_with(name, &tenant), "{name}");
        }
        for name in ["myprod.com", "db1.myprod", "evilcorp.example.com", "login.example.com"] {
            assert!(is_prevalence_domain_with(name, &tenant), "{name}");
        }
        // Another tenant's list does not apply.
        assert!(is_prevalence_domain_with("db1.prod", &InternalDomains::with_tenant(["cloud"])));
        assert!(is_prevalence_domain_with("db1.prod", &InternalDomains::builtin()));
    }

    #[test]
    fn root_dot_is_stripped_for_ioc_matching_only() {
        let e = event(json!({"query": {"hostname": " Evil.Example. "}}));
        assert_eq!(domain_candidates(&e, false)[0].1, "evil.example");
        assert_eq!(domain_candidates(&e, true)[0].1, "evil.example.", "prevalence keeps lower-trim-v1");
    }

    #[test]
    fn prevalence_derivative_contract_names_every_indexed_domain_path() {
        let contract = crate::prevalence_build::derivative_compatibility_contract();
        let fields: Vec<&str> = contract["source_fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        for path in PREVALENCE_DOMAIN_PATHS {
            assert!(fields.contains(path), "{path} missing from the prevalence derivative contract");
        }
    }
}
