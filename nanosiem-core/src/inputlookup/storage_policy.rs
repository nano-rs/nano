// SPDX-License-Identifier: AGPL-3.0-or-later
//! Reviewed HTTPS inputlookup egress policy for shared tenants. No DNS or I/O here.
use url::{Host, Url};

pub const STORAGE_POLICY_ERROR: &str =
    "Shared inputlookup requires a static public HTTPS URL on port 443";
pub const ALLOWLIST_ERROR: &str =
    "host not in this tenant's inputlookup allowlist; a tenant admin can add it in Settings";

fn label(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && !s.starts_with('-')
        && !s.ends_with('-')
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// ASCII/punycode only: callers must explicitly normalize Unicode IDNs first.
/// PSL includes private suffixes, not just ICANN TLDs. The cloud-provider
/// parent amazonaws.com is also explicitly forbidden as required by policy.
pub fn normalize_entry(raw: &str) -> Result<String, &'static str> {
    if !raw.is_ascii()
        || raw.contains(['/', ':', '@', '?', '#', '%', '\\'])
        || raw.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err("enter an ASCII or punycode public hostname, without a URL, port or path");
    }
    let entry = raw.strip_suffix('.').unwrap_or(raw).to_ascii_lowercase();
    let host = entry.strip_prefix("*.").unwrap_or(&entry);
    if host.contains('*') || host.len() > 253 || !host.split('.').all(label) {
        return Err("only exact hosts or *.domain suffixes are supported");
    }
    let parsed = Url::parse(&format!("https://{host}/")).map_err(|_| STORAGE_POLICY_ERROR)?;
    if !matches!(parsed.host(), Some(Host::Domain(h)) if h == host) {
        return Err("IP literals are forbidden");
    }
    for suffix in [
        "localhost",
        "local",
        "localdomain",
        "internal",
        "intranet",
        "lan",
        "home.arpa",
        "svc",
        "cluster.local",
        "nano.rs",
    ] {
        if host == suffix || host.strip_suffix(suffix).is_some_and(|p| p.ends_with('.')) {
            return Err("internal hostnames are forbidden");
        }
    }
    if host == "amazonaws.com"
        || psl::domain(host.as_bytes()).is_none()
        || !psl::suffix(host.as_bytes()).is_some_and(|suffix| suffix.is_known())
    {
        return Err("a registrable domain is required; public suffixes are forbidden");
    }
    Ok(entry)
}

pub fn host_allowed(host: &str, entries: &[String]) -> bool {
    entries.iter().any(|entry| {
        if let Some(suffix) = entry.strip_prefix("*.") {
            host.strip_suffix(suffix)
                .is_some_and(|prefix| prefix.len() > 1 && prefix.ends_with('.'))
        } else {
            host == entry
        }
    })
}

/// Reject parser ambiguities before WHATWG URL normalization can erase them.
/// Query strings are opaque signed credentials and never included in errors.
pub fn parse_storage_url(raw: &str) -> Result<Url, &'static str> {
    if raw.len() > 16_384
        || raw.chars().any(|c| c.is_control() || c.is_whitespace())
        || raw.contains('\\')
        || raw.contains('{')
        || raw.contains('}')
    {
        return Err(STORAGE_POLICY_ERROR);
    }
    let (_, tail) = raw.split_once("://").ok_or(STORAGE_POLICY_ERROR)?;
    let authority = tail.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') || authority.contains('%') {
        return Err(STORAGE_POLICY_ERROR);
    }
    let path = tail
        .get(authority.len()..)
        .unwrap_or("")
        .split(['?', '#'])
        .next()
        .unwrap_or("");
    let lower = path.to_ascii_lowercase();
    if lower.contains("%2f")
        || lower.contains("%5c")
        || lower.contains("%2e")
        || path.split('/').any(|p| p == "." || p == "..")
    {
        return Err(STORAGE_POLICY_ERROR);
    }
    let mut url = Url::parse(raw).map_err(|_| STORAGE_POLICY_ERROR)?;
    if url.scheme() != "https"
        || url.port_or_known_default() != Some(443)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(STORAGE_POLICY_ERROR);
    }
    let Some(Host::Domain(host)) = url.host() else {
        return Err(STORAGE_POLICY_ERROR);
    };
    let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    if host.len() > 253 || !host.contains('.') || !host.split('.').all(label) {
        return Err(STORAGE_POLICY_ERROR);
    }
    url.set_host(Some(&host))
        .map_err(|_| STORAGE_POLICY_ERROR)?;
    Ok(url)
}

pub fn validate_storage_url(raw: &str, extra_hosts: &[String]) -> Result<Url, &'static str> {
    let url = parse_storage_url(raw)?;
    let host = url.host_str().ok_or(STORAGE_POLICY_ERROR)?;
    if !host_allowed(host, extra_hosts) {
        return Err(ALLOWLIST_ERROR);
    }
    Ok(url)
}

pub fn normalize_allowlist_hosts(hosts: &[String]) -> Result<Vec<String>, &'static str> {
    let cap = std::env::var("NANOSIEM_INPUTLOOKUP_ALLOWLIST_MAX_ENTRIES")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(50);
    if hosts.len() > cap {
        return Err("inputlookup allowlist entry limit exceeded");
    }
    let mut out = hosts
        .iter()
        .map(|h| normalize_entry(h))
        .collect::<Result<Vec<_>, _>>()?;
    out.sort();
    out.dedup();
    Ok(out)
}

pub fn redact_single_url(raw: &str) -> String {
    let base = raw.split(['?', '#']).next().unwrap_or(raw);
    let safe = redact_url_credentials(base);
    if base.len() != raw.len() {
        format!("{safe}?[REDACTED]")
    } else {
        safe
    }
}

/// Conservative lexical redaction also works for malformed queries/URLs.
/// Drops userinfo, query and fragment from all HTTP URLs, without parsing nPL.
pub fn redact_url_credentials(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    let mut quote = None;
    while cursor < text.len() {
        let rest = &text[cursor..];
        let is_url = rest
            .get(..8)
            .is_some_and(|s| s.eq_ignore_ascii_case("https://"))
            || rest
                .get(..7)
                .is_some_and(|s| s.eq_ignore_ascii_case("http://"));
        if is_url {
            let end = rest
                .char_indices()
                .find_map(|(i, c)| {
                    if (quote == Some(c)
                        && rest[..i].chars().rev().take_while(|c| *c == '\\').count() % 2 == 0)
                        || (quote.is_none()
                            && (c.is_whitespace() || c == '|' || c == '<' || c == '>'))
                    {
                        Some(i)
                    } else {
                        None
                    }
                })
                .unwrap_or(rest.len());
            let raw = &rest[..end];
            let base = raw.split(['?', '#']).next().unwrap_or(raw);
            if let Some((scheme, tail)) = base.split_once("://") {
                let authority_end = tail.find('/').unwrap_or(tail.len());
                let authority = &tail[..authority_end];
                let host = authority.rsplit('@').next().unwrap_or(authority);
                out.push_str(&format!("{scheme}://{host}{}", &tail[authority_end..]));
                if base.len() != raw.len() {
                    out.push_str("?[REDACTED]");
                }
            }
            cursor += end;
            continue;
        }
        let c = rest.chars().next().unwrap();
        if c == '\'' || c == '"' {
            if quote == Some(c) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(c);
            }
        }
        out.push(c);
        cursor += c.len_utf8();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn default_policy_excludes_providers_outside_the_review_scope() {
        for host in ["account.r2.cloudflarestorage.com", "pub-abc123.r2.dev"] {
            let raw = format!("https://{host}/feed.csv");
            assert!(validate_storage_url(&raw, &[]).is_err());
            assert!(validate_storage_url(&raw, &[host.into()]).is_ok());
        }
    }

    #[test]
    fn empty_defaults_and_label_boundaries() {
        assert_eq!(
            validate_storage_url("https://storage.googleapis.com/b/x", &[]).unwrap_err(),
            ALLOWLIST_ERROR
        );
        let entries = normalize_allowlist_hosts(&["*.Example.COM.".into()]).unwrap();
        for h in ["a.example.com", "a.b.example.com"] {
            assert!(host_allowed(h, &entries));
        }
        for h in ["example.com", "badexample.com", "a.example.com.evil.com"] {
            assert!(!host_allowed(h, &entries));
        }
    }
    #[test]
    fn entry_guardrails() {
        for h in [
            "*",
            "com",
            "*.com",
            "*.co.uk",
            "*.amazonaws.com",
            "127.0.0.1",
            "2130706433",
            "0177.0.0.1",
            "0x7f000001",
            "[::1]",
            "localhost",
            "a.local",
            "a.localdomain",
            "a.internal",
            "a.intranet",
            "a.lan",
            "a.home.arpa",
            "a.svc",
            "a.cluster.local",
            "metadata.google.internal",
            "nano.rs",
            "a.nano.rs",
            "user@a.com",
            "a.com:443",
            "a.com/x",
            "bücher.de",
        ] {
            assert!(normalize_entry(h).is_err(), "{h}");
        }
        assert_eq!(
            normalize_entry("XN--BCHER-KVA.DE.").unwrap(),
            "xn--bcher-kva.de"
        );
    }
    #[test]
    fn url_parser_confusion_and_ip_forms() {
        for raw in [
            "https://storage.googleapis.com@evil.com/x",
            "https://evil.com#@storage.googleapis.com",
            "https://@storage.googleapis.com/x",
            "https://storage.googleapis.com:8443/x",
            "http://storage.googleapis.com/x",
            "https://storage.googleapis.com\\@evil.com/x",
            "https://storage%2egoogleapis.com/x",
            "https://storage.googleapis.com/%2e%2e/x",
            "https://storage.googleapis.com/bucket%2fx",
            "https://storage.googleapis.com/bucket/../x",
            "https://2130706433/x",
            "https://0177.0.0.1/x",
            "https://0x7f000001/x",
            "https://[::1]/x",
            "https://[::ffff:169.254.169.254]/x",
            "https://8.8.8.8/x",
            "https://storage.googleapis.com/{user}",
        ] {
            assert!(parse_storage_url(raw).is_err(), "{raw}");
        }
        assert_eq!(
            validate_storage_url(
                "https://STORAGE.GOOGLEAPIS.COM./bucket/x",
                &["storage.googleapis.com".into()]
            )
            .unwrap()
            .host_str(),
            Some("storage.googleapis.com")
        );
    }
    #[test]
    fn extra_hosts_are_exact_normalized_and_bounded() {
        let extra = normalize_allowlist_hosts(&["FEEDS.Example.COM.".into()]).unwrap();
        assert!(validate_storage_url("https://feeds.example.com/x", &extra).is_ok());
        assert!(validate_storage_url("https://sub.feeds.example.com/x", &extra).is_err());
        for h in [
            "127.0.0.1",
            "example.com:443",
            "example.com/path",
            "example.com@evil.com",
        ] {
            assert!(normalize_allowlist_hosts(&[h.into()]).is_err());
        }
    }
    #[test]
    fn sas_presigned_and_malformed_query_redaction() {
        for text in [
            r#"| inputlookup url="https://storage.googleapis.com/b/x?sig=secret&token=secret""#,
            "https://user:secret@host.example/a?sig=secret#secret",
            "bad https://host.example/a?sig=secret",
            r#"| inputlookup url="https://host.example/a?sig='secret' extra=secret""#,
        ] {
            let safe = redact_url_credentials(text);
            assert!(!safe.contains("secret"));
            assert!(safe.contains("[REDACTED]"));
        }
    }
}
