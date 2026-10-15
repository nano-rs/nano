//! Property tests for the egress policy and secret matching: URL-parsing
//! tricks, address encodings, host templating and encoded secrets.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use nano_connector::policy::{Cidr, HostPolicy, check_ip, is_plain_hostname};
use nano_connector::secrets::SecretSet;
use nano_connector::spec::AllowRule;
use nano_connector::template::Scope;
use proptest::prelude::*;

/// Independent statement of "not a vendor API address" for IPv4, written
/// from the std predicates and the IANA special-purpose registry rather
/// than from the policy's own table.
fn v4_reference_blocked(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_unspecified()
        || o[0] == 0
        || ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
        || o[0] >= 240
        || (o[0] == 100 && (64..128).contains(&o[1]))
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
        || (o[0] == 192 && o[1] == 88 && o[2] == 99)
        || (o[0] == 192 && o[1] == 31 && o[2] == 196)
        || (o[0] == 192 && o[1] == 52 && o[2] == 193)
        || (o[0] == 192 && o[1] == 175 && o[2] == 48)
        || o == [168, 63, 129, 16]
}

/// Addresses near the edges of every special range.
fn v4_edges() -> impl Strategy<Value = u32> {
    let bases: Vec<u32> = [
        [0, 0, 0, 0], [10, 0, 0, 0], [100, 64, 0, 0], [100, 128, 0, 0], [127, 0, 0, 0], [169, 254, 0, 0],
        [172, 16, 0, 0], [172, 32, 0, 0], [192, 0, 0, 0], [192, 0, 2, 0], [192, 88, 99, 0], [192, 168, 0, 0],
        [198, 18, 0, 0], [198, 20, 0, 0], [198, 51, 100, 0], [203, 0, 113, 0], [224, 0, 0, 0], [168, 63, 129, 16],
        [192, 31, 196, 0], [192, 52, 193, 0], [192, 175, 48, 0], [11, 0, 0, 0], [9, 255, 255, 255],
    ]
    .iter()
    .map(|o| u32::from(Ipv4Addr::from(*o)))
    .collect();
    (prop::sample::select(bases), -2i64..300).prop_map(|(b, d)| (b as i64 + d).clamp(0, u32::MAX as i64) as u32)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 4096, ..ProptestConfig::default() })]

    #[test]
    fn v4_policy_matches_reference(n in prop_oneof![any::<u32>(), v4_edges()]) {
        let ip = Ipv4Addr::from(n);
        prop_assert_eq!(check_ip(IpAddr::V4(ip)).is_err(), v4_reference_blocked(ip), "{}", ip);
    }

    #[test]
    fn v6_forms_that_embed_v4_are_always_blocked(n in any::<u32>(), tail in any::<u64>()) {
        let v4 = Ipv4Addr::from(n);
        let [a, b, c, d] = v4.octets();
        let hi = u16::from_be_bytes([a, b]);
        let lo = u16::from_be_bytes([c, d]);
        for ip in [
            v4.to_ipv6_mapped(),
            v4.to_ipv6_compatible(),
            Ipv6Addr::new(0, 0, 0, 0, 0xffff, 0, hi, lo),        // SIIT translated
            Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, hi, lo),      // NAT64
            Ipv6Addr::new(0x64, 0xff9b, 1, 0, 0, 0, hi, lo),      // local NAT64
            Ipv6Addr::new(0x2002, hi, lo, (tail >> 48) as u16, 0, 0, 0, 1), // 6to4
            Ipv6Addr::new(0x2001, 0, hi, lo, 0, 0, 0, 1),          // Teredo
        ] {
            prop_assert!(check_ip(IpAddr::V6(ip)).is_err(), "{} (from {})", ip, v4);
        }
    }

    #[test]
    fn v6_outside_global_unicast_is_blocked(n in any::<u128>()) {
        let ip = Ipv6Addr::from(n);
        if (ip.segments()[0] & 0xe000) != 0x2000 {
            prop_assert!(check_ip(IpAddr::V6(ip)).is_err(), "{}", ip);
        }
    }

    #[test]
    fn cidr_contains_its_own_members(n in any::<u32>(), bits in 0u8..=32) {
        let ip = Ipv4Addr::from(n);
        let c = Cidr::parse(&format!("{ip}/{bits}")).unwrap();
        prop_assert!(c.contains(IpAddr::V4(ip)));
        prop_assert!(c.contains(IpAddr::V6(ip.to_ipv6_mapped())), "a v4 deny must also match the mapped form");
    }
}

/// Pieces an attacker splices into URLs.
fn url_tokens() -> impl Strategy<Value = String> {
    prop::sample::select(vec![
        "api.example.com", "evil.example.com", "127.0.0.1", "169.254.169.254", "0x7f.1", "2130706433", "[::1]",
        "[::ffff:a9fe:a9fe]", "@", "#", "?", "/", "\\", ":", ":443", ":80", ":8443", ".", "..", "%2e", "%2f", "%5c",
        "%00", "%0d%0a", "%40", "%23", "v1", "logs", "admin", "user:pass@", "\t", "\n", " ", "\u{3002}", "\u{ff0e}",
        "\u{430}", "xn--pi-6cd", "localhost", "metadata", ".internal", "\u{200b}", "%25", ";", "&", "=", "//",
    ])
    .prop_map(str::to_string)
}

fn allow_v1() -> HostPolicy {
    HostPolicy::compile(
        &[AllowRule { host: Some("api.example.com".into()), host_suffixes: vec![], path_prefixes: vec!["/v1".into()] }],
        &Scope::default(),
    )
    .unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 20_000, ..ProptestConfig::default() })]

    /// Whatever the string, a URL the policy accepts goes to the allowlisted
    /// host on 443 under /v1, re-parses to the same target, and yields a
    /// request line with no control bytes.
    #[test]
    fn accepted_urls_only_reach_the_allowed_target(
        scheme in prop::sample::select(vec!["https://", "https:", "https:/", "HTTPS://", "https:\\\\", "http://", ""]),
        parts in prop::collection::vec(url_tokens(), 0..10),
    ) {
        let raw = format!("{scheme}{}", parts.concat());
        let Ok(url) = url::Url::parse(&raw) else { return Ok(()) };
        let policy = allow_v1();
        if let Ok((host, port)) = policy.check(&url) {
            prop_assert_eq!(&host, "api.example.com", "{}", raw);
            prop_assert_eq!(port, 443);
            prop_assert_eq!(url.host_str(), Some("api.example.com"));
            prop_assert!(url.username().is_empty() && url.password().is_none());
            prop_assert!(url.path() == "/v1" || url.path().starts_with("/v1/"), "{} -> {}", raw, url.path());
            let again = url::Url::parse(url.as_str()).unwrap();
            prop_assert_eq!(again.host_str(), url.host_str(), "re-parse moved the host: {}", raw);
            prop_assert_eq!(again.path(), url.path());
            let target = match url.query() { Some(q) => format!("{}?{}", url.path(), q), None => url.path().to_string() };
            prop_assert!(target.parse::<http::uri::PathAndQuery>().is_ok(), "request target {:?}", target);
            prop_assert!(!target.bytes().any(|b| b.is_ascii_control() || b == b' '), "control byte in {:?}", target);
        }
    }

    /// A tenant-supplied host for a templated rule is accepted only if it
    /// is a plain name under one of the suffixes, label-aligned.
    #[test]
    fn templated_hosts_stay_under_their_suffix(
        parts in prop::collection::vec(prop::sample::select(vec![
            "acme", "okta", "com", "evil", ".", "-", "okta.com", ".okta.com", "169.254.169.254", "/", "@", ":", "%2e",
            "\u{430}", "localhost", "internal", "0x7f", "1", "xn--", "_", " ", "\n", "{{config.X}}", "OKTA", "COM",
        ]).prop_map(str::to_string), 0..8),
    ) {
        let value = parts.concat();
        let rules = [AllowRule { host: Some("{{config.D}}".into()), host_suffixes: vec![".okta.com".into()], path_prefixes: vec![] }];
        let scope = Scope { config: serde_json::json!({ "D": value }), ..Default::default() };
        if let Ok(p) = HostPolicy::compile(&rules, &scope) {
            let h: Vec<&str> = p.hosts().collect();
            prop_assert_eq!(h.len(), 1);
            prop_assert!(h[0].ends_with(".okta.com") && h[0].len() > ".okta.com".len(), "{:?} from {:?}", h[0], value);
            prop_assert!(is_plain_hostname(h[0]), "{:?}", h[0]);
        }
    }

    /// A secret is found and removed wherever it sits inside base64, hex or
    /// percent-encoded text.
    #[test]
    fn encoded_secrets_are_found_and_redacted(
        secret in "[A-Za-z0-9_+/=.~-]{6,40}",
        prefix in "[ -~]{0,12}",
        suffix in "[ -~]{0,12}",
    ) {
        let set = SecretSet::new([secret.as_str()]);
        let plain = format!("{prefix}{secret}{suffix}");
        for hay in [
            plain.clone(),
            STANDARD.encode(&plain),
            URL_SAFE_NO_PAD.encode(&plain),
            hex::encode(&secret),
            percent_encoding::utf8_percent_encode(&secret, percent_encoding::NON_ALPHANUMERIC).to_string(),
        ] {
            prop_assert!(set.contains_str(&hay), "missed {:?} in {:?}", secret, hay);
            let red = set.redact_str(&hay);
            prop_assert!(!set.contains_str(&red), "left a shape of {:?} in {:?}", secret, red);
        }
    }
}
