// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

#[test]
fn delay_is_zero_up_to_the_start_then_doubles_to_the_cap() {
    for n in 0..=ACCOUNT_DELAY_START {
        assert_eq!(account_delay(n), Duration::ZERO, "{n}");
    }
    let secs: Vec<u64> = ((ACCOUNT_DELAY_START + 1)..=(ACCOUNT_DELAY_START + 7))
        .map(|n| account_delay(n).as_secs())
        .collect();
    assert_eq!(secs, vec![2, 4, 8, 16, 30, 30, 30]);
    assert_eq!(account_delay(i32::MAX).as_secs(), ACCOUNT_DELAY_MAX_SECS);
}

#[test]
fn keys_use_the_normalised_email_string() {
    assert_eq!(normalize_email("  Admin@Example.COM \n"), "admin@example.com");
    assert_eq!(
        account_ip_key("Admin@Example.com", Some("203.0.113.9")),
        "admin@example.com\n203.0.113.9"
    );
    assert_eq!(account_ip_key("a@b.c", None), "a@b.c\nunknown");
}

#[test]
fn canonical_ip_key_handles_ipv4_mapped_and_ipv6_prefix() {
    // IPv4 stays as-is.
    assert_eq!(canonical_ip_key(Some("203.0.113.9")), "203.0.113.9");
    // IPv4-mapped IPv6 collapses to the IPv4 form (both spellings).
    assert_eq!(canonical_ip_key(Some("::ffff:203.0.113.9")), "203.0.113.9");
    assert_eq!(canonical_ip_key(Some("::ffff:cb00:7109")), "203.0.113.9");
    // IPv6 is reduced to its /64, so every host in one /64 shares a key.
    let a = canonical_ip_key(Some("2001:db8:1:2::1"));
    let b = canonical_ip_key(Some("2001:db8:1:2:ffff:ffff:ffff:ffff"));
    assert_eq!(a, b);
    assert_eq!(a, "2001:db8:1:2::/64");
    // A different /64 is a different key.
    assert_ne!(a, canonical_ip_key(Some("2001:db8:1:3::1")));
    // Unparseable / missing fall back to one shared bucket.
    assert_eq!(canonical_ip_key(None), "unknown");
    assert_eq!(canonical_ip_key(Some("not-an-ip")), "unknown");
}

#[test]
fn account_ip_key_canonicalises_the_address() {
    assert_eq!(
        account_ip_key("Admin@Example.com", Some("::ffff:203.0.113.9")),
        "admin@example.com\n203.0.113.9"
    );
    assert_eq!(
        account_ip_key("a@b.c", Some("2001:db8:aa:bb:cc::1")),
        "a@b.c\n2001:db8:aa:bb::/64"
    );
}
