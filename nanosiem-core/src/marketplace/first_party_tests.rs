// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;

#[test]
fn accepts_only_exact_first_party_catalogs() {
    for ok in [
        "https://github.com/nano-rs/nano-enrichments",
        "https://github.com/nano-rs/nano-integrations.git",
        "https://GitHub.com/nanos-sh/nano-enrichments/",
        "https://github.com:443/nano-rs/parsers",
    ] {
        assert!(is_first_party_repo_url(ok), "{ok}");
    }
    for bad in [
        "https://github.com/acme/marketplace",
        "https://attacker.example/github.com/nano-rs/rules",
        "https://github.com.attacker.example/nano-rs/rules",
        "https://github.com/nano-rs-evil/rules",
        "https://github.com/nano-rs/rules/tree/main",
        "https://github.com/nano-rs",
        "http://github.com/nano-rs/rules",
        "https://user:token@github.com/nano-rs/rules",
        "https://token@github.com/nano-rs/rules",
        "https://github.com:8443/nano-rs/rules",
        "https://github.com/nano-rs/rules?x=1",
        "https://github.com/nano-rs/rules#frag",
        "file:///etc/passwd",
        "-uhttps://github.com/nano-rs/rules",
        "not a url",
    ] {
        assert!(!is_first_party_repo_url(bad), "{bad}");
        assert!(validate_first_party_repo_url(bad).is_err(), "{bad}");
    }
}

#[test]
fn redacts_embedded_credentials() {
    assert_eq!(redact_repo_url("https://deploy:tok@example.com/c.git"), "https://example.com/c.git");
    assert_eq!(redact_repo_url("https://tok@example.com/c.git"), "https://example.com/c.git");
    assert_eq!(redact_repo_url("https://github.com/nano-rs/rules"), "https://github.com/nano-rs/rules");
    assert!(!redact_repo_url("https://u:p@[bad/x").contains("u:p"));
}
