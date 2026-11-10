// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use VectorConfigDeliveryCredential as C;

#[test]
fn delivery_switch_off_disables_even_with_tokens() {
    assert_eq!(
        resolve_vector_config_delivery(Some("off"), Some("dedicated-x"), Some("install-x"), false),
        C::Disabled(DeliveryDisabledReason::SwitchedOff)
    );
    assert_eq!(
        resolve_vector_config_delivery(Some(" OFF "), None, Some("install-x"), false),
        C::Disabled(DeliveryDisabledReason::SwitchedOff)
    );
}

#[test]
fn dedicated_token_with_the_install_token_still_accepted_during_v2_0() {
    // v2.0.x: an ingest host whose copied .env predates the dedicated token
    // still presents the install token, so both are accepted.
    assert_eq!(
        resolve_vector_config_delivery(None, Some("dedicated-x"), Some("install-x"), false),
        C::DedicatedOrInstallToken {
            dedicated: "dedicated-x".into(),
            install: "install-x".into()
        }
    );
    assert_eq!(
        resolve_vector_config_delivery(Some("on"), Some(" dedicated-x \n"), None, false),
        C::Dedicated("dedicated-x".into())
    );
}

#[test]
fn strict_mode_accepts_only_the_dedicated_token() {
    assert_eq!(
        resolve_vector_config_delivery(None, Some("dedicated-x"), Some("install-x"), true),
        C::Dedicated("dedicated-x".into())
    );
    // Strict without a dedicated token keeps the old fallback (nothing else
    // could authenticate); the finding still reports it.
    assert_eq!(
        resolve_vector_config_delivery(None, None, Some("install-x"), true),
        C::LegacyInstallToken("install-x".into())
    );
}

#[test]
fn install_token_is_the_deprecated_fallback_only_without_a_dedicated_token() {
    assert_eq!(
        resolve_vector_config_delivery(None, None, Some("install-x"), false),
        C::LegacyInstallToken("install-x".into())
    );
    assert_eq!(
        resolve_vector_config_delivery(None, Some("  "), Some("install-x"), false),
        C::LegacyInstallToken("install-x".into())
    );
    assert_eq!(
        resolve_vector_config_delivery(None, None, None, false),
        C::Disabled(DeliveryDisabledReason::NoCredential)
    );
    assert_eq!(
        resolve_vector_config_delivery(None, None, Some(""), false),
        C::Disabled(DeliveryDisabledReason::NoCredential)
    );
}

#[test]
fn public_dedicated_token_disables_delivery() {
    assert_eq!(
        resolve_vector_config_delivery(None, Some("CHANGE_ME_GENERATED"), Some("install-x"), false),
        C::Disabled(DeliveryDisabledReason::PublicDedicatedToken)
    );
}

#[test]
fn debug_never_prints_token_values() {
    let shown = format!(
        "{:?} {:?}",
        C::Dedicated("s3cr3t-a".into()),
        C::LegacyInstallToken("s3cr3t-b".into())
    );
    assert!(!shown.contains("s3cr3t"), "{shown}");
}

fn titles(inputs: &PostureInputs) -> Vec<String> {
    posture_findings(inputs).into_iter().map(|f| f.title).collect()
}

#[test]
fn a_provisioned_deployment_has_no_findings() {
    let inputs = PostureInputs {
        install_token: Some("9f2c-random-install".into()),
        delivery_token: Some("4be1-random-delivery".into()),
        delivery_strict: true,
        base_url: Some("https://siem.example.com".into()),
        db_passwords: vec![("CLICKHOUSE_PASSWORD".into(), "3b1e-random-pw".into())],
        ..Default::default()
    };
    assert!(posture_findings(&inputs).is_empty());
    // Single-host stack: delivery switched off.
    let inputs = PostureInputs {
        install_token: Some("9f2c-random-install".into()),
        delivery_switch: Some("off".into()),
        ..Default::default()
    };
    assert!(posture_findings(&inputs).is_empty());
}

#[test]
fn install_token_still_accepted_beside_the_dedicated_one_is_a_medium_finding() {
    let inputs = PostureInputs {
        install_token: Some("9f2c-random-install".into()),
        delivery_token: Some("4be1-random-delivery".into()),
        ..Default::default()
    };
    let findings = posture_findings(&inputs);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].priority, "medium");
    assert!(findings[0].description.contains(DELIVERY_STRICT_ENV));
}

#[test]
fn public_database_passwords_are_reported_by_name_only() {
    let inputs = PostureInputs {
        delivery_switch: Some("off".into()),
        db_passwords: vec![
            ("CLICKHOUSE_PASSWORD".into(), "nanosiem".into()),
            ("CLICKHOUSE_VECTOR_PASSWORD".into(), "nanosiem_vector_secret".into()),
            ("DATABASE_URL".into(), "nanosiem".into()),
            ("CLICKHOUSE_ADMIN_PASSWORD".into(), "a4f1-random".into()),
        ],
        ..Default::default()
    };
    let findings = posture_findings(&inputs);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].priority, "high");
    let d = &findings[0].description;
    assert!(d.contains("CLICKHOUSE_PASSWORD, CLICKHOUSE_VECTOR_PASSWORD, DATABASE_URL"), "{d}");
    assert!(!d.contains("CLICKHOUSE_ADMIN_PASSWORD"), "{d}");
    assert!(!d.contains("nanosiem_vector_secret"), "never echoes a value: {d}");
}

#[test]
fn public_install_token_is_critical_and_its_delivery_fallback_too() {
    let inputs = PostureInputs {
        install_token: Some("nanosiem-default-token".into()),
        ..Default::default()
    };
    let findings = posture_findings(&inputs);
    assert_eq!(findings.len(), 2, "{findings:?}");
    assert!(findings.iter().all(|f| f.priority == "critical"));
    assert!(findings[0].title.contains("install token is a public default"));
    // NAN-5148: a public install token is never a delivery credential, so the
    // second finding is that delivery is off, not that it accepts the token.
    assert!(findings[1].title.contains("config delivery is off"), "{findings:?}");
    assert!(findings[1].description.contains(DELIVERY_TOKEN_ENV));
    // No finding ever echoes the value.
    assert!(findings
        .iter()
        .all(|f| !f.description.contains("nanosiem-default-token\"")));
}

#[test]
fn legacy_delivery_fallback_is_high() {
    let inputs = PostureInputs {
        install_token: Some("9f2c-random-install".into()),
        ..Default::default()
    };
    let findings = posture_findings(&inputs);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].priority, "high");
    assert!(findings[0].description.contains(DELIVERY_TOKEN_ENV));
}

#[test]
fn default_keys_allowed_only_flags_non_local_deployments() {
    let base = |url: Option<&str>| PostureInputs {
        delivery_switch: Some("off".into()),
        allow_default_keys: true,
        base_url: url.map(str::to_string),
        ..Default::default()
    };
    for url in [
        None,
        Some("http://localhost"),
        Some("http://localhost:5173/"),
        Some("http://127.0.0.1:3000"),
        Some("http://[::1]:8080"),
        Some("http://nano.localhost"),
    ] {
        assert!(titles(&base(url)).is_empty(), "{url:?}");
    }
    for url in ["https://siem.example.com", "http://10.0.0.5", "http://localhost.evil.com"] {
        let t = titles(&base(Some(url)));
        assert_eq!(t.len(), 1, "{url}");
        assert!(t[0].contains("development keys"), "{url}");
    }
}

/// NAN-5148: a known-public install token never authorizes config delivery,
/// whether or not a dedicated token exists and in either fallback mode.
#[test]
fn public_install_token_is_never_a_delivery_credential() {
    for public in ["nanosiem-default-token", "your-secret-token", " nanosiem-default-token \n"] {
        // No dedicated token: delivery is off rather than open to a public value.
        for strict in [false, true] {
            assert_eq!(
                resolve_vector_config_delivery(None, None, Some(public), strict),
                C::Disabled(DeliveryDisabledReason::PublicInstallToken),
                "{public:?} strict={strict}"
            );
        }
        // Dedicated token present: only the dedicated token is accepted.
        for strict in [false, true] {
            assert_eq!(
                resolve_vector_config_delivery(None, Some("dedicated-x"), Some(public), strict),
                C::Dedicated("dedicated-x".into()),
                "{public:?} strict={strict}"
            );
        }
    }
}

#[test]
fn public_install_token_beside_a_dedicated_token_has_no_delivery_finding() {
    let inputs = PostureInputs {
        install_token: Some("nanosiem-default-token".into()),
        delivery_token: Some("4be1-random-delivery".into()),
        ..Default::default()
    };
    let findings = posture_findings(&inputs);
    // Only the ingest-side finding: delivery no longer accepts the install token.
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert!(findings[0].title.contains("install token is a public default"));
}
