// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5005: a CrowdStrike FDR source config renders a `crowdstrike_fdr`
//! source whose events route to the CrowdStrike Falcon parser by default,
//! and whose `lookups` output is left unconsumed (dropped by design).

use super::*;
use super::super::types::{RoutingRule, SourceConfiguration, SourceConfigurationWithRules};
use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

fn fdr_config(rules: Vec<RoutingRule>, default_source_type: Option<&str>) -> SourceConfigurationWithRules {
    let now = Utc::now();
    SourceConfigurationWithRules {
        config: SourceConfiguration {
            id: Uuid::new_v4(),
            name: "Falcon FDR".to_string(),
            description: None,
            config_type: "crowdstrike_fdr".to_string(),
            connection_config: json!({
                "queue_url": "https://sqs.us-west-2.amazonaws.com/123456789012/cs-mav-cannon-queue"
            }),
            credential_id: None,
            enabled: true,
            deployed: false,
            deployed_at: None,
            created_at: now,
            updated_at: now,
            default_source_type: default_source_type.map(str::to_string),
            events_24h: None,
            bytes_per_day_24h: None,
            last_event_at: None,
            last_deployment: None,
        },
        routing_rules: rules,
    }
}

fn rule(match_field: &str, match_type: &str, value: Option<&str>, target: &str) -> RoutingRule {
    RoutingRule {
        id: Uuid::new_v4(),
        source_configuration_id: Uuid::nil(),
        priority: 10,
        match_field: match_field.to_string(),
        match_type: match_type.to_string(),
        match_value: value.map(str::to_string),
        target_source_type: target.to_string(),
        created_at: Utc::now(),
        fires_24h: None,
        last_fired_at: None,
    }
}

#[test]
fn routes_to_the_falcon_parser_without_rules() {
    let vrl = SourceConfigService::generate_routing_transform(&fdr_config(vec![], None), "src", "route", false);
    assert!(vrl.contains(".source_type = \"crowdstrike_falcon\""), "{vrl}");
    assert!(vrl.contains("crowdstrike_fdr"), "forwarded_via is stamped:\n{vrl}");
}

#[test]
fn an_explicit_default_or_rule_wins_over_the_falcon_fallback() {
    let seeded = fdr_config(vec![], Some("falcon_custom"));
    let vrl = SourceConfigService::generate_routing_transform(&seeded, "src", "route", false);
    assert!(vrl.contains(".source_type = \"falcon_custom\""), "{vrl}");
    assert!(!vrl.contains("crowdstrike_falcon"), "{vrl}");

    let ruled = fdr_config(vec![rule("message", "default", None, "falcon_other")], None);
    let vrl = SourceConfigService::generate_routing_transform(&ruled, "src", "route", false);
    assert!(vrl.contains(".source_type = \"falcon_other\""), "{vrl}");
}

#[test]
fn other_pull_drivers_keep_the_unknown_fallback() {
    let mut config = fdr_config(vec![], None);
    config.config.config_type = "aws_sqs".to_string();
    let vrl = SourceConfigService::generate_routing_transform(&config, "src", "route", false);
    assert!(vrl.contains(".source_type = \"unknown\""), "{vrl}");
}

#[test]
fn validate_connection_config_dispatches_to_the_fdr_driver() {
    let error = SourceConfigService::validate_connection_config(
        "crowdstrike_fdr",
        &json!({"queue_url": "https://sqs.us-west-2.amazonaws.com/1/q", "checksum": "sha1"}),
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("checksum"), "{error}");
    // NAN-4936: no Vector env interpolation in tenant values.
    let error = SourceConfigService::validate_connection_config(
        "crowdstrike_fdr",
        &json!({"queue_url": "https://sqs.us-west-2.amazonaws.com/1/${AWS_SECRET_ACCESS_KEY}"}),
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("connection_config"), "{error}");
    SourceConfigService::validate_connection_config("crowdstrike_fdr", &json!({})).unwrap();
}

#[test]
fn fdr_is_a_pull_source_reading_with_aws_credentials() {
    use super::super::types::SourceConfigType;
    let t = SourceConfigType::from_str("crowdstrike_fdr").unwrap();
    assert_eq!(SourceConfigType::from_str("fdr"), Some(t));
    assert!(t.is_pull_source());
    assert!(t.requires_credentials());
    assert_eq!(t.label(), "CrowdStrike FDR");
    assert!(SourceConfigType::all_types().contains(&t));
    assert_eq!(SourceConfigService::forwarded_via_for_pull_source("crowdstrike_fdr"), Some("crowdstrike_fdr"));
}

/// The rendered source plus its routing transform (lookups output left
/// unconsumed) must pass `vector validate` on the pinned image. Ignored by
/// default (needs docker); run with
/// `NANOSIEM_TEST_VECTOR_IMAGE=ghcr.io/nano-rs/vector:0.61.0-nano.7-debian
///  cargo test -p nanosiem-core --lib fdr_generated_config_passes_vector_validate -- --ignored`.
/// `NANOSIEM_TEST_VECTOR_BIN=<path to a fork vector binary>` runs it without docker.
#[test]
#[ignore = "requires the pinned Vector image (docker) or NANOSIEM_TEST_VECTOR_BIN"]
fn fdr_generated_config_passes_vector_validate() {
    let config = fdr_config(vec![], None);
    let creds = json!({"access_key_id": "AKIAEXAMPLE", "secret_access_key": "example-secret"});
    let source = SourceConfigService::wrap_source_table(
        "falcon_fdr_source",
        crate::source_configs::crowdstrike_fdr::source_table(
            "falcon_fdr_source",
            &config.config.connection_config,
            Some(&creds),
        )
        .unwrap(),
    );
    let route = SourceConfigService::generate_routing_transform(&config, "falcon_fdr_source", "falcon_fdr_route", false);
    let dir = std::env::temp_dir().join(format!("nan5005-vector-validate-{}", Uuid::new_v4().simple()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("vector.toml"),
        format!("{source}\n{route}\n[sinks.out]\ntype = \"blackhole\"\ninputs = [\"falcon_fdr_route\"]\n"),
    )
    .unwrap();
    let output = if let Ok(bin) = std::env::var("NANOSIEM_TEST_VECTOR_BIN") {
        std::process::Command::new(bin)
            .args(["validate", "--no-environment"])
            .arg(dir.join("vector.toml"))
            .output()
            .expect("vector binary must be runnable")
    } else {
        let image = std::env::var("NANOSIEM_TEST_VECTOR_IMAGE")
            .expect("NANOSIEM_TEST_VECTOR_IMAGE must name the pinned Vector image");
        std::process::Command::new("docker")
            .args(["run", "--rm", "-v"])
            .arg(format!("{}:/etc/vector:ro", dir.display()))
            .args([image.as_str(), "validate", "--no-environment", "/etc/vector/vector.toml"])
            .output()
            .expect("docker must be runnable")
    };
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        output.status.success(),
        "crowdstrike_fdr config failed vector validate:\n{source}\n{route}\n{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
