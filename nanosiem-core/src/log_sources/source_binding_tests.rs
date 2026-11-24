// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5789: a fetch log source must name an existing source configuration of
//! its own type (drafts included), and a live one a deployed one.

use uuid::Uuid;

use super::*;

fn cfg(config_type: &str, deployed: bool) -> BoundConfig {
    BoundConfig { config_type: config_type.into(), deployed }
}

const FETCH: [&str; 9] = ["kafka", "aws_s3", "s3", "aws_sqs", "crowdstrike_fdr", "gcp_pubsub", "pubsub", "azure_event_hubs", "KAFKA"];

#[test]
fn every_fetch_type_without_a_binding_is_refused_with_a_field_error() {
    for source_type in FETCH {
        let err = check_binding("log", source_type, None, None, false).unwrap_err();
        assert_eq!(err.field, "dispatch_source_config_id");
        assert!(err.message.contains("needs a source configuration"), "{}", err.message);
        assert!(err.message.contains("routed"), "{}", err.message);
    }
}

#[test]
fn a_binding_to_a_missing_configuration_is_refused() {
    let err = check_binding("log", "kafka", Some(Uuid::new_v4()), None, false).unwrap_err();
    assert!(err.message.contains("does not match any source configuration"), "{}", err.message);
}

#[test]
fn a_binding_to_another_type_is_refused() {
    for (source_type, config_type) in [("kafka", "aws_s3"), ("aws_s3", "kafka"), ("kafka", "http"), ("gcp_pubsub", "splunk_hec"), ("azure_event_hubs", "otlp")] {
        let err = check_binding("log", source_type, Some(Uuid::new_v4()), Some(&cfg(config_type, true)), false).unwrap_err();
        assert!(err.message.contains(&format!("is a {config_type} source configuration")), "{}", err.message);
    }
}

#[test]
fn a_matching_binding_is_accepted_whatever_the_spelling() {
    for (source_type, config_type) in [("kafka", "kafka"), ("KAFKA", "kafka"), ("s3", "aws_s3"), ("aws_sqs", "aws_sqs"), ("pubsub", "gcp_pubsub"), ("azure_event_hubs", "azure_event_hubs")] {
        check_binding("log", source_type, Some(Uuid::new_v4()), Some(&cfg(config_type, true)), true)
            .unwrap_or_else(|e| panic!("{source_type} + {config_type}: {}", e.message));
    }
}

#[test]
fn a_live_source_needs_a_deployed_configuration_a_draft_does_not() {
    let id = Some(Uuid::new_v4());
    assert!(check_binding("log", "kafka", id, Some(&cfg("kafka", false)), false).is_ok());
    let err = check_binding("log", "kafka", id, Some(&cfg("kafka", false)), true).unwrap_err();
    assert!(err.message.contains("is not deployed"), "{}", err.message);
}

#[test]
fn push_and_enrichment_sources_need_no_binding() {
    for source_type in ["routed", "http", "splunk_hec", "vector", "otlp"] {
        assert!(check_binding("log", source_type, None, None, true).is_ok(), "{source_type}");
    }
    // The UI's pull flow stores a routed source carrying the picked config.
    assert!(check_binding("log", "routed", Some(Uuid::new_v4()), Some(&cfg("kafka", false)), true).is_ok());
    assert!(check_binding("enrichment", "kafka", None, None, true).is_ok());
}

/// NAN-5789 round 2: aliases the old per-module lists missed (`fdr`, `sqs`,
/// `event_hubs`) are fetch sources here too, so an unbound one is refused.
#[test]
fn every_alias_of_a_fetch_type_needs_a_binding() {
    for source_type in ["fdr", "sqs", "event_hubs", "eventhubs"] {
        assert!(check_binding("log", source_type, None, None, false).is_err(), "{source_type}");
    }
    assert!(check_binding("log", "sqs", Some(Uuid::new_v4()), Some(&cfg("aws_sqs", true)), true).is_ok());
    assert!(check_binding("log", "event_hubs", Some(Uuid::new_v4()), Some(&cfg("azure_event_hubs", true)), true).is_ok());
}
