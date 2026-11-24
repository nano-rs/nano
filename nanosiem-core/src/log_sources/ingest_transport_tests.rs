// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

/// Every value the import UI sends (`ParserRepositories.tsx` SOURCE_TYPE_MAP)
/// and every alias the renderer understands stays accepted.
#[test]
fn accepts_every_ui_method_and_alias() {
    for (input, want) in [
        ("routed", "routed"),
        ("http", "routed"),
        ("vector", "vector"),
        ("otlp", "otlp"),
        ("opentelemetry", "otlp"),
        ("otel", "otlp"),
        ("splunk_hec", "splunk_hec"),
        ("splunk", "splunk_hec"),
        ("hec", "splunk_hec"),
        ("kafka", "kafka"),
        ("aws_s3", "aws_s3"),
        ("s3", "aws_s3"),
        ("aws_sqs", "aws_sqs"),
        ("gcp_pubsub", "gcp_pubsub"),
        ("pubsub", "gcp_pubsub"),
        ("azure_event_hubs", "azure_event_hubs"),
        ("file", "file"),
        ("syslog", "syslog"),
        ("stdin", "stdin"),
        ("  Kafka ", "kafka"),
    ] {
        assert_eq!(canonical(input), Some(want), "{input}");
    }
}

/// Every canonical name maps to itself, so storing the canonical value is
/// idempotent.
#[test]
fn canonical_names_are_fixed_points() {
    for name in SUPPORTED {
        assert_eq!(canonical(name), Some(*name));
    }
}

/// NAN-5033: the exploit shape (a quote + newline breaking out of the VRL
/// literal) and anything else outside the set is refused.
#[test]
fn refuses_injection_and_unknown_methods() {
    for input in [
        "routed\"\n.x = get_env_var!(\"CLICKHOUSE_PASSWORD\")\n#",
        "routed\"",
        "apache_access",
        "",
        "k afka",
    ] {
        assert_eq!(canonical(input), None, "{input:?}");
    }
    let message = unsupported_message("ingestion_method", "a\"\nb");
    assert!(!message.contains('\n'), "control characters must be escaped: {message}");
}

/// NAN-5789: a fetch method pairs only with a configuration of its own type,
/// whatever the spelling on either side.
#[test]
fn dispatch_compatible_pairs_each_fetch_method_with_its_own_type_only() {
    let fetch = ["kafka", "aws_s3", "aws_sqs", "crowdstrike_fdr", "gcp_pubsub", "azure_event_hubs"];
    for method in fetch {
        for config in fetch.iter().chain(["http", "splunk_hec", "otlp", "vector"].iter()) {
            assert_eq!(dispatch_compatible(config, method), *config == method, "{config} feeding {method}");
        }
    }
    // Aliases and case on both sides.
    assert!(dispatch_compatible("S3", "aws_s3"));
    assert!(dispatch_compatible("aws_s3", "S3"));
    assert!(dispatch_compatible("pubsub", "PubSub"));
    assert!(dispatch_compatible("fdr", "crowdstrike_fdr"));
    assert!(dispatch_compatible("KAFKA", "Kafka"));
    assert!(dispatch_compatible("http", "HTTP"));
    assert!(dispatch_compatible("hec", "splunk"));
    // Unknown on either side fails closed.
    assert!(!dispatch_compatible("rabbitmq", "kafka"));
    assert!(!dispatch_compatible("kafka", "rabbitmq"));
}

/// NAN-5789 round 2: every alias any vocabulary accepts (`SourceConfigType`,
/// `parsers::types::SourceType`) is in the one table, and every classifier
/// built on it agrees.
#[test]
fn the_one_alias_table_covers_every_vocabulary() {
    for (alias, want) in [
        ("sqs", "aws_sqs"),
        ("fdr", "crowdstrike_fdr"),
        ("event_hubs", "azure_event_hubs"),
        ("eventhubs", "azure_event_hubs"),
        ("EventHubs", "azure_event_hubs"),
    ] {
        assert_eq!(canonical(alias), Some(want), "{alias}");
        assert!(is_fetch(alias), "{alias}");
        assert!(crate::parsers::is_fetch_source_type(alias), "{alias}");
        assert!(dispatch_compatible(alias, want), "{alias} config feeding {want}");
        assert!(dispatch_compatible(want, alias), "{want} config feeding {alias}");
    }
    // Every config type SourceConfigType accepts canonicalizes to its as_str().
    for alias in ["http", "kafka", "s3", "sqs", "fdr", "pubsub", "event_hubs", "eventhubs", "splunk", "hec", "vector", "otel", "opentelemetry"] {
        let parsed = crate::source_configs::SourceConfigType::from_str(alias).unwrap();
        assert_eq!(canonical_config_type(alias), Some(parsed.as_str()), "{alias}");
    }
    // Every fetch type the parser vocabulary accepts is a fetch here too.
    for alias in ["kafka", "aws_s3", "s3", "aws_sqs", "sqs", "crowdstrike_fdr", "fdr", "gcp_pubsub", "pubsub", "azure_event_hubs"] {
        assert!(crate::parsers::SourceType::from_str(alias).is_some(), "{alias}");
        assert!(is_fetch(alias), "{alias}");
    }
    for push in ["routed", "http", "vector", "otlp", "splunk_hec", "file", "syslog", "stdin", "nonsense"] {
        assert!(!is_fetch(push), "{push}");
    }
}
