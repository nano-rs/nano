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
