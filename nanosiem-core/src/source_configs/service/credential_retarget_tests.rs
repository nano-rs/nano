// SPDX-License-Identifier: AGPL-3.0-or-later
//! A bound stored credential cannot be moved to a new connection host without
//! credential-owner permission (security review 2026-11-09, NAN-5147).

use super::*;
use serde_json::json;

#[test]
fn kafka_broker_change_is_a_move() {
    let old = json!({"bootstrap_servers": "kafka-1.corp:9092,kafka-2.corp:9092", "group_id": "g"});
    let new = json!({"bootstrap_servers": "broker.elsewhere.example:9092", "group_id": "g"});
    assert!(moves_credential_destination("kafka", &old, "kafka", &new));
}

#[test]
fn kafka_broker_reorder_and_non_host_edits_are_not_a_move() {
    let old = json!({"bootstrap_servers": "kafka-1.corp:9092,kafka-2.corp:9092", "group_id": "g", "topics": ["a"]});
    let new = json!({"bootstrap_servers": " KAFKA-2.corp:9092 , kafka-1.corp:9092", "group_id": "g2", "topics": ["a", "b"]});
    assert!(!moves_credential_destination("kafka", &old, "kafka", &new));
}

#[test]
fn kafka_first_broker_configuration_is_a_move() {
    // Fail closed: a bound credential on an unconfigured source must not be
    // pointed at its first broker without credential-owner approval.
    let new = json!({"bootstrap_servers": "kafka-1.corp:9092"});
    assert!(moves_credential_destination("kafka", &json!({}), "kafka", &new));
}

#[test]
fn gcp_pubsub_endpoint_change_is_a_move() {
    let old = json!({"project": "p", "subscription": "s"});
    let new = json!({"project": "p", "subscription": "s", "endpoint": "https://pubsub.elsewhere.example"});
    assert!(moves_credential_destination("gcp_pubsub", &old, "gcp_pubsub", &new));
    let tuned = json!({"project": "p", "subscription": "s2", "ack_deadline_secs": 60});
    assert!(!moves_credential_destination("gcp_pubsub", &old, "gcp_pubsub", &tuned));
}

#[test]
fn azure_namespace_and_checkpoint_account_changes_are_moves() {
    let old = json!({"namespace": "acme-logs", "event_hub_name": "h", "checkpoint_account": "acmeckpt"});
    let same = json!({"namespace": "acme-logs.servicebus.windows.net", "event_hub_name": "h2", "checkpoint_account": "ACMECKPT"});
    assert!(!moves_credential_destination("azure_event_hubs", &old, "azure_event_hubs", &same));
    let ns = json!({"namespace": "other-logs", "event_hub_name": "h", "checkpoint_account": "acmeckpt"});
    assert!(moves_credential_destination("azure_event_hubs", &old, "azure_event_hubs", &ns));
    let ckpt = json!({"namespace": "acme-logs", "event_hub_name": "h", "checkpoint_account": "otherckpt"});
    assert!(moves_credential_destination("azure_event_hubs", &old, "azure_event_hubs", &ckpt));
}

#[test]
fn system_level_drivers_have_no_destination_and_unknown_drivers_fail_closed() {
    for t in ["http", "vector", "splunk_hec", "otlp"] {
        assert!(!moves_credential_destination(t, &json!({}), t, &json!({"x": 1})), "{t}");
    }
    assert!(moves_credential_destination("future_driver", &json!({}), "future_driver", &json!({})));
    assert!(connection_destination("future_driver", &json!({})).is_none());
    // Driver aliases resolve to the same driver, not a "change".
    let conn = json!({"queue_url": "https://sqs.us-east-1.amazonaws.com/1/q"});
    assert!(!moves_credential_destination("sqs", &conn, "aws_sqs", &conn));
}

#[test]
fn every_known_driver_is_listed_explicitly() {
    for t in [
        "http", "kafka", "aws_s3", "aws_sqs", "gcp_pubsub", "azure_event_hubs", "splunk_hec",
        "vector", "otlp",
    ] {
        assert!(
            crate::source_configs::types::SourceConfigType::from_str(t).is_some(),
            "{t} is a known driver"
        );
        assert!(connection_destination(t, &json!({})).is_some(), "{t} must be listed");
    }
}

#[test]
fn aws_endpoint_changes_are_moves() {
    let old = json!({"queue_url": "https://sqs.us-east-1.amazonaws.com/1/q", "region": "us-east-1"});
    let custom = json!({"queue_url": "https://sqs.us-east-1.amazonaws.com/1/q", "endpoint": "https://minio.elsewhere.example"});
    assert!(moves_credential_destination("aws_sqs", &old, "aws_sqs", &custom), "custom endpoint appearing");
    let moved = json!({"queue_url": "https://sqs.us-east-1.amazonaws.com/1/q", "endpoint": "https://other.example"});
    assert!(moves_credential_destination("aws_sqs", &custom, "aws_sqs", &moved), "custom endpoint host change");
    let queue_host = json!({"queue_url": "https://queue.elsewhere.example/1/q"});
    assert!(moves_credential_destination("aws_sqs", &old, "aws_sqs", &queue_host), "queue_url host change");
    let s3_old = json!({"sqs_queue_url": "https://sqs.eu-west-1.amazonaws.com/1/q", "endpoint": "https://minio.corp:9000"});
    let s3_new = json!({"sqs_queue_url": "https://sqs.eu-west-1.amazonaws.com/1/q", "endpoint": "https://minio.corp:9001"});
    assert!(moves_credential_destination("aws_s3", &s3_old, "aws_s3", &s3_new), "port change");
}

#[test]
fn aws_same_host_edits_are_not_moves() {
    let old = json!({"queue_url": "https://sqs.us-east-1.amazonaws.com/1/q", "poll_secs": 15});
    let new = json!({"queue_url": "https://sqs.us-east-1.amazonaws.com/1/other-q", "poll_secs": 30});
    assert!(!moves_credential_destination("aws_sqs", &old, "aws_sqs", &new));
    let s3 = json!({"sqs_queue_url": "https://sqs.eu-west-1.amazonaws.com/1/q", "endpoint": "https://minio.corp:9000"});
    let s3_tuned = json!({"sqs_queue_url": "https://sqs.eu-west-1.amazonaws.com/1/q", "endpoint": "https://MINIO.corp:9000/", "client_concurrency": 4});
    assert!(!moves_credential_destination("aws_s3", &s3, "aws_s3", &s3_tuned));
}

#[test]
fn driver_change_is_a_move() {
    let conn = json!({"bootstrap_servers": "kafka-1.corp:9092"});
    assert!(moves_credential_destination("kafka", &conn, "aws_sqs", &json!({})));
}
