// SPDX-License-Identifier: AGPL-3.0-or-later

//! Generic JSON-over-HTTP contracts.
//!
//! The HTTP edge owns transport decoding only. A JSON object is the source
//! event, including a top-level string named `message`; source-specific parser
//! VRL decides whether that field has envelope semantics. JSON arrays are
//! expanded before source routing so every member traverses the configured
//! parser and receives its own durable sink finalizer.

use vrl::value::Value;

use super::credential_header_tests::{json, run_chain, run_chain_with_metadata, transform_source};

const BASE: &str = include_str!("../../../../../config/vector/00-base.toml");

fn request(body: &str, content_type: Option<&str>) -> Value {
    let mut event = serde_json::json!({
        "message": body,
        "path": "/ingest",
        "X-Source-Type": "json_generic",
        "nano_ingest_peer": "192.0.2.10",
    });
    if let Some(content_type) = content_type {
        event["Content-Type"] = content_type.into();
    }
    json(event)
}

fn through_content_parser(body: &str, content_type: Option<&str>) -> Value {
    run_chain(
        request(body, content_type),
        &[
            ("auth_check", transform_source("auth_check")),
            ("rate_limit_prep", transform_source("rate_limit_prep")),
            ("parse_content", transform_source("parse_content")),
        ],
    )
}

fn through_batch_expansion(body: &str, content_type: Option<&str>) -> Value {
    run_chain(
        request(body, content_type),
        &[
            ("auth_check", transform_source("auth_check")),
            ("rate_limit_prep", transform_source("rate_limit_prep")),
            ("parse_content", transform_source("parse_content")),
            ("json_batch_expand", transform_source("json_batch_expand")),
        ],
    )
}

fn string_at(value: &Value, key: &str) -> Option<String> {
    let json = serde_json::to_value(value).ok()?;
    json.get(key)?.as_str().map(str::to_owned)
}

#[test]
fn json_object_message_field_does_not_replace_the_source_record() {
    let body = r#"{"timestamp":"2026-11-08T15:24:27Z","message":"connection allowed","src_ip":"10.0.0.7","nested":{"objects":[{"name":"a"},{"name":"b"}]}}"#;
    let parsed = through_content_parser(body, Some("application/json"));

    assert_eq!(string_at(&parsed, "message").as_deref(), Some(body));
    let nested = parsed
        .as_object()
        .and_then(|object| object.get("nested"))
        .and_then(Value::as_object)
        .expect("nested object stays typed");
    let objects = nested
        .get("objects")
        .and_then(Value::as_array)
        .expect("object array stays typed");
    assert_eq!(objects.len(), 2);
    assert!(objects.iter().all(|value| value.is_object()));
}

#[test]
fn ndjson_record_message_field_does_not_replace_the_source_record() {
    let body =
        r#"{"timestamp":"2026-11-08T15:24:28Z","message":"ndjson member","src_ip":"10.0.0.8"}"#;
    let parsed = through_content_parser(body, Some("application/x-ndjson"));

    assert_eq!(string_at(&parsed, "message").as_deref(), Some(body));
    assert_eq!(string_at(&parsed, "src_ip").as_deref(), Some("10.0.0.8"));
}

#[test]
fn user_nano_json_batch_field_is_not_a_transport_control() {
    let body = r#"{"timestamp":"2026-11-08T15:24:29Z","message":"ordinary event","src_ip":"10.0.0.9","nano_json_batch":[{"legitimate":true}]}"#;
    let parsed = through_content_parser(body, Some("application/json"));
    let after_expand = run_chain(
        parsed,
        &[("json_batch_expand", transform_source("json_batch_expand"))],
    );
    let normalized = run_chain(
        after_expand,
        &[(
            "json_batch_normalize",
            transform_source("json_batch_normalize"),
        )],
    );
    let normalized = serde_json::to_value(normalized).expect("event serializes");

    assert!(normalized.is_object(), "ordinary object must not fan out");
    assert_eq!(
        normalized["nano_json_batch"],
        serde_json::json!([{"legitimate": true}])
    );
    assert_eq!(normalized["message"].as_str(), Some(body));
}

#[test]
fn credential_fields_are_removed_before_json_records_reach_a_parser() {
    let secret = "must-not-reach-parser";
    let object_body = format!(
        r#"{{"message":"login","src_ip":"10.0.0.6","Authorization":"Bearer {secret}","headers":{{"Cookie":"{secret}","Accept":"*/*"}}}}"#
    );
    let object = through_content_parser(&object_body, Some("application/json"));
    let object_json = serde_json::to_value(&object).expect("single object serializes");
    let parser_record: serde_json::Value = serde_json::from_str(
        object_json["message"]
            .as_str()
            .expect("parser message remains JSON"),
    )
    .expect("sanitized parser message parses");
    assert_eq!(
        parser_record
            .pointer("/headers/Accept")
            .and_then(serde_json::Value::as_str),
        Some("*/*")
    );
    assert!(!object_json.to_string().contains(secret));
    assert!(parser_record.get("Authorization").is_none());
    assert!(parser_record.pointer("/headers/Cookie").is_none());

    let array_body = format!(
        r#"[{{"message":"login","src_ip":"10.0.0.6","x-api-key":"{secret}","nested":{{"X-Webhook-Secret":"{secret}","keep":true}}}}]"#
    );
    let expanded = through_batch_expansion(&array_body, Some("application/json"));
    let member = expanded
        .as_array()
        .and_then(|members| members.first())
        .cloned()
        .expect("one array member");
    let normalized = run_chain_with_metadata(
        member,
        json(serde_json::json!({"nano_json_batch_member": true})),
        &[(
            "json_batch_normalize",
            transform_source("json_batch_normalize"),
        )],
    );
    let normalized = serde_json::to_value(normalized).expect("array member serializes");
    assert!(!normalized.to_string().contains(secret));
    assert_eq!(
        normalized
            .pointer("/nested/keep")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
}

#[test]
fn json_arrays_are_expanded_between_decode_and_source_routing() {
    let document: toml::Value = toml::from_str(BASE).expect("00-base.toml parses");
    let transforms = document["transforms"].as_table().expect("transforms table");

    let expand = transforms
        .get("json_batch_expand")
        .expect("JSON arrays have an expansion transform");
    assert_eq!(
        expand["inputs"]
            .as_array()
            .and_then(|inputs| inputs.first())
            .and_then(toml::Value::as_str),
        Some("parse_content")
    );
    let normalize = transforms
        .get("json_batch_normalize")
        .expect("expanded members have a normalization transform");
    assert_eq!(
        normalize["inputs"]
            .as_array()
            .and_then(|inputs| inputs.first())
            .and_then(toml::Value::as_str),
        Some("json_batch_expand")
    );
    assert_eq!(
        transforms["source_type_extract"]["inputs"]
            .as_array()
            .and_then(|inputs| inputs.first())
            .and_then(toml::Value::as_str),
        Some("json_batch_normalize")
    );
}

#[test]
fn json_array_members_reach_the_parser_as_independent_typed_records() {
    let body = r#"[{"timestamp":"2026-10-08T15:24:27Z","message":"first","src_ip":"10.0.0.7","objects":[{"name":"a"},{"name":"b"}]},{"timestamp":"2026-10-08T15:24:28Z","message":"second","src_ip":"10.0.0.8","objects":[{"name":"c"}]}]"#;
    let expanded = through_batch_expansion(body, Some("application/json"));
    let members = expanded
        .as_array()
        .expect("unnest emits one log object per member");
    assert_eq!(members.len(), 2);

    let parser = r#"
p = object!(parse_json!(string!(.message)))
event_time = parse_timestamp!(string!(p.timestamp), "%+")
. = {
    "class_uid": 4001,
    "category_uid": 4,
    "activity_id": 6,
    "type_uid": 400106,
    "time": to_unix_timestamp!(event_time, unit: "milliseconds"),
    "message": string!(p.message),
    "metadata": { "version": "1.9.0" },
    "src_endpoint": { "ip": string!(p.src_ip) },
    "unmapped": p
}
"#;

    for (index, member) in members.iter().cloned().enumerate() {
        let stored = run_chain_with_metadata(
            member,
            json(serde_json::json!({"nano_json_batch_member": true})),
            &[
                (
                    "json_batch_normalize",
                    transform_source("json_batch_normalize"),
                ),
                (
                    "source_type_extract",
                    transform_source("source_type_extract"),
                ),
                ("json_source_parser", parser.to_string()),
                (
                    "ocsf_prepare",
                    super::super::parser_config::OCSF_PREPARE_VRL.to_string(),
                ),
            ],
        );
        let stored = serde_json::to_value(stored).expect("stored event serializes");
        let event = stored.get("event").expect("OCSF event");
        assert_eq!(
            event.get("class_uid").and_then(serde_json::Value::as_u64),
            Some(4001)
        );
        assert_eq!(
            stored
                .get("source_type")
                .and_then(serde_json::Value::as_str),
            Some("json_generic")
        );
        assert_eq!(
            event
                .pointer("/src_endpoint/ip")
                .and_then(serde_json::Value::as_str),
            Some(if index == 0 { "10.0.0.7" } else { "10.0.0.8" })
        );
        assert_eq!(
            stored.get("timestamp").and_then(serde_json::Value::as_str),
            Some(if index == 0 {
                "2026-10-08 15:24:27.000"
            } else {
                "2026-10-08 15:24:28.000"
            })
        );
        let objects = event
            .pointer("/unmapped/objects")
            .and_then(serde_json::Value::as_array)
            .expect("nested array remains typed");
        assert_eq!(objects.len(), if index == 0 { 2 } else { 1 });
        assert!(objects.iter().all(serde_json::Value::is_object));
    }
}
