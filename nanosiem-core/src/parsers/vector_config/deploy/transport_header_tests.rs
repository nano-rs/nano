// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4945: HTTP transport headers never reach a stored event, the client
//! address cannot be forged, and parsers still see the request Content-Type.
//!
//! The `http_ingest` source copies `Content-Type`, `X-Source-Type`,
//! `X-Forwarded-For`, `X-Real-IP` and the request `path` onto the event, and
//! (host_key) the TCP peer as `nano_ingest_peer`.
//! - `X-Source-Type`, `path` and the forwarding headers are dropped right after
//!   they are read, before `parse_content` merges the JSON body, so a body
//!   field of the same name is the sender's and stays.
//! - `client_ip` (the throttle key) is the TCP peer, or `X-Real-IP` when that
//!   peer is a trusted proxy (the nginx edge overwrites it). `X-Forwarded-For`
//!   is never believed. `ingest_client_ip` / `ingest_peer` are restored after
//!   the body merge, so a body cannot overwrite them.
//! - `Content-Type` stays on the event through the parsers and is dropped at the
//!   storage boundary (`ingest_transport_strip_vrl!`) when it still holds the
//!   header value.
//!
//! Executes the real VRL from 00-base.toml, the generic OCSF lane and the
//! per-parser OCSF prepare stage.

use vrl::value::Value;

use super::credential_header_tests::{json, run_chain, transform_in, transform_source};
use super::VectorConfigManager;

const EDGE_PEER: &str = "172.18.0.5";
const HEC: &str = include_str!("../../../../../config/vector/02-hec-source.toml");

fn http_request(body: &str, content_type: Option<&str>, peer: &str, real_ip: Option<&str>) -> Value {
    let mut event = serde_json::json!({
        "message": body,
        "path": "/ingest",
        "X-Source-Type": "nan4945_http",
        "X-Forwarded-For": "198.51.100.1, 203.0.113.9",
        "nano_ingest_peer": peer,
    });
    if let Some(ct) = content_type {
        event["Content-Type"] = ct.into();
    }
    if let Some(ip) = real_ip {
        event["X-Real-IP"] = ip.into();
    }
    json(event)
}

fn base_chain() -> Vec<(&'static str, String)> {
    let rate_limit_prep = transform_source("rate_limit_prep").replace(
        r#"get_env_var("NANO_INGEST_TRUSTED_PROXIES") ?? """#,
        r#""172.18.0.5/32""#,
    );
    vec![
        ("auth_check", transform_source("auth_check")),
        ("rate_limit_prep", rate_limit_prep),
        ("parse_content", transform_source("parse_content")),
        ("source_type_extract", transform_source("source_type_extract")),
    ]
}

fn direct_base_chain() -> Vec<(&'static str, String)> {
    vec![
        ("auth_check", transform_source("auth_check")),
        ("rate_limit_prep", transform_source("rate_limit_prep")),
        ("parse_content", transform_source("parse_content")),
        ("source_type_extract", transform_source("source_type_extract")),
    ]
}

fn pipeline_transform(name: &str) -> String {
    let content = VectorConfigManager::pipeline_config_content();
    let header = format!("[transforms.{name}]\n");
    let at = content.find(&header).unwrap_or_else(|| panic!("{name} transform"));
    let body = &content[at..];
    let open = body.find("source = '''\n").expect("remap source") + "source = '''\n".len();
    let close = body[open..].find("\n'''").expect("source terminator");
    body[open..open + close].to_string()
}

fn generic_parser() -> String {
    pipeline_transform("generic_parser")
}

/// The base chain, then the generic OCSF lane an unparsed (draft) source takes.
fn store_generic(event: Value) -> Value {
    let mut chain = base_chain();
    chain.push(("generic_parser", generic_parser()));
    chain.push((
        "generic_ocsf_prepare",
        transform_in(VectorConfigManager::GENERIC_OCSF_PREPARE_BLOCK, "generic_ocsf_prepare"),
    ));
    run_chain(event, &chain)
}

fn s(stored: &Value, path: &[&str]) -> Option<String> {
    let mut v = serde_json::to_value(stored).expect("event serializes");
    for seg in path {
        v = v.get(*seg)?.clone();
    }
    v.as_str().map(str::to_string)
}

fn unmapped(stored: &Value, key: &str) -> Option<String> {
    s(stored, &["event", "unmapped", key])
}

#[test]
fn transport_headers_are_read_then_dropped() {
    let stored = store_generic(http_request(
        r#"{"message":"hello","user":"alice"}"#,
        Some("application/json"),
        EDGE_PEER,
        Some("203.0.113.9"),
    ));
    let record = stored
        .as_object()
        .and_then(|o| o.get("event"))
        .and_then(|e| e.as_object())
        .and_then(|e| e.get("unmapped"))
        .and_then(|u| u.as_object())
        .expect("generic lane keeps the record under event.unmapped");
    for field in [
        "Content-Type",
        "content-type",
        "X-Source-Type",
        "X-Forwarded-For",
        "X-Real-IP",
        "path",
        "nano_ingest_peer",
    ] {
        assert!(!record.contains_key(field), "transport field `{field}` reached storage: {stored}");
    }
    // Every value the pipeline read from them is still derived.
    assert_eq!(s(&stored, &["source_type"]).as_deref(), Some("nan4945_http"), "{stored}");
    assert_eq!(unmapped(&stored, "request_path").as_deref(), Some("/ingest"));
    assert_eq!(unmapped(&stored, "content_format").as_deref(), Some("json"));
    // And the sender's payload is untouched.
    assert_eq!(unmapped(&stored, "user").as_deref(), Some("alice"));
    assert_eq!(s(&stored, &["event", "message"]).as_deref(), Some("hello"));
}

/// The edge replaces the forwarding chain after resolving only trusted proxy
/// hops. Vector consumes its X-Real-IP and never trusts the original chain.
#[test]
fn a_spoofed_forwarded_for_never_becomes_the_client_ip() {
    let stored = store_generic(http_request(
        r#"{"message":"m"}"#,
        Some("application/json"),
        EDGE_PEER,
        Some("203.0.113.9"),
    ));
    assert_eq!(unmapped(&stored, "client_ip").as_deref(), Some("203.0.113.9"));
    assert_eq!(unmapped(&stored, "ingest_client_ip").as_deref(), Some("203.0.113.9"));
    assert_eq!(unmapped(&stored, "ingest_peer").as_deref(), Some(EDGE_PEER));
    assert_ne!(unmapped(&stored, "client_ip").as_deref(), Some("198.51.100.1"));
}

/// A sender that reaches Vector directly cannot claim another address with
/// X-Real-IP: only a trusted proxy's X-Real-IP is believed.
#[test]
fn a_direct_sender_cannot_forge_x_real_ip() {
    let mut chain = direct_base_chain();
    chain.push(("generic_parser", generic_parser()));
    chain.push((
        "generic_ocsf_prepare",
        transform_in(VectorConfigManager::GENERIC_OCSF_PREPARE_BLOCK, "generic_ocsf_prepare"),
    ));
    let mut forged = http_request(
        r#"{"message":"m"}"#,
        Some("application/json"),
        "172.19.0.77",
        Some("10.9.9.9"),
    );
    forged
        .as_object_mut()
        .expect("event object")
        .insert("X-Nano-Edge-Client-IP".into(), "203.0.113.250".into());
    let forged_prep = run_chain(forged, &direct_base_chain()[..2]);
    assert_eq!(s(&forged_prep, &["client_ip"]).as_deref(), Some("172.19.0.77"));
    assert_eq!(s(&forged_prep, &["X-Nano-Edge-Client-IP"]), None);
    let stored = run_chain(
        http_request(r#"{"message":"m"}"#, Some("application/json"), "172.19.0.77", Some("10.9.9.9")),
        &chain,
    );
    assert_eq!(unmapped(&stored, "client_ip").as_deref(), Some("172.19.0.77"));
    assert_eq!(unmapped(&stored, "ingest_peer").as_deref(), Some("172.19.0.77"));

    // The throttle key is set before the body merge: it is the trusted value.
    let prepped = run_chain(
        http_request(r#"{"message":"m"}"#, None, "172.19.0.77", Some("10.9.9.9")),
        &direct_base_chain()[..2],
    );
    assert_eq!(s(&prepped, &["client_ip"]).as_deref(), Some("172.19.0.77"));
}

#[test]
fn role_split_edge_private_identity_survives_without_private_range_trust() {
    let mut event = http_request(r#"{"message":"m"}"#, None, EDGE_PEER, Some("192.0.2.250"));
    event
        .as_object_mut()
        .expect("event object")
        .insert("X-Nano-Edge-Client-IP".into(), "203.0.113.44".into());
    let prep = transform_source("rate_limit_prep").replace(
        r#"get_env_var("NANO_HEC_TRUST_EDGE_IDENTITY") ?? """#,
        r#""true""#,
    );
    let prepped = run_chain(
        event,
        &[("auth_check", transform_source("auth_check")), ("rate_limit_prep", prep)],
    );
    assert_eq!(s(&prepped, &["client_ip"]).as_deref(), Some("203.0.113.44"));
    assert_eq!(s(&prepped, &["X-Nano-Edge-Client-IP"]), None);
}

/// The body is sender data: it cannot overwrite the recorded ingest addresses.
#[test]
fn a_body_cannot_overwrite_the_ingest_addresses() {
    let stored = store_generic(http_request(
        r#"{"message":"m","ingest_client_ip":"1.2.3.4","ingest_peer":"1.2.3.4"}"#,
        Some("application/json"),
        EDGE_PEER,
        Some("203.0.113.9"),
    ));
    assert_eq!(unmapped(&stored, "ingest_client_ip").as_deref(), Some("203.0.113.9"));
    assert_eq!(unmapped(&stored, "ingest_peer").as_deref(), Some(EDGE_PEER));
}

#[test]
fn udm_root_replacement_restores_only_protected_ingest_identity() {
    let mut chain = base_chain();
    chain.push((
        "root_replacing_parser",
        r#". = { "message": "parsed", "client_ip": "1.2.3.4", "ingest_client_ip": "1.2.3.4", "ingest_peer": "1.2.3.4", "ext": { "client_ip": "5.6.7.8" } }"#.to_string(),
    ));
    chain.push(("clickhouse_mapping", pipeline_transform("clickhouse_mapping")));
    let stored = run_chain(
        http_request(r#"{"message":"m"}"#, Some("application/json"), EDGE_PEER, Some("203.0.113.9")),
        &chain,
    );
    assert_eq!(s(&stored, &["ext", "client_ip"]).as_deref(), Some("203.0.113.9"));
    assert_eq!(s(&stored, &["ext", "ingest_client_ip"]).as_deref(), Some("203.0.113.9"));
    assert_eq!(s(&stored, &["ext", "ingest_peer"]).as_deref(), Some(EDGE_PEER));
}

#[test]
fn hec_edge_identity_survives_envelope_host_and_parser_replacement() {
    let hec_normalize = transform_in(HEC, "hec_normalize").replace(
        r#"get_env_var("NANO_HEC_TRUST_EDGE_IDENTITY") ?? """#,
        r#""true""#,
    );
    let event = json(serde_json::json!({
        "splunk_sourcetype": "hec_identity_test",
        "splunk_channel": "sender-channel;nano-client=203.0.113.44",
        "host": "sender-controlled-host",
        "event": {"message": "hello", "client_ip": "1.2.3.4"}
    }));
    let normalized = run_chain(event.clone(), &[("hec_normalize", hec_normalize.clone())]);
    assert_eq!(s(&normalized, &["splunk_channel"]).as_deref(), Some("sender-channel"));

    let stored = run_chain(
        event,
        &[
            ("hec_normalize", hec_normalize),
            (
                "root_replacing_ocsf_parser",
                r#". = { "class_uid": 3002, "metadata": { "version": "1.8.0" }, "unmapped": { "client_ip": "5.6.7.8" } }"#.to_string(),
            ),
            ("ocsf_prepare", super::super::parser_config::OCSF_PREPARE_VRL.to_string()),
        ],
    );
    assert_eq!(unmapped(&stored, "client_ip").as_deref(), Some("203.0.113.44"));
    assert_eq!(unmapped(&stored, "ingest_client_ip").as_deref(), Some("203.0.113.44"));
    assert_ne!(unmapped(&stored, "client_ip").as_deref(), Some("sender-controlled-host"));
}

#[test]
fn direct_hec_sender_cannot_forge_the_private_edge_suffix() {
    let event = json(serde_json::json!({
        "splunk_sourcetype": "hec_identity_test",
        "splunk_channel": "sender-channel;nano-client=203.0.113.44",
        "event": {"message": "hello"}
    }));
    let stored = run_chain(
        event,
        &[
            ("hec_normalize", transform_in(HEC, "hec_normalize")),
            ("ocsf_prepare", super::super::parser_config::OCSF_PREPARE_VRL.to_string()),
        ],
    );
    assert_eq!(unmapped(&stored, "client_ip"), None);
    assert_eq!(unmapped(&stored, "ingest_client_ip"), None);
}

/// Web and proxy logs carry `path` (and sometimes `Content-Type`) as their own
/// fields: the body's values are data and must survive the transport cleanup.
#[test]
fn body_fields_named_like_transport_headers_survive() {
    let stored = store_generic(http_request(
        r#"{"message":"GET","path":"/var/www/index.html","Content-Type":"text/html","X-Forwarded-For":"198.51.100.9"}"#,
        Some("application/json"),
        EDGE_PEER,
        Some("203.0.113.9"),
    ));
    assert_eq!(unmapped(&stored, "path").as_deref(), Some("/var/www/index.html"));
    assert_eq!(unmapped(&stored, "Content-Type").as_deref(), Some("text/html"));
    assert_eq!(unmapped(&stored, "X-Forwarded-For").as_deref(), Some("198.51.100.9"));
    assert_eq!(unmapped(&stored, "request_path").as_deref(), Some("/ingest"));
}

/// Without a Content-Type the body is still sniffed as JSON: dropping the
/// headers changes storage, not decoding.
#[test]
fn decoding_without_content_type_is_unchanged() {
    let stored = store_generic(http_request(
        r#"{"message":"plain","user":"bob"}"#,
        None,
        EDGE_PEER,
        None,
    ));
    assert_eq!(unmapped(&stored, "content_format").as_deref(), Some("json"));
    assert_eq!(unmapped(&stored, "user").as_deref(), Some("bob"));
}

/// A deployed format-aware parser still selects its decoder from the request
/// Content-Type, and the header still never reaches the stored row.
#[test]
fn format_aware_parsers_still_see_the_content_type() {
    let parser = r#"
ct = downcase(to_string(."Content-Type") ?? "")
if starts_with(ct, "application/xml") {
    doc = object!(parse_xml!(string!(.message)))
    .user = doc.login.user
} else if starts_with(ct, "text/csv") {
    row = parse_csv!(string!(.message))
    .user = row[1]
} else {
    .user = "unparsed"
}
. = { "class_uid": 3002, "user": { "name": .user }, "metadata": { "version": "1.8.0" }, "Content-Type": ."Content-Type" }
"#;
    for (ct, body) in [
        ("application/xml", "<login><user>alice</user></login>"),
        ("text/csv", "login,carol,ok"),
    ] {
        let mut chain = base_chain();
        chain.push(("parser", parser.to_string()));
        chain.push(("ocsf_prepare", super::super::parser_config::OCSF_PREPARE_VRL.to_string()));
        let stored = run_chain(http_request(body, Some(ct), EDGE_PEER, Some("203.0.113.9")), &chain);
        let expected = if ct == "text/csv" { "carol" } else { "alice" };
        assert_eq!(
            s(&stored, &["event", "user", "name"]).as_deref(),
            Some(expected),
            "{ct}: the parser must see the request Content-Type: {stored}"
        );
        assert_eq!(
            s(&stored, &["event", "Content-Type"]),
            None,
            "{ct}: the transport Content-Type must not be stored: {stored}"
        );
        assert_eq!(unmapped(&stored, "client_ip").as_deref(), Some("203.0.113.9"));
        assert_eq!(unmapped(&stored, "ingest_peer").as_deref(), Some(EDGE_PEER));
    }
}
