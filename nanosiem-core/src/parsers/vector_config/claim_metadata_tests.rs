// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4912 (codex P2-3): a token-bound sender's differing `source_type`
//! claim survives a parser that replaces the event root, on both the UDM and
//! the OCSF lane. The ingest lanes stash it in event METADATA
//! (`%nano_claimed_source_type`, which a sender cannot set); the generated UDM
//! `_output` and `OCSF_PREPARE_VRL` restore it after the parser ran.
//!
//! Runs the shipped lane VRL (00-base `source_type_extract`, 02-hec
//! `hec_normalize`) and the generated parser chain on the VRL runtime.

use chrono::Utc;
use serde_json::{json, Value};
use uuid::Uuid;

use super::parser_config::OCSF_PREPARE_VRL;
use super::VectorConfigManager;
use crate::parsers::types::Parser;

const BASE: &str = include_str!("../../../../config/vector/00-base.toml");
const HEC: &str = include_str!("../../../../config/vector/02-hec-source.toml");

fn transform_source(config: &str, name: &str) -> String {
    let substituted = regex::Regex::new(r"\$\{[A-Z0-9_]+:-([^}]*)\}")
        .unwrap()
        .replace_all(config, "$1");
    let table: toml::Table = substituted.parse().expect("config parses");
    table["transforms"][name]["source"]
        .as_str()
        .unwrap_or_else(|| panic!("{name} has a VRL source"))
        .to_string()
}

/// Runs `program`; returns (event, metadata). Panics on abort or error.
fn run(program: &str, event: Value, metadata: Value) -> (Value, Value) {
    let compiled = vrl::compiler::compile(program, &vrl::stdlib::all())
        .unwrap_or_else(|d| panic!("VRL compiles: {d:?}"))
        .program;
    let mut target = vrl::compiler::TargetValue {
        value: vrl::value::Value::from(event),
        metadata: vrl::value::Value::from(metadata),
        secrets: vrl::value::Secrets::new(),
    };
    vrl::compiler::runtime::Runtime::new(vrl::compiler::state::RuntimeState::default())
        .resolve(&mut target, &compiled, &vrl::compiler::TimeZone::Local)
        .unwrap_or_else(|e| panic!("VRL runtime: {e:?}"));
    (
        target.value.try_into().expect("event json"),
        target.metadata.try_into().expect("metadata json"),
    )
}

const TOKEN: &str = "0b9a3c34-4cbb-4c1e-9d0f-6a3bd1f0f7e1";

fn stamp() -> Value {
    json!({ "nano_credential_id": TOKEN, "nano_credential_name": "acme_vpn" })
}

fn parser(vrl: &str) -> Parser {
    Parser {
        activation_parked: false,
        id: Uuid::new_v4(),
        name: "acme_vpn".into(),
        description: None,
        source_type: "routed".into(),
        parser_vrl: vrl.into(),
        output_fields: None,
        feed_id: None,
        dispatch_source_config_id: None,
        dispatch_route_name: None,
        namespace: "default".into(),
        enabled: true,
        validated: true,
        validation_error: None,
        timezone: "UTC".into(),
        match_values: Some(vec!["acme_vpn".into()]),
        sampling_ratio: None,
        sampling_exclude_condition: None,
        extension_vrl: None,
        extension_enabled: false,
        category: None,
        vendor: None,
        product: None,
        kind: "log".into(),
        enrich_kind: None,
        enrich_source: None,
        target_table: None,
        normalize_vrl: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

/// The HTTP lane stamps the claim into metadata (and still onto the event).
fn http_lane(claimed: &str) -> (Value, Value) {
    run(
        &transform_source(BASE, "source_type_extract"),
        json!({ "message": "m", "source_type": claimed }),
        stamp(),
    )
}

#[test]
fn ingest_lanes_stash_the_claim_in_metadata() {
    let (event, meta) = http_lane("audit");
    assert_eq!(event["source_type"], "acme_vpn");
    assert_eq!(event["claimed_source_type"], "audit");
    assert_eq!(meta["nano_claimed_source_type"], "audit");

    let (event, meta) = run(
        &transform_source(HEC, "hec_normalize"),
        json!({ "message": "m", "sourcetype": "audit" }),
        stamp(),
    );
    assert_eq!(event["source_type"], "acme_vpn");
    assert_eq!(meta["nano_claimed_source_type"], "audit");

    // No differing claim: nothing stashed, and a stale metadata value a
    // previous component left is cleared.
    let (_, meta) = run(
        &transform_source(BASE, "source_type_extract"),
        json!({ "message": "m", "source_type": "acme_vpn" }),
        json!({ "nano_credential_id": TOKEN, "nano_credential_name": "acme_vpn", "nano_claimed_source_type": "forged" }),
    );
    assert!(meta.get("nano_claimed_source_type").map_or(true, Value::is_null), "{meta}");
}

#[test]
fn udm_output_restores_the_claim_after_a_root_replacing_parser() {
    let _udm = crate::schema::pin_active_schema_for_test(crate::schema::SchemaId::Udm);
    let config = VectorConfigManager::new("/tmp/nanosiem-test")
        .generate_parser_config_string(&parser(r#". = { "message": .message, "ext": { "rebuilt": true } }"#));
    let parse_vrl = transform_source(&config, "acme_vpn_parse");
    let output_vrl = transform_source(&config, "acme_vpn_output");

    let (event, meta) = http_lane("audit");
    let (parsed, meta) = run(&parse_vrl, event, meta);
    assert!(parsed.get("claimed_source_type").is_none(), "the parser wiped the root: {parsed}");
    let (out, _) = run(&output_vrl, parsed, meta);
    assert_eq!(out["claimed_source_type"], "audit", "{out}");
    assert_eq!(out["ext"]["rebuilt"], true);
}

#[test]
fn ocsf_prepare_restores_the_claim_under_unmapped() {
    let (_, meta) = http_lane("audit");
    let mut meta = meta;
    meta["source_type"] = json!("acme_vpn");
    // An OCSF parser replaced the root with an OCSF object.
    let ocsf = json!({ "class_uid": 3002, "time": 1762164000000i64, "metadata": { "product": { "name": "vpn" } } });
    let (row, _) = run(OCSF_PREPARE_VRL, ocsf, meta);
    assert_eq!(row["source_type"], "acme_vpn");
    assert_eq!(row["event"]["unmapped"]["claimed_source_type"], "audit", "{row}");
    assert_eq!(row["event"]["metadata"]["log_source"], "acme_vpn");

    // No claim: the event is not touched.
    let (row, _) = run(OCSF_PREPARE_VRL, json!({ "class_uid": 3002 }), json!({ "source_type": "acme_vpn" }));
    assert!(row["event"].get("unmapped").is_none(), "{row}");
}
