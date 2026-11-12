// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4963: an OCSF row records the lane its event was claimed on.
//!
//! An OCSF parser replaces the event root, so `_ocsf_prepare` takes the row's
//! `source_type` and the event's `metadata.log_source` from `%source_type`
//! event metadata. The Splunk HEC, Vector-native and OTLP lanes never stashed
//! it, so connector feeds (Okta, Google Workspace, Slack: `sourcetype=<lane>`
//! over HEC with the platform token) landed as `unknown`. Under OCSF every
//! parser now stamps the lane on its own input (`<name>_source_lane`).
//!
//! The chain tests run the shipped `hec_normalize` VRL and the generated
//! parser components on the VRL runtime; the render tests pin the topology on
//! every lane and the UDM render staying free of the stamp.

use chrono::Utc;
use serde_json::{json, Value};
use uuid::Uuid;

use super::parser_config::{OCSF_LANE_STAMP_SUFFIX, OCSF_LANE_STAMP_VRL};
use super::VectorConfigManager;
use crate::parsers::pipe::{Plan, Step};
use crate::parsers::types::Parser;

const HEC: &str = include_str!("../../../../config/vector/02-hec-source.toml");

/// A cut-down `okta_ocsf`: like the first-party parser it replaces the root
/// with an OCSF object and does NOT set `metadata.log_source`.
const OKTA_LIKE_VRL: &str = r#"raw = object!(parse_json!(.message))
. = {
  "class_uid": 3007,
  "category_uid": 3,
  "activity_id": 1,
  "time": 1762164000000,
  "user": { "name": raw.target[0].alternateId },
  "actor": { "user": { "name": raw.actor.alternateId } },
  "metadata": { "uid": raw.uuid, "product": { "name": "Okta System Log", "vendor_name": "Okta" } }
}"#;

fn okta_event() -> Value {
    json!({
        "uuid": "e2e-uuid-1",
        "eventType": "user.lifecycle.create",
        "actor": { "alternateId": "admin@example.com" },
        "target": [{ "alternateId": "new.user@example.com" }]
    })
}

fn parser(name: &str, source_type: &str, lanes: &[&str], vrl: &str) -> Parser {
    Parser {
        activation_parked: false,
        id: Uuid::new_v4(),
        name: name.into(),
        description: None,
        source_type: source_type.into(),
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
        match_values: Some(lanes.iter().map(|s| s.to_string()).collect()),
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

fn manager() -> (tempfile::TempDir, VectorConfigManager) {
    let dir = tempfile::tempdir().expect("tempdir");
    let m = VectorConfigManager::new(dir.path());
    (dir, m)
}

fn render(p: &Parser, ocsf: bool) -> String {
    let (_dir, m) = manager();
    m.generate_parser_config_for(p, ocsf)
}

fn transforms(config: &str) -> toml::Table {
    let doc: toml::Table = config.parse().expect("generated config is valid TOML");
    doc["transforms"].as_table().unwrap().clone()
}

fn inputs(t: &toml::Table, name: &str) -> Vec<String> {
    t[name]["inputs"]
        .as_array()
        .unwrap_or_else(|| panic!("{name} has inputs"))
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect()
}

fn source(t: &toml::Table, name: &str) -> String {
    t[name]["source"]
        .as_str()
        .unwrap_or_else(|| panic!("{name} has a VRL source"))
        .to_string()
}

fn hec_normalize_vrl() -> String {
    let substituted = regex::Regex::new(r"\$\{[A-Z0-9_]+:-([^}]*)\}")
        .unwrap()
        .replace_all(HEC, "$1");
    let table: toml::Table = substituted.parse().expect("02-hec-source parses");
    table["transforms"]["hec_normalize"]["source"]
        .as_str()
        .unwrap()
        .to_string()
}

/// Runs `program`; returns (event, metadata). Panics on abort or error.
fn run(program: &str, event: Value, metadata: Value) -> (Value, Value) {
    let compiled = vrl::compiler::compile(program, &vrl::stdlib::all())
        .unwrap_or_else(|d| panic!("VRL compiles: {d:?}\n{program}"))
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

/// What `nano-connector-runner` sends for an `okta_system_log` feed: the
/// platform credential (multiplex route `*`), `sourcetype=okta`, the System
/// Log record as the HEC event. Returns `hec_normalize`'s output.
fn connector_hec_event() -> (Value, Value) {
    run(
        &hec_normalize_vrl(),
        json!({ "event": okta_event(), "splunk_sourcetype": "okta" }),
        json!({ "nano_credential_id": "00000000-0000-0000-0000-00000000p1a7", "nano_credential_name": "*" }),
    )
}

/// The HEC parser's components after `splunk_hec_route` (a passthrough) and
/// its filter: stamp (when rendered), parse, OCSF prepare. Returns the row.
fn through_parser(config: &str, name: &str, event: Value, meta: Value) -> Value {
    let t = transforms(config);
    let stamp = format!("{name}{OCSF_LANE_STAMP_SUFFIX}");
    let (event, meta) = if t.contains_key(&stamp) {
        run(&source(&t, &stamp), event, meta)
    } else {
        (event, meta)
    };
    let (event, meta) = run(&source(&t, &format!("{name}_parse")), event, meta);
    let (row, _) = run(&source(&t, &format!("{name}_ocsf_prepare")), event, meta);
    row
}

#[test]
fn hec_connector_event_lands_on_its_lane() {
    let p = parser("okta_ocsf", "splunk_hec", &["okta"], OKTA_LIKE_VRL);
    let (event, meta) = connector_hec_event();
    assert_eq!(event["source_type"], "okta", "multiplex credential keeps the declared type");

    let row = through_parser(&render(&p, true), "okta_ocsf", event.clone(), meta.clone());
    assert_eq!(row["source_type"], "okta", "{row}");
    assert_eq!(row["event"]["metadata"]["log_source"], "okta", "{row}");
    assert_eq!(row["event"]["class_uid"], 3007);
    assert_eq!(row["event"]["user"]["name"], "new.user@example.com");

    // The defect this fixes: the same chain without the stamp (the pre-fix
    // render) lands as `unknown`, because nothing on the HEC lane stashes it.
    let mut pre_fix = render(&p, true);
    pre_fix = pre_fix.replace(OCSF_LANE_STAMP_VRL, "# no stamp");
    let row = through_parser(&pre_fix, "okta_ocsf", event, meta);
    assert_eq!(row["source_type"], "unknown", "{row}");
    assert_eq!(row["event"]["metadata"]["log_source"], "unknown", "{row}");
}

#[test]
fn a_parser_that_sets_its_own_log_source_or_source_type_wins() {
    let (event, meta) = connector_hec_event();

    let explicit_log_source = format!("{OKTA_LIKE_VRL}\n.metadata.log_source = \"okta_custom\"");
    let p = parser("okta_ocsf", "splunk_hec", &["okta"], &explicit_log_source);
    let row = through_parser(&render(&p, true), "okta_ocsf", event.clone(), meta.clone());
    assert_eq!(row["event"]["metadata"]["log_source"], "okta_custom", "{row}");
    assert_eq!(row["source_type"], "okta", "the row column is still the lane");

    let explicit_source_type = format!("{OKTA_LIKE_VRL}\n%source_type = \"okta_override\"");
    let p = parser("okta_ocsf", "splunk_hec", &["okta"], &explicit_source_type);
    let row = through_parser(&render(&p, true), "okta_ocsf", event, meta);
    assert_eq!(row["source_type"], "okta_override", "{row}");
    assert_eq!(row["event"]["metadata"]["log_source"], "okta_override", "{row}");
}

#[test]
fn stamp_takes_the_routed_value_and_never_writes_unknown() {
    // HTTP lane with system-level routing rules: `source_type_extract` stashed
    // the pre-rule value, the rules then rewrote `.source_type`. The parser was
    // claimed on the rewritten value, so that is the lane.
    let (_, meta) = run(
        OCSF_LANE_STAMP_VRL,
        json!({ "source_type": "apache_access" }),
        json!({ "source_type": "apache_raw" }),
    );
    assert_eq!(meta["source_type"], "apache_access");

    // Case is normalized like the ingress stashes do.
    let (_, meta) = run(OCSF_LANE_STAMP_VRL, json!({ "source_type": "Okta" }), json!({}));
    assert_eq!(meta["source_type"], "okta");

    // No usable lane: an upstream stash is left alone, and nothing is invented.
    for missing in [json!({}), json!({ "source_type": "unknown" }), json!({ "source_type": "" })] {
        let (_, meta) = run(OCSF_LANE_STAMP_VRL, missing.clone(), json!({ "source_type": "kept" }));
        assert_eq!(meta["source_type"], "kept", "{missing}");
        let (_, meta) = run(OCSF_LANE_STAMP_VRL, missing.clone(), json!({}));
        assert!(meta.get("source_type").is_none(), "{missing}: {meta}");
    }
}

/// Every lane's parser reads the stamp, and the stamp reads the lane's input.
#[test]
fn every_lane_renders_the_stamp_between_its_input_and_the_parser() {
    let mut fetch = parser("kafka_app", "kafka", &["kafka_app"], ".class_uid = 0");
    fetch.dispatch_route_name = Some("kafka_feed_route".into());
    let cases = [
        (parser("okta_ocsf", "splunk_hec", &["okta"], ".class_uid = 0"), "okta_ocsf_filter"),
        (parser("acme_vpn", "routed", &["acme_vpn"], ".class_uid = 0"), "source_router.acme_vpn"),
        (parser("fwd_app", "vector", &["fwd_app"], ".class_uid = 0"), "source_router.fwd_app"),
        (parser("syslog_app", "syslog_rfc5424", &["syslog_app"], ".class_uid = 0"), "source_router.syslog_app"),
        (parser("otel_app", "opentelemetry", &["otlp_log"], ".class_uid = 0"), "otel_app_filter"),
        (fetch, "kafka_app_filter"),
    ];
    for (p, upstream) in cases {
        let name = p.name.clone();
        let t = transforms(&render(&p, true));
        let stamp = format!("{name}{OCSF_LANE_STAMP_SUFFIX}");
        assert_eq!(inputs(&t, &stamp), vec![upstream.to_string()], "{name}");
        assert_eq!(t[&stamp]["type"].as_str(), Some("remap"), "{name}");
        assert_eq!(source(&t, &stamp).trim(), OCSF_LANE_STAMP_VRL, "{name}");
        assert_eq!(inputs(&t, &format!("{name}_parse")), vec![stamp.clone()], "{name}");
        // Nothing else reads the lane input directly (no bypass of the stamp).
        let readers: Vec<_> = t
            .iter()
            .filter(|(_, b)| {
                b.get("inputs")
                    .and_then(|i| i.as_array())
                    .is_some_and(|i| i.iter().any(|v| v.as_str() == Some(upstream)))
            })
            .map(|(k, _)| k.clone())
            .collect();
        assert_eq!(readers, vec![stamp], "{name}");
    }
}

#[test]
fn stub_extension_and_native_plans_read_the_stamp() {
    // Stub: no parser VRL, the extension carries the logic and reads the input.
    let mut stub = parser("stub_app", "splunk_hec", &["stub_app"], "");
    stub.extension_vrl = Some(".class_uid = 0".into());
    stub.extension_enabled = true;
    let t = transforms(&render(&stub, true));
    assert!(!t.contains_key("stub_app_parse"));
    assert_eq!(inputs(&t, "stub_app_extension"), vec!["stub_app_source_lane".to_string()]);

    // A plan with native steps: the identity `_parse` the chain reads from
    // reads the stamp; the chain itself is unchanged.
    let step = |id: &str, kind: &str, config: Value| Step {
        id: id.into(),
        name: id.into(),
        kind: kind.into(),
        enabled: true,
        condition: None,
        config: config.as_object().unwrap().clone(),
    };
    let plan = Plan {
        version: 2,
        revision: 1,
        steps: vec![
            step("parse", "parse", json!({"format":"json","field":"message"})),
            step("dedupe", "dedupe", json!({"fields":["message"],"cacheEvents":100})),
        ],
    };
    let p = parser("plan_app", "splunk_hec", &["plan_app"], &plan.stored().unwrap());
    let config = render(&p, true);
    let t = transforms(&config);
    assert_eq!(inputs(&t, "plan_app_parse"), vec!["plan_app_source_lane".to_string()]);
    // The NAN-4919 deploy guard accepts the stamped document.
    crate::parsers::pipe::guard::check_document(
        "plan_app",
        &p.parser_vrl,
        &config,
        &crate::parsers::pipe::native::runtime_transforms(),
    )
    .unwrap_or_else(|e| panic!("guard refused the stamped plan render: {e}\n{config}"));
}

#[test]
fn guard_accepts_the_stamped_vrl_render() {
    let p = parser("okta_ocsf", "splunk_hec", &["okta"], OKTA_LIKE_VRL);
    let config = render(&p, true);
    crate::parsers::pipe::guard::check_document(
        "okta_ocsf",
        &p.parser_vrl,
        &config,
        &crate::parsers::pipe::native::runtime_transforms(),
    )
    .unwrap_or_else(|e| panic!("guard refused the stamped render: {e}\n{config}"));
}

/// UDM keeps the root, so `_output` reads `.source_type` directly: no stamp,
/// and the parser reads its lane input as before (byte-identical topology).
#[test]
fn udm_render_has_no_stamp() {
    let p = parser("okta_ocsf", "splunk_hec", &["okta"], OKTA_LIKE_VRL);
    let config = render(&p, false);
    assert!(!config.contains(OCSF_LANE_STAMP_SUFFIX), "{config}");
    assert!(!config.contains("%source_type"), "{config}");
    let t = transforms(&config);
    assert_eq!(inputs(&t, "okta_ocsf_parse"), vec!["okta_ocsf_filter".to_string()]);
}
