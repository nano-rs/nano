// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5071: a source-bound ingest token decides the source on every push
//! lane, so its events reach that source's parser whatever the transport.
//!
//! A Splunk HEC source's parser used to read only `splunk_hec_route`. The same
//! token presented on HTTP `/ingest` was accepted (200), `source_type_extract`
//! stamped the bound route key, and with no routed parser claiming that key the
//! event fell through `source_router.generic`: stored unparsed, at ingest time,
//! and invisible to parser health. Every enabled HEC parser now also reads a
//! `source_router.<name>-token_bound` route that claims exactly the
//! token-decided events for its keys.
//!
//! The scenario runs the shipped HTTP lane VRL (`00-base.toml`
//! `source_type_extract`), evaluates every rendered `source_router` route on
//! its output, then the HEC parser's filter and parse step.

use chrono::Utc;
use serde_json::{json, Value};
use uuid::Uuid;

use super::VectorConfigManager;
use crate::parsers::types::Parser;

const BASE: &str = include_str!("../../../../config/vector/00-base.toml");

const ASA_TOKEN: &str = "0b9a3c34-4cbb-4c1e-9d0f-6a3bd1f0f7e1";

const ASA_LIKE_VRL: &str = r#"m = parse_regex!(to_string!(.message), r'%ASA-(?P<sev>\d)-(?P<id>\d+): (?P<rest>.*)')
.udm.event_id = m.id
.udm.action = "deny""#;

fn parser(name: &str, source_type: &str, keys: &[&str], enabled: bool) -> Parser {
    Parser {
        id: Uuid::new_v4(),
        name: name.into(),
        description: None,
        source_type: source_type.into(),
        parser_vrl: ASA_LIKE_VRL.into(),
        output_fields: None,
        feed_id: None,
        dispatch_source_config_id: None,
        dispatch_route_name: None,
        namespace: "default".into(),
        enabled,
        validated: true,
        validation_error: None,
        timezone: "UTC".into(),
        match_values: Some(keys.iter().map(|s| s.to_string()).collect()),
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

fn base_source(name: &str) -> String {
    let substituted = regex::Regex::new(r"\$\{[A-Z0-9_]+:-([^}]*)\}")
        .unwrap()
        .replace_all(BASE, "$1");
    let table: toml::Table = substituted.parse().expect("00-base parses");
    table["transforms"][name]["source"].as_str().unwrap().to_string()
}

/// Runs `program`; returns (result, event, metadata). Panics on abort/error.
fn run(program: &str, event: Value, metadata: Value) -> (Value, Value, Value) {
    let compiled = vrl::compiler::compile(program, &vrl::stdlib::all())
        .unwrap_or_else(|d| panic!("VRL compiles: {d:?}\n{program}"))
        .program;
    let mut target = vrl::compiler::TargetValue {
        value: vrl::value::Value::from(event),
        metadata: vrl::value::Value::from(metadata),
        secrets: vrl::value::Secrets::new(),
    };
    let result = vrl::compiler::runtime::Runtime::new(vrl::compiler::state::RuntimeState::default())
        .resolve(&mut target, &compiled, &vrl::compiler::TimeZone::Local)
        .unwrap_or_else(|e| panic!("VRL runtime: {e:?}\n{program}"));
    (
        result.try_into().expect("result json"),
        target.value.try_into().expect("event json"),
        target.metadata.try_into().expect("metadata json"),
    )
}

/// What the HTTP lane hands `source_router` for one `/ingest` record
/// authenticated by `credential_name` (`None` = unstamped static fallback).
fn http_event(credential_name: Option<&str>, declared: &str) -> (Value, Value) {
    let meta = match credential_name {
        Some(name) => json!({ "nano_credential_id": ASA_TOKEN, "nano_credential_name": name }),
        None => json!({}),
    };
    let (_, event, meta) = run(
        &base_source("source_type_extract"),
        json!({
            "message": "%ASA-4-106023: Deny tcp src outside:203.0.113.7/4431 dst inside:10.0.0.5/22",
            "source_type": declared,
            "metadata": { "forwarded_via": "http" }
        }),
        meta,
    );
    (event, meta)
}

struct Deployed {
    _dir: tempfile::TempDir,
    parsers_dir: std::path::PathBuf,
}

async fn deploy(set: &[Parser]) -> Deployed {
    let dir = tempfile::tempdir().unwrap();
    let mgr = VectorConfigManager::new(dir.path());
    mgr.deploy_parsers(set).await.unwrap();
    let parsers_dir = mgr.parsers_dir().to_path_buf();
    Deployed { _dir: dir, parsers_dir }
}

fn load(path: &std::path::Path) -> toml::Table {
    let raw = std::fs::read_to_string(path).unwrap();
    toml::from_str(&crate::vector_env::substitute_like_vector(&raw)).unwrap()
}

/// The `source_router` routes `event` matches, by name.
fn matching_routes(d: &Deployed, event: &Value, meta: &Value) -> Vec<String> {
    let router = load(&d.parsers_dir.join("_router.toml"));
    let routes = router["transforms"]["source_router"]["route"].as_table().unwrap();
    let mut out: Vec<String> = routes
        .iter()
        .filter(|(_, cond)| {
            let (r, _, _) = run(cond.as_str().unwrap(), event.clone(), meta.clone());
            r.as_bool().expect("route condition is boolean")
        })
        .map(|(name, _)| name.clone())
        .collect();
    out.sort();
    out
}

fn transforms(d: &Deployed, file: &str) -> toml::Table {
    load(&d.parsers_dir.join(file))["transforms"].as_table().unwrap().clone()
}

#[tokio::test]
async fn a_hec_source_token_on_http_ingest_reaches_the_hec_parser() {
    let asa = parser("cisco_asa", "splunk_hec", &["cisco_asa"], true);
    let d = deploy(std::slice::from_ref(&asa)).await;

    // The HEC parser's filter reads both lanes.
    let t = transforms(&d, "cisco_asa.toml");
    let inputs: Vec<&str> = t["cisco_asa_filter"]["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(inputs, vec!["splunk_hec_route", "source_router.cisco_asa-token_bound"]);

    // HTTP /ingest with the HEC source's token: the token decided the type.
    let (event, meta) = http_event(Some("cisco_asa"), "unknown");
    assert_eq!(event["source_type"], "cisco_asa");
    assert_eq!(
        matching_routes(&d, &event, &meta),
        vec!["cisco_asa-token_bound"],
        "claimed once, by the bound source's route, never also by `generic`"
    );

    // ... passes the parser's filter and is parsed.
    let filter = t["cisco_asa_filter"]["condition"].as_str().unwrap();
    assert_eq!(run(filter, event.clone(), meta.clone()).0, json!(true));
    let (_, parsed, _) = run(t["cisco_asa_parse"]["source"].as_str().unwrap(), event, meta);
    assert_eq!(parsed["udm"]["event_id"], "106023", "{parsed}");

    // The defect: the pre-fix router had no such route, so only `generic`
    // matched and the record was stored raw.
    let router = std::fs::read_to_string(d.parsers_dir.join("_router.toml")).unwrap();
    assert!(router.contains("cisco_asa-token_bound = "), "{router}");
}

/// Multiplex credentials (platform credential, legacy-multiplex install
/// token: route `*`) and unstamped events keep declared-type routing: a
/// declared HEC-only type still falls to `generic` on HTTP, exactly as before.
#[tokio::test]
async fn multiplex_and_unstamped_events_keep_declared_type_routing() {
    let asa = parser("cisco_asa", "splunk_hec", &["cisco_asa"], true);
    let d = deploy(std::slice::from_ref(&asa)).await;

    for credential in [Some("*"), None] {
        let (event, meta) = http_event(credential, "cisco_asa");
        assert_eq!(event["source_type"], "cisco_asa");
        assert_eq!(matching_routes(&d, &event, &meta), vec!["generic"], "credential={credential:?}");
    }

    // A token bound to some OTHER source cannot reach the HEC parser by
    // declaring its type: the token's key wins and the claim is recorded.
    let (event, meta) = http_event(Some("acme_vpn"), "cisco_asa");
    assert_eq!(event["source_type"], "acme_vpn");
    assert_eq!(event["claimed_source_type"], "cisco_asa");
    assert_eq!(matching_routes(&d, &event, &meta), vec!["generic"]);
}

/// A routed parser that claims the same key already receives the HTTP event;
/// the HEC parser's token-bound route must not claim it too (double write).
#[tokio::test]
async fn a_key_a_routed_parser_claims_is_not_claimed_twice() {
    let hec = parser("asa_hec", "splunk_hec", &["cisco_asa"], true);
    let routed = parser("asa_routed", "routed", &["cisco_asa"], true);
    let d = deploy(&[hec, routed]).await;

    let (event, meta) = http_event(Some("cisco_asa"), "unknown");
    assert_eq!(matching_routes(&d, &event, &meta), vec!["asa_routed"]);
    let router = load(&d.parsers_dir.join("_router.toml"));
    assert_eq!(router["transforms"]["source_router"]["route"]["asa_hec-token_bound"].as_str(), Some("false"));
}

/// Router and parser files stay in lockstep (NAN-4952 contract): a disabled
/// HEC parser has neither a file nor a route; enabling it adds both. Active
/// and staged writers alike.
#[tokio::test]
async fn token_bound_routes_track_enabled_hec_parsers_in_both_writers() {
    let dir = tempfile::tempdir().unwrap();
    let mgr = VectorConfigManager::new(dir.path());
    for enabled in [false, true, false] {
        let set = vec![
            parser("cisco_asa", "splunk_hec", &["cisco_asa"], enabled),
            parser("sysmon", "hec", &["windows_sysmon"], true),
        ];
        mgr.deploy_parsers(&set).await.unwrap();
        let routes = route_names(&mgr.parsers_dir().join("_router.toml"));
        let mut want = vec!["sysmon-token_bound".to_string()];
        if enabled {
            want.insert(0, "cisco_asa-token_bound".to_string());
        }
        assert_eq!(routes, want, "enabled={enabled}");
        assert_eq!(mgr.parsers_dir().join("cisco_asa.toml").exists(), enabled);

        mgr.stage_parsers(&set).await.unwrap();
        let staged = mgr.staging_dir().join("sources").join("parsers").join("_router.toml");
        assert_eq!(route_names(&staged), want, "staged, enabled={enabled}");
        mgr.cleanup_staging().await.unwrap();
    }
}

fn route_names(router: &std::path::Path) -> Vec<String> {
    let doc = load(router);
    let mut names: Vec<String> = doc["transforms"]["source_router"]["route"]
        .as_table()
        .unwrap()
        .keys()
        .filter(|k| k.as_str() != "generic")
        .cloned()
        .collect();
    names.sort();
    names
}

const HEC: &str = include_str!("../../../../config/vector/02-hec-source.toml");

fn hec_normalize(event: Value, meta: Value) -> (Value, Value) {
    let substituted = regex::Regex::new(r"\$\{[A-Z0-9_]+:-([^}]*)\}")
        .unwrap()
        .replace_all(HEC, "$1");
    let table: toml::Table = substituted.parse().expect("02-hec-source parses");
    let (_, event, meta) = run(table["transforms"]["hec_normalize"]["source"].as_str().unwrap(), event, meta);
    (event, meta)
}

/// Review finding 1: a HEC source with NO `match_values` whose name changes
/// under `safe_name`. Its token stamps `route_key` = `palo_alto_fw`; every
/// claim (router route, HEC filter, `_unclaimed` filter) must use that same
/// key, or the event is claimed by one and dropped by the next.
#[tokio::test]
async fn a_hec_source_without_match_values_is_parsed_on_both_lanes() {
    let mut fw = parser("Palo Alto FW", "splunk_hec", &[], true);
    fw.match_values = None;
    let key = crate::ingest_tokens::route_key(None, &fw.name);
    assert_eq!(key, "palo_alto_fw");
    let d = deploy(std::slice::from_ref(&fw)).await;
    let t = transforms(&d, "palo_alto_fw.toml");
    let filter = t["palo_alto_fw_filter"]["condition"].as_str().unwrap().to_string();
    let parse = t["palo_alto_fw_parse"]["source"].as_str().unwrap().to_string();
    let stamp = || json!({ "nano_credential_id": ASA_TOKEN, "nano_credential_name": key });

    // HTTP /ingest: the token-bound route claims it, generic does not, and
    // the parser's own filter keeps it.
    let (event, meta) = http_event(Some(&key), "unknown");
    assert_eq!(matching_routes(&d, &event, &meta), vec!["palo_alto_fw-token_bound"]);
    assert_eq!(run(&filter, event.clone(), meta.clone()).0, json!(true), "{filter}");
    let (_, parsed, _) = run(&parse, event, meta);
    assert_eq!(parsed["udm"]["event_id"], "106023");

    // HEC :8088: the filter keeps it, and the router's `_unclaimed` filter
    // (what reaches `source_router` from the HEC lane) excludes it, so it is
    // neither dropped nor double-written raw.
    let (event, meta) = hec_normalize(
        json!({ "event": "%ASA-4-106023: Deny tcp src outside:203.0.113.7/4431 dst inside:10.0.0.5/22" }),
        stamp(),
    );
    assert_eq!(event["source_type"], "palo_alto_fw");
    assert_eq!(run(&filter, event.clone(), meta.clone()).0, json!(true), "{filter}");
    let (_, parsed, _) = run(&parse, event.clone(), meta.clone());
    assert_eq!(parsed["udm"]["event_id"], "106023");
    let unclaimed = crate::parsers::vector_config::router::build_unclaimed_filter_condition_for_tests(&[&fw]);
    assert_eq!(run(&unclaimed, event, meta).0, json!(false), "{unclaimed}");
}

/// Review finding 2: a routed source whose safe name looks like a derived
/// token-bound route (`foo__token_bound`, `Foo  Token Bound`) must not
/// duplicate a key in `[transforms.source_router.route]` (Vector would refuse
/// the whole router). The derived name uses `-`, which no safe name contains.
#[tokio::test]
async fn a_routed_name_cannot_collide_with_a_token_bound_route() {
    for routed_name in ["foo__token_bound", "Foo  Token Bound", "foo-token_bound"] {
        let set = vec![
            parser("foo", "splunk_hec", &["foo"], true),
            parser(routed_name, "routed", &["other"], true),
        ];
        let d = deploy(&set).await;
        // `load` panics on a duplicate key; both routes are present.
        let routes = route_names(&d.parsers_dir.join("_router.toml"));
        let routed_route = VectorConfigManager::safe_name(routed_name);
        assert_ne!(routed_route, "foo-token_bound");
        let mut want = vec!["foo-token_bound".to_string(), routed_route];
        want.sort();
        assert_eq!(routes, want, "routed={routed_name}");
    }
}
