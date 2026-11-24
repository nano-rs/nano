// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5846: a vendor field that spills to `unmapped.client_ip` is stored
//! unchanged, and nano's ingest provenance lives under its own namespace.
//!
//! Before this fix the OCSF storage boundary deleted `unmapped.client_ip` and
//! wrote the ingest client IP there. A Microsoft 365 `ClientIP` (the user's
//! sign-in address) was replaced by the forwarder's address on HTTP sources,
//! and deleted outright where there was no ingest address (direct HEC). The
//! same address was also stamped three times (`client_ip`,
//! `ingest_client_ip`, `ingest_peer`).
//!
//! Now nano writes `unmapped.nano.ingest.client_ip`, plus
//! `unmapped.nano.ingest.peer` only when it differs, and first removes every
//! `unmapped` key in the `nano` namespace in ANY spelling: ClickHouse's `JSON`
//! column reads `.` in a key as a path separator, so a flat
//! `"nano.ingest.client_ip"` (what every shipped parser's residual spill
//! emits for a nested source key) is the same stored path as nano's nested
//! write. Left in place it either forges provenance or collides with the
//! nested write (ClickHouse Code 117, which drops the whole sink batch).
//!
//! Executes the real 00-base.toml / 02-hec-source.toml VRL and the generated
//! per-parser OCSF chain on the VRL runtime. [`stored_paths`] models how
//! ClickHouse resolves the keys; `scripts/tests/ingest-provenance-ch.live.sh`
//! inserts the same rows (written by [`dump_rows_for_clickhouse`]) into a real
//! ClickHouse `JSON` column.

use std::collections::BTreeMap;

use chrono::Utc;
use uuid::Uuid;
use vrl::value::Value;

use super::credential_header_tests::{json, run_chain, transform_in, transform_source};
use super::transport_header_tests::{http_request, store_generic};
use super::VectorConfigManager;
use crate::parsers::types::Parser;

const HEC: &str = include_str!("../../../../../config/vector/02-hec-source.toml");
const EDGE_PEER: &str = "172.18.0.5";
const SENDER: &str = "203.0.113.9";
/// The user's sign-in address, as Microsoft 365 sends it (`[v6]:port`).
const VENDOR_CLIENT_IP: &str = "[2001:db8::1]:52344";
const FORGED: &str = "6.6.6.6";

/// The shape of the shipped microsoft_365 OCSF parser: it maps the bare
/// address to `src_endpoint.ip`, and its residual spill (parsers
/// `scripts/residual/spill.vrl`) writes every source leaf to `unmapped` as a
/// FLAT dotted, snake_cased key, so `ClientIP` spills as `client_ip` and a
/// nested `{"nano": {"ingest": {...}}}` as `"nano.ingest.client_ip"`.
const M365_OCSF: &str = r#"p = object!(parse_json!(string!(.message)))
raw_ip = string(p.ClientIP) ?? ""
ip = replace(replace(raw_ip, r'^\[', ""), r'\]:\d+$', "")
residual = map_keys(flatten(p)) -> |key| {
    join!(map_values(split(key, ".")) -> |part| { snakecase(string!(part)) }, ".")
}
. = {
    "class_uid": 3002,
    "category_uid": 3,
    "activity_id": 1,
    "time": 1755525831000,
    "user": { "name": string(p.UserId) ?? "" },
    "src_endpoint": { "ip": ip },
    "metadata": { "version": "1.9.0", "product": { "name": "Microsoft 365" } },
    "unmapped": residual
}"#;

/// A custom OCSF parser that keeps the event root (the decoded record plus
/// the class): every sender key stays at the event root, so a dotted root
/// key `"unmapped.nano.ingest.client_ip"` is the stored path
/// `unmapped.nano.ingest.client_ip`.
const ROOT_KEEPING_OCSF: &str = r#". = object!(parse_json!(string!(.message)))
.class_uid = 0
.category_uid = 0
.time = 1755525831000"#;

fn m365_record(extra: &serde_json::Value) -> String {
    let mut record = serde_json::json!({
        "CreationTime": "2026-08-18T14:07:52",
        "Operation": "UserLoginFailed",
        "Workload": "AzureActiveDirectory",
        "UserId": "jane.doe@example.com",
        "ClientIP": VENDOR_CLIENT_IP,
    });
    for (k, v) in extra.as_object().unwrap() {
        record[k] = v.clone();
    }
    record.to_string()
}

/// Every spelling a sender can use for `nano.ingest.*`: nested, flat dotted,
/// and mixed. Each must neither forge provenance nor collide with nano's write.
fn hostile_payloads() -> Vec<(&'static str, serde_json::Value)> {
    vec![
        ("nested", serde_json::json!({ "nano": { "ingest": { "client_ip": FORGED, "peer": FORGED, "extra": FORGED } } })),
        ("flat", serde_json::json!({ "nano.ingest.client_ip": FORGED, "nano.ingest.peer": FORGED })),
        ("flat peer only", serde_json::json!({ "nano.ingest.peer": FORGED })),
        ("mixed object", serde_json::json!({ "nano.ingest": { "client_ip": FORGED } })),
        ("mixed scalar", serde_json::json!({ "nano.ingest": FORGED })),
        ("mixed inner", serde_json::json!({ "nano": { "ingest.client_ip": FORGED, "ingest.peer": FORGED } })),
        ("case varied", serde_json::json!({ "Nano": { "Ingest": { "ClientIP": FORGED } } })),
        ("scalar nano", serde_json::json!({ "nano": FORGED })),
        ("all at once", serde_json::json!({
            "nano": { "ingest": { "client_ip": FORGED }, "ingest.peer": FORGED },
            "nano.ingest": { "peer": FORGED },
            "nano.ingest.client_ip": FORGED,
        })),
        // A dotted key at the EVENT ROOT that ClickHouse resolves under
        // `unmapped` (a root-keeping parser stores it as sent).
        ("root dotted", serde_json::json!({
            "unmapped.nano.ingest.client_ip": FORGED,
            "unmapped.nano": { "ingest": { "peer": FORGED } },
            "unmapped.source_nano.keep": FORGED,
        })),
    ]
}

/// Lanes whose parser keeps one value per distinct source path (the shipped
/// spill suffixes a second spelling; the mock keeps one, which is enough to
/// prove nano itself never drops one).
fn spill_lane(lane: &str) -> bool {
    lane.starts_with("http") || lane.starts_with("hec")
}

/// Whether to run `shape` on `lane`. A root-keeping parser stores the
/// sender's own root keys as sent, so a payload that spells ONE root path two
/// ways ("all at once") is the sender's own duplicate, the general case
/// tracked in NAN-5849, not a collision with anything nano writes.
fn applies(lane: &str, shape: &str) -> bool {
    !(lane == "root-keeping parser" && shape == "all at once")
}

fn is_under(path: &str, prefix: &str) -> bool {
    path == prefix || path.starts_with(&format!("{prefix}."))
}

/// How many `FORGED` values the stored event must still hold (nano drops none).
fn expected_total(lane: &str, payload: &serde_json::Value) -> usize {
    if spill_lane(lane) {
        stored_paths(payload).values().filter(|v| v.contains(&serde_json::json!(FORGED))).count()
    } else {
        forged_count(payload, |_| true)
    }
}

/// How many of them nano moves into `unmapped.source_nano_json`: the values
/// that would otherwise land in its namespace. The spill snake_cases keys
/// (`Nano` becomes `nano`); the generic lane keeps the sender's case (`Nano`
/// is a different, unreserved ClickHouse path); a root-keeping parser leaves
/// everything at the event root, where only `unmapped.nano*` keys resolve
/// into `unmapped`.
fn expected_moved(lane: &str, payload: &serde_json::Value) -> usize {
    let paths = stored_paths(payload);
    let forged = |v: &Vec<serde_json::Value>| v.iter().filter(|x| **x == serde_json::json!(FORGED)).count();
    match lane {
        "generic lane" => paths.iter().filter(|(p, _)| is_under(p, "nano")).map(|(_, v)| forged(v)).sum(),
        "root-keeping parser" => paths.iter().filter(|(p, _)| is_under(p, "unmapped.nano")).map(|(_, v)| forged(v)).sum(),
        _ => paths
            .iter()
            .filter(|(p, v)| is_under(&p.to_lowercase(), "nano") && v.contains(&serde_json::json!(FORGED)))
            .count(),
    }
}

fn parser(name: &str, vrl: &str) -> Parser {
    Parser {
        activation_parked: false,
        id: Uuid::new_v4(),
        name: name.into(),
        description: None,
        source_type: name.into(),
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
        match_values: Some(vec![name.into()]),
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

/// The generated per-parser OCSF stages, in order, up to `_ocsf_prepare`.
fn parser_stages(p: &Parser, hec: bool) -> Vec<(String, String)> {
    let config = VectorConfigManager::new("/tmp/nanosiem-test").generate_parser_config_for(p, true);
    let config = regex::Regex::new(r"\$\{[A-Z0-9_]+:-([^}]*)\}")
        .unwrap()
        .replace_all(&config, "$1")
        .into_owned();
    let mut names = vec!["source_lane"];
    if hec {
        assert!(
            config.contains(&format!("[transforms.{}_hec_payload]", p.name)),
            "a JSON-input parser gets the HEC payload step"
        );
        names.push("hec_payload");
    }
    names.extend(["source_tz", "parse", "ocsf_prepare"]);
    names
        .into_iter()
        .map(|n| {
            let name = format!("{}_{n}", p.name);
            let vrl = transform_in(&config, &name);
            (name, vrl)
        })
        .collect()
}

fn chain_refs(chain: &[(String, String)]) -> Vec<(&str, String)> {
    chain.iter().map(|(n, v)| (n.as_str(), v.clone())).collect()
}

/// HTTP `/ingest` through a trusted proxy (`X-Real-IP` believed) or direct.
fn store_http(body: &str, via_proxy: bool) -> Value {
    store_http_with(&parser("microsoft_365", M365_OCSF), body, via_proxy)
}

fn store_http_with(p: &Parser, body: &str, via_proxy: bool) -> Value {
    let mut event = serde_json::json!({
        "message": body,
        "path": "/ingest",
        "Content-Type": "application/json",
        "X-Source-Type": p.name.clone(),
        "nano_ingest_peer": EDGE_PEER,
    });
    if via_proxy {
        event["X-Real-IP"] = SENDER.into();
    }
    let rate_limit_prep = transform_source("rate_limit_prep").replace(
        r#"get_env_var("NANO_INGEST_TRUSTED_PROXIES") ?? """#,
        r#""172.18.0.5/32""#,
    );
    let stages = parser_stages(p, false);
    let mut chain = vec![
        ("auth_check", transform_source("auth_check")),
        ("rate_limit_prep", rate_limit_prep),
        ("parse_content", transform_source("parse_content")),
        ("source_type_extract", transform_source("source_type_extract")),
    ];
    chain.extend(chain_refs(&stages));
    run_chain(json(event), &chain)
}

/// Splunk HEC `{"event": {...}}`, spread over the root as the source emits
/// it. `edge` = the role-split edge asserted the client in the channel; a
/// direct HEC sender has no ingest address at all.
fn store_hec(record: &str, edge: bool) -> Value {
    let mut event = serde_json::json!({
        "splunk_sourcetype": "microsoft_365",
        "splunk_channel": if edge { format!("c-1;nano-client={SENDER}") } else { "c-1".to_string() },
        "host": "fwd-01",
    });
    for (k, v) in serde_json::from_str::<serde_json::Value>(record).unwrap().as_object().unwrap() {
        event[k] = v.clone();
    }
    // No `message`: hec_normalize rebuilds the record from the root, and the
    // JSON-input parser receives it whole.
    let mut hec_normalize = transform_in(HEC, "hec_normalize");
    if edge {
        hec_normalize = hec_normalize
            .replace(r#"get_env_var("NANO_HEC_TRUST_EDGE_IDENTITY") ?? """#, r#""true""#);
    }
    let stages = parser_stages(&parser("microsoft_365", M365_OCSF), true);
    let mut chain = vec![("hec_normalize", hec_normalize)];
    chain.extend(chain_refs(&stages));
    run_chain(json(event), &chain)
}

/// The generic Base Event lane (no parser): the body lands under `unmapped`
/// as sent, NOT flattened, so every nested and mixed spelling reaches it.
fn store_generic_lane(record: &str) -> Value {
    store_generic(http_request(record, Some("application/json"), EDGE_PEER, Some(SENDER)))
}

/// Every lane, its stored row and the provenance nano must have written.
fn lanes(extra: &serde_json::Value) -> Vec<(&'static str, Value, serde_json::Value)> {
    let record = m365_record(extra);
    vec![
        ("http proxy", store_http(&record, true), serde_json::json!({ "client_ip": SENDER, "peer": EDGE_PEER })),
        ("http direct", store_http(&record, false), serde_json::json!({ "client_ip": EDGE_PEER })),
        ("hec edge", store_hec(&record, true), serde_json::json!({ "client_ip": SENDER })),
        ("hec direct", store_hec(&record, false), serde_json::Value::Null),
        ("generic lane", store_generic_lane(&record), serde_json::json!({ "client_ip": SENDER, "peer": EDGE_PEER })),
        (
            "root-keeping parser",
            store_http_with(&parser("keep_root", ROOT_KEEPING_OCSF), &record, true),
            serde_json::json!({ "client_ip": SENDER, "peer": EDGE_PEER }),
        ),
    ]
}

fn at(stored: &Value, path: &[&str]) -> serde_json::Value {
    let mut v = serde_json::to_value(stored).expect("event serializes");
    for seg in path {
        v = v.get(*seg).cloned().unwrap_or(serde_json::Value::Null);
    }
    v
}

fn unmapped(stored: &Value) -> serde_json::Value {
    at(stored, &["event", "unmapped"])
}

/// The leaf paths ClickHouse's `JSON` type stores for `value`: every key is
/// split on `.` (`"a.b": 1` and `{"a": {"b": 1}}` are the same path `a.b`).
/// Returns each path with every value it was given, so a path with two
/// values is a ClickHouse Code 117 (duplicate path) insert failure.
pub(super) fn stored_paths(value: &serde_json::Value) -> BTreeMap<String, Vec<serde_json::Value>> {
    fn walk(value: &serde_json::Value, prefix: &str, out: &mut BTreeMap<String, Vec<serde_json::Value>>) {
        match value.as_object() {
            Some(map) if !map.is_empty() => {
                for (key, child) in map {
                    let path = if prefix.is_empty() { key.clone() } else { format!("{prefix}.{key}") };
                    walk(child, &path, out);
                }
            }
            _ => out.entry(prefix.to_string()).or_default().push(value.clone()),
        }
    }
    let mut out = BTreeMap::new();
    walk(value, "", &mut out);
    out
}

/// No stored path is spelled twice anywhere in the event (no Code 117), and
/// the `nano` namespace holds exactly nano's provenance.
pub(super) fn assert_clickhouse_safe_provenance(stored: &Value, expected: &serde_json::Value, lane: &str) {
    let paths = stored_paths(&at(stored, &["event"]));
    for (path, values) in &paths {
        assert_eq!(values.len(), 1, "{lane}: `{path}` stored twice (ClickHouse Code 117): {stored}");
    }
    let nano: BTreeMap<_, _> = paths
        .iter()
        .filter(|(path, _)| *path == "unmapped.nano" || path.starts_with("unmapped.nano."))
        .map(|(path, values)| (path.trim_start_matches("unmapped.nano.ingest.").to_string(), values[0].clone()))
        .collect();
    let want: BTreeMap<_, _> = expected
        .as_object()
        .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default();
    assert_eq!(nano, want, "{lane}: unmapped.nano must hold only nano's provenance: {stored}");
}

fn assert_vendor_kept(stored: &Value, lane: &str) {
    let u = unmapped(stored);
    // The generic lane keeps the record under its own key names (`ClientIP`);
    // a root-keeping parser keeps it at the event root.
    let root = at(stored, &["event", "ClientIP"]);
    let vendor = u.get("client_ip").or_else(|| u.get("ClientIP")).or(if root.is_null() { None } else { Some(&root) });
    assert_eq!(vendor, Some(&serde_json::json!(VENDOR_CLIENT_IP)), "{lane}: vendor ClientIP must survive: {stored}");
    assert!(u.get("ingest_client_ip").is_none(), "{lane}: legacy key written: {stored}");
    assert!(u.get("ingest_peer").is_none(), "{lane}: legacy key written: {stored}");
}

#[test]
fn m365_client_ip_survives_every_lane_with_provenance_under_the_namespace() {
    for (lane, stored, expected) in lanes(&serde_json::json!({})) {
        assert_vendor_kept(&stored, lane);
        assert_clickhouse_safe_provenance(&stored, &expected, lane);
    }
    let stored = store_http(&m365_record(&serde_json::json!({})), true);
    assert_eq!(at(&stored, &["event", "src_endpoint", "ip"]), "2001:db8::1", "{stored}");
}

/// Direct HEC carries no ingest address: the vendor field used to be deleted.
#[test]
fn a_source_with_no_ingest_ip_keeps_the_vendor_field() {
    let stored = store_hec(&m365_record(&serde_json::json!({})), false);
    assert_vendor_kept(&stored, "hec direct");
    assert!(unmapped(&stored).get("nano").is_none(), "no ingest address, no provenance: {stored}");
}

/// `FORGED` values per stored path of `value` whose path passes `keep`.
fn forged_count(value: &serde_json::Value, keep: impl Fn(&str) -> bool) -> usize {
    stored_paths(value)
        .iter()
        .filter(|(path, _)| keep(path))
        .map(|(_, values)| values.iter().filter(|v| **v == serde_json::json!(FORGED)).count())
        .sum()
}

/// The stored event with every `unmapped.source_nano_json*` string decoded
/// in place, so the moved values can be counted like any other path.
fn decoded_event(stored: &Value) -> serde_json::Value {
    let mut event = at(stored, &["event"]);
    if let Some(u) = event.get_mut("unmapped").and_then(|u| u.as_object_mut()) {
        for (key, value) in u.iter_mut() {
            if key.starts_with("source_nano_json") {
                let text = value.as_str().unwrap_or_else(|| panic!("`{key}` must be ONE string leaf"));
                *value = serde_json::from_str(text).expect("source_nano_json is JSON");
            }
        }
    }
    event
}

/// A sender cannot forge or add to ingest provenance in any spelling, on any
/// lane, no spelling makes nano's write collide with it, and every sender
/// value is KEPT (moved into `unmapped.source_nano_json`), never dropped.
#[test]
fn hostile_nano_payloads_never_spoof_collide_or_get_dropped() {
    for (shape, payload) in hostile_payloads() {
        for (lane_name, stored, expected) in lanes(&payload) {
            if !applies(lane_name, shape) {
                continue;
            }
            let lane = format!("{lane_name} / {shape}");
            assert_clickhouse_safe_provenance(&stored, &expected, &lane);
            let event = decoded_event(&stored);
            assert_eq!(forged_count(&event, |p| is_under(p, "unmapped.nano")), 0, "{lane}: forged provenance stored: {stored}");
            assert_eq!(forged_count(&event, |_| true), expected_total(lane_name, &payload), "{lane}: a sender value was dropped: {stored}");
            assert_eq!(
                forged_count(&event, |p| is_under(p, "unmapped.source_nano_json")),
                expected_moved(lane_name, &payload),
                "{lane}: sender values must be kept in unmapped.source_nano_json: {stored}"
            );
            assert_vendor_kept(&stored, &lane);
        }
    }
}

/// Every lane moves something for at least one shape (the counts above are
/// not vacuously zero).
#[test]
fn every_lane_exercises_the_rename() {
    for (lane, _, _) in lanes(&serde_json::json!({})) {
        let moved: usize = hostile_payloads().iter().filter(|(s, _)| applies(lane, s)).map(|(_, p)| expected_moved(lane, p)).sum();
        assert!(moved > 0, "{lane}");
    }
}

/// The moved keys are kept whole and unmodified in one JSON string, under
/// their original names: within-object duplicates and empty objects survive,
/// and it is one string leaf, so it can never collide with a path.
#[test]
fn moved_keys_are_kept_whole_in_one_json_string() {
    let body = serde_json::json!({
        "nano": { "a": { "b": "v1" }, "a.b": "v2", "empty": {} },
        "nano.keep": 3,
        "source_nano": { "own": 5 },
    });
    let stored = store_generic_lane(&m365_record(&body));
    let u = unmapped(&stored);
    let text = u["source_nano_json"].as_str().expect("one string leaf");
    let moved: serde_json::Value = serde_json::from_str(text).unwrap();
    assert_eq!(moved, serde_json::json!({ "nano": body["nano"], "nano.keep": 3 }), "{stored}");
    assert_eq!(u["source_nano"], serde_json::json!({ "own": 5 }), "source_nano is vendor data, untouched: {stored}");
    assert_clickhouse_safe_provenance(&stored, &serde_json::json!({ "client_ip": SENDER, "peer": EDGE_PEER }), "whole");
}

/// A taken target name (in `unmapped`, or as a root-keeping parser's root
/// key) is never overwritten: the next free `_2` ... `_10` is used.
#[test]
fn a_taken_target_name_gets_the_next_suffix() {
    let body = serde_json::json!({ "nano": { "x": 1 }, "source_nano_json": "vendor", "source_nano_json_2": "vendor 2" });
    let u = unmapped(&store_generic_lane(&m365_record(&body)));
    assert_eq!(u["source_nano_json"], "vendor");
    assert_eq!(u["source_nano_json_2"], "vendor 2");
    assert_eq!(u["source_nano_json_3"], r#"{"nano":{"x":1}}"#);

    let p = parser("keep_root", ROOT_KEEPING_OCSF);
    let body = serde_json::json!({ "unmapped.nano.x": 1, "unmapped.source_nano_json": "vendor" });
    let stored = store_http_with(&p, &m365_record(&body), true);
    assert_eq!(at(&stored, &["event", "unmapped.source_nano_json"]), "vendor", "{stored}");
    assert_eq!(unmapped(&stored)["source_nano_json_2"], r#"{"unmapped.nano.x":1}"#, "{stored}");
    assert_clickhouse_safe_provenance(&stored, &serde_json::json!({ "client_ip": SENDER, "peer": EDGE_PEER }), "suffix");
}

/// An event without a reserved key is not touched: a VALUE "nano" (every
/// json_generic event's `vendor_name`), `source_nano*` keys and `nano_*`
/// markers stay exactly as sent.
#[test]
fn events_without_a_reserved_key_are_not_touched() {
    let body = serde_json::json!({
        "vendor_name": "nano",
        "tag": "nano.x",
        "source_nano": { "a": { "b": 1 } },
        "source_nano.c": 2,
        "nano_build": "7",
    });
    let stored = store_generic_lane(&m365_record(&body));
    let u = unmapped(&stored);
    for (k, v) in body.as_object().unwrap() {
        assert_eq!(&u[k], v, "{k}: {stored}");
    }
    assert!(u.as_object().unwrap().keys().all(|k| !k.starts_with("source_nano_json")), "{stored}");
}

/// The provenance step's own time on `event` (the same program with and
/// without it, best of 3), and the event it produced.
fn time_step(event: &serde_json::Value) -> (std::time::Duration, serde_json::Value) {
    let base = "nano_cred_text = encode_json(.)\nocsf_event = .\n";
    let with = format!("{base}{}. = ocsf_event", super::super::INGEST_PROVENANCE_VRL);
    let without = format!("{base}. = ocsf_event");
    let meta = serde_json::json!({ "nano_ingest_client_ip": SENDER });
    let time = |program: &str| {
        let compiled = vrl::compiler::compile(program, &vrl::stdlib::all()).expect("compiles").program;
        let mut best = std::time::Duration::MAX;
        let mut out = None;
        for _ in 0..3 {
            let mut target = vrl::compiler::TargetValue {
                value: json(event.clone()),
                metadata: json(meta.clone()),
                secrets: vrl::value::Secrets::new(),
            };
            let start = std::time::Instant::now();
            vrl::compiler::runtime::Runtime::new(vrl::compiler::state::RuntimeState::default())
                .resolve(&mut target, &compiled, &vrl::compiler::TimeZone::Local)
                .expect("runs");
            best = best.min(start.elapsed());
            out = Some(target.value);
        }
        (best, out.unwrap())
    };
    let (with_time, stored) = time(&with);
    let (without_time, _) = time(&without);
    (with_time.saturating_sub(without_time), serde_json::to_value(&stored).unwrap())
}

/// Release Vector is far faster than a debug-build test; the debug budget
/// still catches a super-linear regression (the round-3 rename took seconds
/// at a few KB, the round-4 root scan over a second at 300 KB).
fn budget_ms() -> u128 {
    if cfg!(debug_assertions) { 500 } else { 50 }
}

/// Wall-clock assertions are opt-in: they are too load-sensitive to gate the
/// default `cargo test` (the functional checks in the same tests always run).
/// Run them with:
///
/// ```text
/// NANO_PERF_TESTS=1 cargo test --release -p nanosiem-core --lib ingest_provenance_tests -- --nocapture
/// ```
fn perf_assertions_enabled() -> bool {
    std::env::var("NANO_PERF_TESTS").is_ok_and(|v| v == "1")
}

/// A 1 MB hostile `nano` object (many keys, colliding spellings) is moved
/// losslessly; with `NANO_PERF_TESTS=1`, also within the time budget.
#[test]
fn a_one_megabyte_hostile_nano_object_is_bounded() {
    let mut inner = serde_json::Map::new();
    for i in 0..40_000 {
        inner.insert(format!("k{i}"), format!("{FORGED}-{i:08}-pad").into());
    }
    let mut unmapped = serde_json::Map::new();
    unmapped.insert("nano".into(), serde_json::Value::Object(inner.clone()));
    for i in 0..2_000 {
        unmapped.insert(format!("nano.k{i}"), format!("{FORGED}-{i}").into());
    }
    let event = serde_json::json!({ "class_uid": 0, "unmapped": unmapped });
    assert!(event.to_string().len() > 1_000_000, "the payload is at least 1 MB");
    let (step, stored) = time_step(&event);
    eprintln!("1 MB hostile nano object: provenance step {step:?}");
    if perf_assertions_enabled() {
        assert!(step.as_millis() < budget_ms(), "provenance step took {step:?} (budget {} ms)", budget_ms());
    }
    let text = stored["unmapped"]["source_nano_json"].as_str().expect("moved");
    let moved: serde_json::Value = serde_json::from_str(text).unwrap();
    assert_eq!(moved["nano"], serde_json::Value::Object(inner), "lossless");
    assert_eq!(stored["unmapped"]["nano"], serde_json::json!({ "ingest": { "client_ip": SENDER } }));
}

/// A root-keeping parser's event: `n` root keys that look like taken target
/// names (`unmapped.source_nano_json_k<i>`), `n` reserved root keys and `n`
/// reserved `unmapped` keys.
fn root_heavy_event(n: usize) -> serde_json::Value {
    let mut root = serde_json::Map::new();
    let mut unmapped = serde_json::Map::new();
    for i in 0..n {
        root.insert(format!("unmapped.source_nano_json_k{i}"), i.into());
        root.insert(format!("unmapped.nano.k{i}"), format!("{FORGED}-{i}").into());
        unmapped.insert(format!("nano.k{i}"), format!("{FORGED}-{i}").into());
    }
    root.insert("unmapped.source_nano_json".into(), "vendor".into());
    root.insert("class_uid".into(), 0.into());
    root.insert("unmapped".into(), serde_json::Value::Object(unmapped));
    serde_json::Value::Object(root)
}

/// Review r4: the root path is strictly linear. Always: nothing is lost and
/// the taken name is respected. With `NANO_PERF_TESTS=1`: 10k root keys and
/// 10k reserved keys stay in budget, and doubling the input roughly doubles
/// the time (a quadratic loop would quadruple it).
#[test]
fn ten_thousand_root_and_reserved_keys_are_linear() {
    let (step, stored) = time_step(&root_heavy_event(10_000));
    eprintln!("10k root + 10k reserved keys: provenance step {step:?}");
    if perf_assertions_enabled() {
        let (small, _) = time_step(&root_heavy_event(5_000));
        eprintln!("5k root + 5k reserved keys: provenance step {small:?}");
        assert!(step.as_millis() < budget_ms(), "provenance step took {step:?} (budget {} ms)", budget_ms());
        assert!(
            step.as_secs_f64() < small.as_secs_f64() * 3.0 + 0.005,
            "not linear: 5k took {small:?}, 10k took {step:?}"
        );
    }
    // The taken root name is respected; every reserved value is in the string.
    assert_eq!(stored["unmapped.source_nano_json"], "vendor");
    let moved: serde_json::Value = serde_json::from_str(stored["unmapped"]["source_nano_json_2"].as_str().expect("next free name")).unwrap();
    assert_eq!(moved.as_object().unwrap().len(), 20_000, "every reserved key kept");
    assert!(stored.as_object().unwrap().keys().all(|k| !k.starts_with("unmapped.nano")), "root reserved keys moved");
    assert_eq!(stored["unmapped.source_nano_json_k9999"], 9999, "look-alike root keys untouched");
}

/// Other `nano`-prefixed names are not the namespace: the NAN-5839 parser
/// markers (`nano_*`) and look-alikes such as `nanoid` stay where they are.
#[test]
fn only_the_nano_namespace_is_reserved() {
    let stored = store_generic_lane(&m365_record(&serde_json::json!({ "nanoid": "n-1", "nano_build": "7" })));
    let u = unmapped(&stored);
    assert_eq!(u["nanoid"], "n-1", "{stored}");
    assert_eq!(u["nano_build"], "7", "{stored}");
}

/// For `scripts/tests/ingest-provenance-ch.live.sh`: with
/// `NANO_PROVENANCE_ROWS_OUT=<file>`, writes every lane x payload row (the
/// exact `ocsf_logs_raw` insert shape) as JSONEachRow. A no-op otherwise.
#[test]
fn dump_rows_for_clickhouse() {
    let Ok(out) = std::env::var("NANO_PROVENANCE_ROWS_OUT") else { return };
    let mut payloads = vec![("benign", serde_json::json!({}))];
    payloads.extend(hostile_payloads());
    let mut text = String::new();
    for (shape, payload) in payloads {
        for (lane, stored, expected) in lanes(&payload) {
            if !applies(lane, shape) {
                continue;
            }
            let mut row = serde_json::to_value(&stored).expect("row serializes");
            // Shape a ClickHouse JSON column accepts, with the case label.
            row["timestamp"] = "2026-11-22 12:00:00.000".into();
            let line = serde_json::json!({
                "label": format!("{lane} / {shape}"),
                "expected_client_ip": expected.get("client_ip").cloned().unwrap_or_default(),
                "expected_peer": expected.get("peer").cloned().unwrap_or_default(),
                "expected_kept": if shape == "benign" { 0 } else { expected_moved(lane, &payload) },
                "event": row["event"],
            });
            text.push_str(&line.to_string());
            text.push('\n');
        }
    }
    std::fs::write(&out, text).expect("write rows");
}
