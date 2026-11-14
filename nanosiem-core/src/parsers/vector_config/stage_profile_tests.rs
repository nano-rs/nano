// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5180: the `vector_stage_profile` example walks the rendered topology.
//!
//! It must run every transform an event reaches (a processing plan's
//! `_pipe_*` stages, an aborted record's `.dropped` path into `_output` and
//! `db_parser_health`) and refuse a component it cannot simulate rather than
//! silently skip it and under-report CPU.

#[allow(dead_code)]
#[path = "../../../examples/vector_stage_profile.rs"]
mod stage_profile;

use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

use super::VectorConfigManager;
use crate::parsers::pipe::{Plan, Step};
use crate::parsers::types::Parser;
use stage_profile::{http_event, Profile};

const BASE: &str = include_str!("../../../../config/vector/00-base.toml");

fn parser(name: &str, parser_vrl: &str) -> Parser {
    Parser {
        activation_parked: false,
        id: Uuid::new_v4(),
        name: name.into(),
        description: None,
        source_type: "routed".into(),
        parser_vrl: parser_vrl.into(),
        output_fields: None,
        feed_id: None,
        dispatch_source_config_id: None,
        dispatch_route_name: None,
        namespace: "default".into(),
        enabled: true,
        validated: true,
        validation_error: None,
        timezone: "UTC".into(),
        match_values: None,
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

fn step(id: &str, kind: &str, config: serde_json::Value) -> Step {
    Step {
        id: id.into(),
        name: id.into(),
        kind: kind.into(),
        enabled: true,
        condition: None,
        config: config.as_object().unwrap().clone(),
    }
}

/// A plan with native steps the profiler can run (a first-match route and an
/// inline lookup render as `route` / `remap` transforms), plus `extra`.
fn plan(extra: Vec<Step>) -> String {
    let mut steps = vec![
        step("parse", "parse", json!({"format":"json","field":"message"})),
        step(
            "route",
            "route",
            json!({"mode":"first","field":"unmapped.branch","routes":[
                {"label":"deny","predicate":".action == \"deny\""},
                {"label":"any","predicate":"true"}
            ]}),
        ),
        step(
            "owners",
            "lookup",
            json!({"table":"owners","version":"1","rows":[{"host":"h1","owner":"alice"}],
                   "match":{"host":"host"},"outputs":{"owner":"unmapped.owner"}}),
        ),
    ];
    steps.extend(extra);
    Plan { version: 2, revision: 1, steps }.stored().unwrap()
}

/// The rendered tree for `parsers`: static HTTP lane, router, each parser's
/// file, combiner and shared pipeline (OCSF profile).
fn profile(parsers: &[Parser]) -> Profile {
    let m = VectorConfigManager::new("/tmp/nanosiem-test");
    let routed: Vec<&Parser> = parsers.iter().collect();
    let router = format!(
        "[transforms.source_router]\ntype = \"route\"\ninputs = [\"source_type_extract\"]\n\n[transforms.source_router.route]\n{}",
        VectorConfigManager::source_router_route_lines(&routed, parsers)
    );
    let mut docs = vec![
        ("00-base.toml".to_string(), BASE.to_string()),
        ("_router.toml".to_string(), router),
        ("_combiner.toml".to_string(), VectorConfigManager::combiner_config_content_for(parsers, true)),
        ("_pipeline.toml".to_string(), VectorConfigManager::pipeline_config_content().to_string()),
    ];
    for p in parsers {
        docs.push((format!("{}.toml", p.name), m.generate_parser_config_for(p, true)));
    }
    Profile::load(&docs).unwrap_or_else(|e| panic!("{e}"))
}

fn ran(p: &Profile, component: &str) -> usize {
    p.rows().iter().find(|r| r.component == component).map_or(0, |r| r.runs)
}

#[test]
fn walks_native_plan_stages_and_the_dropped_path() {
    let aborting = parser(
        "boom_app",
        "if (to_string(.message) ?? \"\") == \"boom\" { abort }\n. = {\"class_uid\": 0, \"time\": 1762164000000, \"raw_data\": .message}",
    );
    let planned = parser("hec_app", &plan(vec![]));
    let mut p = profile(&[aborting, planned]);

    p.run(http_event(r#"{"action":"deny","host":"h1","user":"a"}"#, "hec_app", "text/plain")).unwrap();
    let pipe: Vec<String> = p
        .rows()
        .iter()
        .filter(|r| r.component.starts_with("hec_app_pipe_") && r.runs > 0)
        .map(|r| r.component.clone())
        .collect();
    assert!(pipe.len() >= 3, "the plan's generated stages ran: {pipe:?}");
    // NAN-5346: on OCSF a record without `class_uid` takes `_ocsf_failure`
    // into `_ocsf_prepare`; there is no `_output` step any more.
    assert_eq!(ran(&p, "hec_app_output"), 0, "OCSF parsers have no UDM `_output` step");
    assert_eq!(ran(&p, "hec_app_ocsf_failure"), 1, "a record without class_uid is a parse-error record");
    assert_eq!(ran(&p, "hec_app_ocsf_prepare"), 1, "and reaches the OCSF lane");
    assert_eq!(ran(&p, "db_parser_health"), 1);

    p.run(http_event("boom", "boom_app", "text/plain")).unwrap();
    assert_eq!(ran(&p, "boom_app_parse"), 1);
    assert_eq!(ran(&p, "boom_app_ocsf_failure"), 1, "the rerouted original becomes a parse-error record");
    assert_eq!(ran(&p, "boom_app_ocsf_prepare"), 1, "which is stored in the OCSF lane");
    assert_eq!(ran(&p, "boom_app_output"), 0, "never the UDM `_output` path");
    assert_eq!(ran(&p, "db_parser_health"), 2, "and is counted by parser health");

    p.run(http_event("fine", "boom_app", "text/plain")).unwrap();
    assert_eq!(ran(&p, "boom_app_ocsf_prepare"), 2);
    assert!(p.not_reached(&["boom_app_"]).is_empty(), "{:?}", p.not_reached(&["boom_app_"]));
}

#[test]
fn refuses_a_native_component_it_cannot_simulate() {
    let deduped = parser(
        "hec_app",
        &plan(vec![step("dedupe", "dedupe", json!({"fields":["message"],"cacheEvents":100}))]),
    );
    let mut p = profile(&[deduped]);
    let err = p
        .run(http_event(r#"{"action":"allow","host":"h1"}"#, "hec_app", "text/plain"))
        .expect_err("a dedupe stage cannot be simulated");
    assert!(err.contains("dedupe"), "{err}");
}
