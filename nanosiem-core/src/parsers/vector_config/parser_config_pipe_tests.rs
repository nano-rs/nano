// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4919: Nano Pipe plans render into the parser slot of the generated
//! Vector config (source router → pipeline → extension → OCSF / UDM output).
//!
//! `pinned_vector_validates_and_runs_rendered_pipelines` additionally runs the
//! rendered config through `vector validate` and `vector test` on the pinned
//! fork image when `NANO_PIPE_VECTOR_IMAGE` names it (Docker required), e.g.
//! `NANO_PIPE_VECTOR_IMAGE=ghcr.io/nano-rs/vector:0.61.0-nano.2-debian`.

use super::super::VectorConfigManager;
use crate::parsers::pipe::{Plan, Step};
use crate::parsers::types::Parser;
use chrono::Utc;
use serde_json::{json, Value};
use uuid::Uuid;

fn parser(parser_vrl: &str, extension: Option<&str>) -> Parser {
    Parser {
        id: Uuid::new_v4(),
        name: "hec_app".to_string(),
        description: None,
        source_type: "routed".to_string(),
        parser_vrl: parser_vrl.to_string(),
        output_fields: None,
        feed_id: None,
        dispatch_source_config_id: None,
        dispatch_route_name: None,
        namespace: "default".to_string(),
        enabled: true,
        validated: true,
        validation_error: None,
        timezone: "UTC".to_string(),
        match_values: None,
        sampling_ratio: None,
        sampling_exclude_condition: None,
        extension_vrl: extension.map(str::to_string),
        extension_enabled: extension.is_some(),
        category: None,
        vendor: None,
        product: None,
        kind: "log".to_string(),
        enrich_kind: None,
        enrich_source: None,
        target_table: None,
        normalize_vrl: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn step(id: &str, kind: &str, config: Value) -> Step {
    Step {
        id: id.into(),
        name: id.into(),
        kind: kind.into(),
        enabled: true,
        condition: None,
        config: config.as_object().unwrap().clone(),
    }
}

fn manager() -> VectorConfigManager {
    VectorConfigManager::new(std::path::PathBuf::from("/tmp/nanosiem-test"))
}

/// The acceptance pipeline: parse JSON, mask the user, drop heartbeats.
fn stateless_plan() -> Plan {
    Plan {
        version: 2,
        revision: 1,
        steps: vec![
            step("parse", "parse", json!({"format":"json","field":"message"})),
            step("mask", "mask", json!({"fields":["user"],"operation":"replace","replacement":"[MASKED] '''\u{7f}"})),
            step("noise", "filter", json!({"predicate":".action == \"heartbeat\"","action":"drop"})),
        ],
    }
}

fn native_plan() -> Plan {
    let mut plan = stateless_plan();
    plan.steps.extend([
        step("dedupe", "dedupe", json!({"fields":["message"],"cacheEvents":100})),
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
    ]);
    plan
}

fn transforms(config: &str) -> toml::Table {
    let doc: toml::Table = config.parse().expect("generated config is valid TOML");
    doc["transforms"].as_table().unwrap().clone()
}

fn compile_all_remaps(config: &str) {
    let fns = crate::parsers::vrl_functions::parser_vrl_functions();
    for (name, body) in transforms(config) {
        if body["type"].as_str() == Some("remap") {
            let source = body["source"].as_str().unwrap();
            crate::parsers::vrl_guard::compile(source, &fns)
                .unwrap_or_else(|e| panic!("{name} does not compile: {}", e.render(source)));
        }
    }
}

#[test]
fn stateless_plan_renders_one_parse_remap_as_a_basic_string() {
    // NAN-5271: an unset profile now means OCSF; this asserts the UDM shape.
    let _udm = crate::schema::pin_active_schema_for_test(crate::schema::SchemaId::Udm);
    let p = parser(&stateless_plan().stored().unwrap(), None);
    let config = manager().generate_parser_config_string(&p);
    let t = transforms(&config);
    let parse = t["hec_app_parse"]["source"].as_str().unwrap();
    // Tenant literals survive (triple quotes as data, DEL as a VRL escape).
    assert!(parse.contains(r"[MASKED] '''\u{7f}"), "{parse}");
    assert!(!t.keys().any(|k| k.contains("_pipe_")));
    assert_eq!(
        t["hec_app_output"]["inputs"].as_array().unwrap().len(),
        2,
        "{config}"
    );
    compile_all_remaps(&config);
    manager().guarded_parser_config(&p).unwrap();
}

#[test]
fn native_plan_splices_a_chain_into_the_parser_slot() {
    // NAN-5271: an unset profile now means OCSF; this asserts the UDM shape.
    let _udm = crate::schema::pin_active_schema_for_test(crate::schema::SchemaId::Udm);
    let plan = native_plan();
    let p = parser(&plan.stored().unwrap(), Some(".team = \"soc\""));
    let config = manager().generate_parser_config_string(&p);
    let t = transforms(&config);
    // `_parse` is an identity remap from the router; the chain reads it.
    assert_eq!(t["hec_app_parse"]["source"].as_str().unwrap().trim(), ".");
    assert_eq!(
        t["hec_app_parse"]["inputs"].as_array().unwrap()[0].as_str(),
        Some("source_router.hec_app")
    );
    assert_eq!(
        t["hec_app_pipe_3_remap"]["inputs"].as_array().unwrap()[0].as_str(),
        Some("hec_app_parse")
    );
    // The extension follows the chain; `_output` reads the extension plus
    // every generated failure port.
    let chain = crate::parsers::pipe::native::render(&plan, "hec_app", "hec_app_parse").unwrap();
    assert_eq!(
        t["hec_app_extension"]["inputs"].as_array().unwrap()[0].as_str(),
        Some(chain.output.as_str())
    );
    let outputs: Vec<&str> = t["hec_app_output"]["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(outputs[0], "hec_app_extension");
    for failure in &chain.failures {
        assert!(outputs.contains(&failure.as_str()), "{failure} not unioned: {outputs:?}");
    }
    // First-match route renders as a chain of single-branch `route`s (the
    // image has no `exclusive_route`): branch 1 consumes branch 0's misses.
    assert_eq!(t["hec_app_pipe_4_route_0"]["type"].as_str(), Some("route"));
    assert_eq!(
        t["hec_app_pipe_4_route_1"]["inputs"].as_array().unwrap()[0].as_str(),
        Some("hec_app_pipe_4_route_0._unmatched")
    );
    assert_eq!(
        t["hec_app_pipe_4_fallback"]["inputs"].as_array().unwrap()[0].as_str(),
        Some("hec_app_pipe_4_route_1._unmatched")
    );
    // No enrichment table or file: the lookup snapshot is inline.
    assert!(!config.contains("enrichment_table"));
    compile_all_remaps(&config);
    manager().guarded_parser_config(&p).unwrap();
}

#[test]
fn invalid_stored_plans_are_refused_at_deploy() {
    let stored = stateless_plan().stored().unwrap();
    let edited = stored.replace(crate::parsers::pipe::BODY, ". = {}");
    let p = parser(&edited, None);
    assert!(manager().guarded_parser_config(&p).is_err());
    // The rendered fallback never forwards unprocessed events as success.
    assert!(manager()
        .generate_parser_config_string(&p)
        .contains("abort # invalid processing plan"));
}

// --- pinned Vector image ---------------------------------------------------

fn harness(config: &str, tests: &str) -> String {
    format!(
        "[sources.input]\ntype = \"demo_logs\"\nformat = \"json\"\ncount = 1\n\n\
         [transforms.source_router]\ntype = \"route\"\ninputs = [\"input\"]\n\
         [transforms.source_router.route]\nhec_app = 'true'\n\n\
         {config}\n\
         [sinks.out]\ntype = \"blackhole\"\ninputs = [\"hec_app_output\"]\n\n{tests}"
    )
}

fn run_vector(image: &str, dir: &std::path::Path, args: &[&str]) -> (bool, String) {
    let out = std::process::Command::new("docker")
        .args(["run", "--rm", "-v"])
        .arg(format!("{}:/c:ro", dir.display()))
        .arg(image)
        .args(args)
        .output()
        .expect("docker run");
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

#[test]
fn pinned_vector_validates_and_runs_rendered_pipelines() {
    let Ok(image) = std::env::var("NANO_PIPE_VECTOR_IMAGE") else {
        eprintln!("NANO_PIPE_VECTOR_IMAGE unset; skipping the pinned-image fixture");
        return;
    };
    let dir = std::env::temp_dir().join(format!("nano-pipe-fixture-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    for (name, plan) in [("stateless", stateless_plan()), ("native", native_plan())] {
        let p = parser(&plan.stored().unwrap(), Some(".team = \"soc\""));
        let config = manager().guarded_parser_config(&p).unwrap();
        // Behaviour on the real runtime: a heartbeat is dropped, a deny
        // event comes out masked, routed and enriched.
        let tests = r#"
[[tests]]
name = "masks and drops"
[[tests.inputs]]
insert_at = "hec_app_parse"
type = "log"
log_fields.message = '{"user":"alice","action":"deny","host":"h1"}'
[[tests.inputs]]
insert_at = "hec_app_parse"
type = "log"
log_fields.message = '{"user":"bob","action":"heartbeat","host":"h1"}'
[[tests.outputs]]
extract_from = "hec_app_extension"
[[tests.outputs.conditions]]
type = "vrl"
source = '''
assert!(starts_with(string!(.user), "[MASKED]"))
assert_eq!(.action, "deny")
assert_eq!(.team, "soc")
'''
"#;
        let tests = if name == "native" {
            tests.replace(
                "assert_eq!(.team, \"soc\")",
                "assert_eq!(.team, \"soc\")\nassert_eq!(.unmapped.branch, \"deny\")\nassert_eq!(.unmapped.owner, \"alice\")",
            )
        } else {
            tests.to_string()
        };
        let file = dir.join(format!("{name}.toml"));
        std::fs::write(&file, harness(&config, &tests)).unwrap();
        let path = format!("/c/{name}.toml");
        let (ok, log) = run_vector(&image, &dir, &["validate", "--no-environment", &path]);
        assert!(ok, "vector validate failed for {name}:\n{log}");
        let (ok, log) = run_vector(&image, &dir, &["test", &path]);
        assert!(ok, "vector test failed for {name}:\n{log}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Codex P1 (NAN-4919): in a first-match route, an earlier predicate's
/// RUNTIME ERROR is a non-match (Vector semantics), so the event must take
/// the next branch instead of falling through to a dropping fallback.
#[test]
fn pinned_vector_first_match_route_survives_an_erroring_predicate() {
    let Ok(image) = std::env::var("NANO_PIPE_VECTOR_IMAGE") else {
        eprintln!("NANO_PIPE_VECTOR_IMAGE unset; skipping the pinned-image fixture");
        return;
    };
    let plan = Plan {
        version: 2,
        revision: 1,
        steps: vec![step(
            "route",
            "route",
            json!({"mode":"first","field":"unmapped.branch","fallback":"drop","routes":[
                {"label":"server_error","predicate":"int!(.status) == 500"},
                {"label":"two","predicate":"true"}
            ]}),
        )],
    };
    // The batch preview already routes it to branch 2.
    let rows = crate::parsers::pipe::batch::run(&plan, &[json!({"message":"no status"})], None).unwrap();
    assert_eq!(rows[0].outputs[0]["unmapped"]["branch"], "two");
    let p = parser(&plan.stored().unwrap(), Some(".team = \"soc\""));
    let config = manager().guarded_parser_config(&p).unwrap();
    let tests = r#"
[[tests]]
name = "erroring first predicate falls to branch two"
[[tests.inputs]]
insert_at = "hec_app_parse"
type = "log"
log_fields.message = "no status"
[[tests.inputs]]
insert_at = "hec_app_parse"
type = "log"
log_fields.status = 500
[[tests.outputs]]
extract_from = "hec_app_extension"
[[tests.outputs.conditions]]
type = "vrl"
source = '''
b = string!(.unmapped.branch)
assert!(b == "two" || (b == "server_error" && .status == 500))
'''
[[tests]]
name = "the erroring event is not dropped"
[[tests.inputs]]
insert_at = "hec_app_parse"
type = "log"
log_fields.message = "no status"
[[tests.outputs]]
extract_from = "hec_app_extension"
[[tests.outputs.conditions]]
type = "vrl"
source = '''
assert_eq!(.unmapped.branch, "two")
'''
"#;
    let dir = std::env::temp_dir().join(format!("nano-pipe-route-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("route.toml"), harness(&config, tests)).unwrap();
    let (ok, log) = run_vector(&image, &dir, &["test", "/c/route.toml"]);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(ok, "vector test failed:\n{log}");
}
