// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-3625: "Input is" route branches read the platform input identity
//! (`%nano_credential_id`), pass the bundle guard, cannot be forged from
//! tenant VRL, and route in the real Vector runtime.
use super::{archive, model::TenantSource, overlay};
use crate::parsers::pipe::{native, Plan, Step};
use serde_json::json;

const PUSH: &str = "6f1c0c1e-2b8f-4d7e-9a51-0c5e6c1d2a10";
const PULL: &str = "0b7e4d33-8c2a-4f6e-b1d9-5a3f2e7c9d01";

fn plan(steps: serde_json::Value) -> Plan {
    let steps: Vec<Step> = serde_json::from_value(steps).unwrap();
    Plan {
        version: 2,
        revision: 1,
        steps,
    }
}

fn input_route() -> serde_json::Value {
    json!({"id":"route","name":"Route by input","kind":"route","enabled":true,"config":{
    "mode":"first","field":"unmapped.input_branch","fallback":"drop",
    "routes":[
        {"label":"pushed","inputs":[format!("push:{PUSH}")]},
        {"label":"pulled","inputs":[format!("pull:{PULL}")]}
    ]}})
}

fn source(plan: &Plan) -> TenantSource {
    TenantSource {
        slug: "pipe-input".into(),
        log_source_id: uuid::Uuid::from_u128(77),
        version_id: 1,
        version_number: 1,
        name: "Route by input".into(),
        parser_vrl: plan.stored().unwrap(),
        extension_vrl: None,
        extension_enabled: false,
        vendor: None,
        product: None,
        category: None,
        namespace: "default".into(),
        timezone: "UTC".into(),
        sampling_ratio: None,
        sampling_exclude_condition: None,
        forked_from: None,
        samples: vec![],
    }
}

#[test]
fn input_route_renders_platform_identity_checks_and_passes_the_guard() {
    let plan = plan(json!([input_route()]));
    let chain = native::render(&plan, "lane", "events").unwrap();
    let routes = chain.transforms["lane_pipe_0_native"]["routes"]
        .as_array()
        .unwrap();
    assert_eq!(
        routes[0]["condition"].as_str(),
        Some(format!("(%nano_credential_id == \"{PUSH}\")").as_str())
    );
    assert_eq!(
        routes[1]["condition"].as_str(),
        Some(format!("(%nano_credential_id == \"pull:{PULL}\")").as_str())
    );

    let base = archive::unpack(include_bytes!("testdata/platform-base.tar.gz")).unwrap();
    let (candidate, generated) = overlay::apply_overlay(&base, &[source(&plan)]).unwrap();
    overlay::verify_against_base(&base, &candidate).unwrap();
    let text = candidate.text(&generated[0].tenant.file()).unwrap();
    let document: toml::Table = text.parse().unwrap();
    let conditions: Vec<&str> = document["transforms"]
        .as_table()
        .unwrap()
        .values()
        .filter(|t| t.get("type").and_then(toml::Value::as_str) == Some("exclusive_route"))
        .flat_map(|t| t["routes"].as_array().unwrap())
        .filter_map(|route| route["condition"].as_str())
        .collect();
    assert_eq!(
        conditions,
        vec![
            format!("(%nano_credential_id == \"{PUSH}\")"),
            format!("(%nano_credential_id == \"pull:{PULL}\")"),
        ],
        "{text}"
    );
}

#[test]
fn branches_without_inputs_render_exactly_as_before() {
    // Existing route plans carry no `inputs`: the rendered condition is the
    // author's predicate verbatim, so their bundles do not change.
    let plan = plan(
        json!([{"id":"route","name":"Route","kind":"route","enabled":true,"config":{
        "mode":"fanout","routes":[{"label":"a","predicate":".host == \"a\""}]}}]),
    );
    let chain = native::render(&plan, "lane", "events").unwrap();
    assert_eq!(
        chain.transforms["lane_pipe_0_native"]["route"]["branch_0"].as_str(),
        Some(".host == \"a\"")
    );
}

#[test]
fn tenant_vrl_cannot_forge_the_input_identity() {
    // A tenant step that stamps a different input before the route is
    // refused by the bundle guard: `%` metadata is platform-owned.
    for forge in [
        format!("%nano_credential_id = \"pull:{PULL}\""),
        "del(%nano_credential_id)".to_string(),
        format!("%\"nano_credential_id\" = \"{PUSH}\""),
    ] {
        let plan = plan(json!([
            {"id":"forge","name":"Forge","kind":"vrl","enabled":true,"config":{"code":forge}},
            input_route()
        ]));
        let base = archive::unpack(include_bytes!("testdata/platform-base.tar.gz")).unwrap();
        let error = match overlay::apply_overlay(&base, &[source(&plan)]) {
            Err(error) => error.to_string(),
            Ok((candidate, _)) => format!(
                "{:?}",
                overlay::verify_against_base(&base, &candidate).expect_err(&forge)
            ),
        };
        assert!(error.contains("metadata"), "{forge}: {error}");
    }
    // Pipe field steps cannot write the stored identity either.
    for path in ["metadata.nano_credential_id", "metadata.nano_input"] {
        let plan = Plan {
            version: 2,
            revision: 1,
            steps: serde_json::from_value(json!([
                {"id":"set","name":"Set","kind":"set","enabled":true,"config":{"field":path,"value":"x"}}
            ]))
            .unwrap(),
        };
        assert!(
            plan.validate().unwrap_err().contains("Platform identity"),
            "{path}"
        );
    }
}

#[test]
fn input_route_runs_in_vector() {
    let Ok(image) = std::env::var("NANO_PIPE_VECTOR_TEST_IMAGE") else {
        return;
    };
    let plan = plan(json!([input_route()]));
    let chain = native::render(&plan, "lane", "stamp").unwrap();
    // `stamp` stands in for ingress: it sets the platform metadata from a
    // test-only field the way the Worker/pull stamp does. Every event also
    // carries a forged payload identity that must be ignored.
    let mut config = toml::Table::new();
    let mut sources = toml::Table::new();
    sources.insert(
        "events".into(),
        toml::Value::Table(toml::from_str("type = \"stdin\"").unwrap()),
    );
    config.insert("sources".into(), sources.into());
    let mut transforms = chain.transforms.clone();
    transforms.insert(
        "stamp".into(),
        toml::Value::Table(
            toml::from_str(
                &format!("type = \"remap\"\ninputs = [\"events\"]\nsource = '''\nif exists(.test_stamp) {{ %nano_credential_id = string!(del(.test_stamp)) }}\n.metadata = {{ \"nano_credential_id\": \"{PUSH}\", \"nano_input\": \"push:{PUSH}\" }}\n'''"),
            )
            .unwrap(),
        ),
    );
    config.insert("transforms".into(), transforms.into());
    let mut sinks = toml::Table::new();
    sinks.insert(
        "out".into(),
        toml::Value::Table(
            toml::from_str(&format!(
                "type = \"blackhole\"\ninputs = [\"{}\"]",
                chain.output
            ))
            .unwrap(),
        ),
    );
    config.insert("sinks".into(), sinks.into());
    let case = |name: &str, stamp: Option<String>, branch: &str| {
        let mut fields = toml::Table::new();
        fields.insert("message".into(), name.into());
        if let Some(stamp) = stamp {
            fields.insert("test_stamp".into(), stamp.into());
        }
        let mut input = toml::Table::new();
        input.insert("insert_at".into(), "stamp".into());
        input.insert("type".into(), "log".into());
        input.insert("log_fields".into(), fields.into());
        let mut test = toml::Table::new();
        test.insert("name".into(), name.into());
        test.insert("inputs".into(), toml::Value::Array(vec![input.into()]));
        let mut condition = toml::Table::new();
        condition.insert("type".into(), "vrl".into());
        condition.insert(
            "source".into(),
            format!("assert_eq!(.unmapped.input_branch, \"{branch}\")").into(),
        );
        let mut output = toml::Table::new();
        output.insert("extract_from".into(), chain.output.clone().into());
        output.insert(
            "conditions".into(),
            toml::Value::Array(vec![condition.into()]),
        );
        test.insert("outputs".into(), toml::Value::Array(vec![output.into()]));
        toml::Value::Table(test)
    };
    let mut no_output = toml::Table::new();
    no_output.insert("name".into(), "unknown input falls back to drop".into());
    let mut input = toml::Table::new();
    input.insert("insert_at".into(), "stamp".into());
    input.insert("type".into(), "log".into());
    let mut fields = toml::Table::new();
    fields.insert("message".into(), "unknown".into());
    input.insert("log_fields".into(), fields.into());
    no_output.insert("inputs".into(), toml::Value::Array(vec![input.into()]));
    no_output.insert(
        "no_outputs_from".into(),
        toml::Value::Array(vec![chain.output.clone().into()]),
    );
    config.insert(
        "tests".into(),
        toml::Value::Array(vec![
            case("push input", Some(PUSH.into()), "pushed"),
            // The payload claims the push credential; the stamp says pull.
            case("pull input", Some(format!("pull:{PULL}")), "pulled"),
            no_output.into(),
        ]),
    );
    let temp =
        tempfile::tempdir_in(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../target"))
            .unwrap();
    std::fs::write(
        temp.path().join("vector.toml"),
        toml::to_string(&config).unwrap(),
    )
    .unwrap();
    let output = std::process::Command::new("docker")
        .args([
            "run",
            "--rm",
            "--network",
            "none",
            "--memory",
            "512m",
            "--cpus",
            "2",
            "-v",
        ])
        .arg(format!("{}:/fixtures:ro", temp.path().display()))
        .arg(&image)
        .args(["test", "/fixtures/vector.toml"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
