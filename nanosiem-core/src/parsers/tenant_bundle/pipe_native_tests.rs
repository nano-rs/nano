// SPDX-License-Identifier: AGPL-3.0-or-later
use super::{archive, model::TenantSource, overlay, vector_tests};
use crate::parsers::pipe::{native, Plan, Step};
use serde_json::json;

#[test]
fn native_pipe_chain_is_owned_guarded_and_runs_in_vector() {
    let steps:Vec<Step>=serde_json::from_value(json!([
        {"id":"parse","name":"Parse","kind":"parse","enabled":true,"config":{"format":"json","field":"message"}},
        {"id":"class","name":"Class","kind":"set","enabled":true,"config":{"field":"class_uid","value":4002}},
        {"id":"time","name":"Time","kind":"set","enabled":true,"config":{"field":"time","value":1700000000000_i64}},
        {"id":"dedupe","name":"Dedupe","kind":"dedupe","enabled":true,"config":{"fields":["id"],"cacheEvents":10}},
        {"id":"combine","name":"Combine","kind":"combine","enabled":true,"config":{"keys":["host"],"countField":"unmapped.count","maxEvents":2,"timeoutSec":1,"merge":{"bytes":"sum"}}},
        {"id":"route","name":"Route","kind":"route","enabled":true,"config":{"mode":"first","field":"unmapped.branch","routes":[{"label":"owned","predicate":".host == \"a\"","drop":false}],"fallback":"drop"}},
        {"id":"lookup","name":"Lookup","kind":"lookup","enabled":true,"config":{"table":"owners","version":"1","rows":[{"key":"a","value":"alice"}],"match":{"key":"host"},"outputs":{"value":"unmapped.owner"},"missing":"error"}}
    ])).unwrap();
    let plan = Plan {
        version: 2,
        revision: 1,
        steps,
    };
    let samples: Vec<String> = [
        json!({"id":1,"host":"a","bytes":1}),
        json!({"id":2,"host":"a","bytes":3}),
        json!({"id":2,"host":"a","bytes":3}),
    ]
    .iter()
    .map(serde_json::Value::to_string)
    .collect();
    let source = TenantSource {
        slug: "pipe-native".into(),
        log_source_id: uuid::Uuid::from_u128(44),
        version_id: 1,
        version_number: 1,
        name: "Native pipe".into(),
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
        samples: samples.clone(),
    };
    let base = archive::unpack(include_bytes!("testdata/platform-base.tar.gz")).unwrap();
    let (candidate, generated) = overlay::apply_overlay(&base, &[source]).unwrap();
    overlay::verify_against_base(&base, &candidate).unwrap();
    let prefix = "tenant__pipe_native";
    let text = candidate.text(&generated[0].tenant.file()).unwrap();
    let document: toml::Table = text.parse().unwrap();
    let types: Vec<_> = document["transforms"]
        .as_table()
        .unwrap()
        .values()
        .filter_map(|value| value.get("type").and_then(toml::Value::as_str))
        .collect();
    assert!(
        types.contains(&"dedupe")
            && types.contains(&"reduce")
            && types.contains(&"exclusive_route")
    );
    assert_eq!(
        native::lookup_files(prefix, &document).unwrap(),
        vec!["sources/parsers/tenant__pipe_native_lookup_6.csv"]
    );
    let (platform, _) = overlay::strip_overlay(&candidate).unwrap();
    assert_eq!(platform.files, base.files);
    let mut corrupted = candidate.clone();
    corrupted.put(
        &generated[0].tenant.file(),
        text.replace(
            &format!("{}/tenant__pipe_native_lookup_6.csv", native::LOOKUP_ROOT),
            "/etc/secrets/private.csv",
        )
        .into_bytes(),
    );
    assert!(overlay::verify_against_base(&base, &corrupted).is_err());
    assert!(!native::lookup_calls_owned(
        prefix,
        "get_enrichment_table_record(\"tenant__foreign_pipe_6_lookup\", {})"
    ));
    let release_tests = vector_tests::render(&[(&generated[0], &samples)]).unwrap();
    assert!(release_tests.contains("tenant__pipe_native_pipe_4_prepare.dropped"));
    assert!(release_tests.contains("no_outputs_from"));
    if let Ok(image) = std::env::var("NANO_PIPE_VECTOR_TEST_IMAGE") {
        let temp = tempfile::tempdir_in(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../target"),
        )
        .unwrap();
        let mut emitted = text.replace(native::LOOKUP_ROOT, "/fixtures");
        let lookup = native::table_file(prefix, 6);
        std::fs::write(
            temp.path().join(&lookup),
            candidate
                .file(&format!("sources/parsers/{lookup}"))
                .unwrap(),
        )
        .unwrap();
        emitted.push_str("\n[sources.events]\ntype=\"stdin\"\n[transforms.source_router]\ntype=\"route\"\ninputs=[\"events\"]\n[transforms.source_router.route]\ntenant__pipe_native=\"true\"\n[sinks.test]\ntype=\"blackhole\"\ninputs=[\"tenant__pipe_native_output\",\"tenant__pipe_native_ocsf_prepare\"]\n");
        let base_emitted = emitted.clone();
        let mut test = toml::Table::new();
        test.insert("name".into(), "native processing batch".into());
        let inputs = [
            json!({"id":1,"host":"a","bytes":1}),
            json!({"id":2,"host":"a","bytes":3}),
            json!({"id":2,"host":"a","bytes":3}),
        ];
        let inputs = inputs
            .iter()
            .map(|value| {
                let mut fields = toml::Table::new();
                fields.insert("message".into(), value.to_string().into());
                fields.insert("source_type".into(), "pipe-native".into());
                let mut input = toml::Table::new();
                input.insert("insert_at".into(), "tenant__pipe_native_parse".into());
                input.insert("type".into(), "log".into());
                input.insert("log_fields".into(), fields.into());
                toml::Value::Table(input)
            })
            .collect();
        test.insert("inputs".into(), toml::Value::Array(inputs));
        let mut condition = toml::Table::new();
        condition.insert("type".into(), "vrl".into());
        condition.insert("source".into(),"assert!(.event.class_uid == 4002)\nassert!(.event.bytes == 4)\nunmapped = object!(parse_json!(.event.unmapped))\nassert!(unmapped.count == 2)\nassert!(unmapped.branch == \"owned\")\nassert!(unmapped.owner == \"alice\")".into());
        let mut output = toml::Table::new();
        output.insert(
            "extract_from".into(),
            "tenant__pipe_native_ocsf_prepare".into(),
        );
        output.insert(
            "conditions".into(),
            toml::Value::Array(vec![condition.into()]),
        );
        test.insert("outputs".into(), toml::Value::Array(vec![output.into()]));
        let mut tests = toml::Table::new();
        tests.insert("tests".into(), toml::Value::Array(vec![test.into()]));
        let mut emitted_tests: toml::Table = release_tests.parse().unwrap();
        emitted_tests
            .get_mut("tests")
            .unwrap()
            .as_array_mut()
            .unwrap()
            .extend(tests["tests"].as_array().unwrap().iter().cloned());
        emitted.push_str(&toml::to_string(&emitted_tests).unwrap());
        std::fs::write(temp.path().join("vector.toml"), emitted).unwrap();
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
        let mut bad_samples = samples.clone();
        bad_samples.push(json!({"id":3,"host":"a","bytes":"wrong type"}).to_string());
        let failing =
            base_emitted + &vector_tests::render(&[(&generated[0], &bad_samples)]).unwrap();
        std::fs::write(temp.path().join("vector.toml"), failing).unwrap();
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
            .arg(image)
            .args(["test", "/fixtures/vector.toml"])
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "a bad member must fail release verification even alongside valid outputs"
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("tenant pipe-native sample"),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn native_bounds_hash_keys_preserve_typed_context_and_keep_events_out_of_lua() {
    let steps: Vec<Step> = serde_json::from_value(json!([
        {"id":"time","name":"Typed timestamps","kind":"vrl","enabled":true,"config":{"code":".timestamp = t'2025-01-01T00:00:00Z'\n.nested.when = t'2025-01-01T00:00:00Z'\n.nothing = null\n.empty = []"}},
        {"id":"dedupe","name":"Dedupe","kind":"dedupe","enabled":true,"config":{"fields":["key","message"],"cacheEvents":50000}},
        {"id":"combine","name":"Combine","kind":"combine","enabled":true,"config":{"keys":["key"],"countField":"count","maxEvents":100,"timeoutSec":60}}
    ])).unwrap();
    let plan = Plan {
        version: 2,
        revision: 1,
        steps,
    };
    let chain = native::render(&plan, "bounded", "events").unwrap();
    let dedupe = chain.transforms["bounded_pipe_1_native"]
        .as_table()
        .unwrap();
    assert_eq!(
        dedupe["cache"]["num_events"].as_integer(),
        Some(native::MAX_DEDUPE_EVENTS as i64)
    );
    assert_eq!(
        dedupe["fields"]["match"].as_array().unwrap(),
        &[toml::Value::String("signature".into())]
    );
    let prepare = chain.transforms["bounded_pipe_1_prepare"]["source"]
        .as_str()
        .unwrap();
    assert!(prepare.contains("SHA-256") && prepare.contains("is_timestamp"));
    let gate = chain.transforms["bounded_pipe_2_bound"].as_table().unwrap();
    let reducer = chain.transforms["bounded_pipe_2_native"]
        .as_table()
        .unwrap();
    assert_eq!(reducer["expire_after_ms"].as_integer(), Some(5000));
    assert_eq!(
        reducer["inputs"].as_array().unwrap(),
        &[
            toml::Value::String("bounded_pipe_2_stash".into()),
            toml::Value::String("bounded_pipe_2_bound".into())
        ]
    );
    // Only the {group_hash} control copy may reach the Lua gate: Vector's Lua
    // conversion drops metadata (finalizers) and rewrites null/[] values.
    assert_eq!(
        gate["inputs"].as_array().unwrap(),
        &[toml::Value::String("bounded_pipe_2_control".into())]
    );
    assert_eq!(
        chain.transforms["bounded_pipe_2_control"]["source"].as_str(),
        Some(". = { \"group_hash\": .group_hash }")
    );
    native::guard_transform("lua", gate).unwrap();
    let mut unsafe_gate = gate.clone();
    unsafe_gate.insert("source".into(), "os.execute('anything')".into());
    assert!(native::guard_transform("lua", &unsafe_gate).is_err());
    let Some(image) = std::env::var("NANO_PIPE_VECTOR_TEST_IMAGE").ok() else {
        return;
    };
    let temp =
        tempfile::tempdir_in(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../target"))
            .unwrap();
    let mut document = toml::Table::new();
    document.insert("transforms".into(), chain.transforms.into());
    // Reject every violating member, not merely require one matching output.
    let mut violations = toml::Table::new();
    violations.insert("type".into(), "filter".into());
    violations.insert(
        "inputs".into(),
        toml::Value::Array(vec![chain.output.clone().into()]),
    );
    violations.insert("condition".into(), "(.count != 1 && .count != 2) || !is_timestamp(.timestamp) || !is_timestamp(.nested.when) || exists(.group_hash) || exists(.signature) || !exists(.nothing) || .nothing != null || .empty != []".into());
    document
        .get_mut("transforms")
        .unwrap()
        .as_table_mut()
        .unwrap()
        .insert("bounds_violation".into(), violations.into());
    let mut inputs: Vec<toml::Value> = (0..=native::MAX_GROUPS)
        .map(|key| {
            let mut fields = toml::Table::new();
            fields.insert("key".into(), (key as i64).into());
            fields.insert("message".into(), "first".repeat(6000).into());
            let mut input = toml::Table::new();
            input.insert("insert_at".into(), "bounded_pipe_1_remap".into());
            input.insert("type".into(), "log".into());
            input.insert("log_fields".into(), fields.into());
            input.into()
        })
        .collect();
    let mut repeated = inputs[0].clone();
    repeated
        .get_mut("log_fields")
        .unwrap()
        .as_table_mut()
        .unwrap()
        .insert("message".into(), "again".into());
    inputs.push(repeated);
    let mut test = toml::Table::new();
    test.insert("name".into(), "bounded typed groups".into());
    test.insert("inputs".into(), toml::Value::Array(inputs));
    let mut condition = toml::Table::new();
    condition.insert("type".into(), "vrl".into());
    condition.insert("source".into(),"assert!(.count == 1 || .count == 2, \"markers bound groups; cross-input order may merge one reuse\")\nassert!(is_timestamp(.timestamp))\nassert!(is_timestamp(.nested.when))\nassert!(!exists(.group_hash))\nassert!(!exists(.signature))".into());
    let mut output = toml::Table::new();
    output.insert("extract_from".into(), chain.output.clone().into());
    output.insert(
        "conditions".into(),
        toml::Value::Array(vec![condition.into()]),
    );
    test.insert("outputs".into(), toml::Value::Array(vec![output.into()]));
    test.insert(
        "no_outputs_from".into(),
        toml::Value::Array(
            chain
                .failures
                .iter()
                .cloned()
                .chain(["bounds_violation".into()])
                .map(toml::Value::String)
                .collect(),
        ),
    );
    document.insert("tests".into(), toml::Value::Array(vec![test.into()]));
    let mut config = toml::to_string(&document).unwrap();
    let mut sink_inputs = vec![chain.output];
    sink_inputs.extend(chain.failures);
    sink_inputs.push("bounds_violation".into());
    config.push_str(&format!(
        "\n[sources.events]\ntype=\"stdin\"\n[sinks.out]\ntype=\"blackhole\"\ninputs={}\n",
        serde_json::to_string(&sink_inputs).unwrap()
    ));
    std::fs::write(temp.path().join("vector.toml"), config).unwrap();
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
        .arg(image)
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
