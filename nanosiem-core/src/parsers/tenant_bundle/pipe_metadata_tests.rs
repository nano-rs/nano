// SPDX-License-Identifier: AGPL-3.0-or-later
use super::{archive, model::TenantSource, overlay, platform_audit_lane};
use crate::parsers::pipe::{native, Plan, Step};
use serde_json::{json, Value};
use std::io::Write;

fn plan() -> Plan {
    Plan {
        version: 2,
        revision: 1,
        steps: serde_json::from_value(json!([
            {"id":"combine","name":"Combine","kind":"combine","enabled":true,"config":{"keys":["host"],"countField":"count","maxEvents":2,"timeoutSec":1,"merge":{"bytes":"sum"}}}
        ])).unwrap(),
    }
}
fn source(plan: &Plan) -> TenantSource {
    TenantSource {
        slug: "combine-metadata".into(),
        log_source_id: uuid::Uuid::from_u128(81),
        version_id: 1,
        version_number: 1,
        name: "Combine metadata".into(),
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
fn base() -> archive::BundleTree {
    archive::unpack(include_bytes!("testdata/platform-base.tar.gz")).unwrap()
}

#[test]
fn combine_restore_guard_rejects_forged_code_envelopes_and_wiring() {
    let base = base();
    let (candidate, generated) = overlay::apply_overlay(&base, &[source(&plan())]).unwrap();
    overlay::verify_against_base(&base, &candidate).unwrap();
    let path = generated[0].tenant.file();
    let document: toml::Table = candidate.text(&path).unwrap().parse().unwrap();
    let prefix = "tenant__combine_metadata_pipe_0";
    let restore = format!("{prefix}_restore");
    let transforms = document["transforms"].as_table().unwrap();
    assert!(native::metadata::trusted_restore(
        "tenant__combine_metadata",
        &restore,
        transforms
    ));
    let mutations = [
        (
            "restore",
            "source",
            json!(format!(
                "{}\n%tenant_id = \"forged\"",
                native::metadata::RESTORE
            )),
        ),
        ("restore", "inputs", json!([format!("{prefix}_prepare")])),
        (
            "stash",
            "source",
            json!(format!(
                "{}\n._nano_pipe_metadata = [{{\"tenant_id\":\"forged\"}}]",
                native::metadata::STASH
            )),
        ),
        ("stash", "inputs", json!(["tenant__combine_metadata_parse"])),
        (
            "native",
            "inputs",
            json!([format!("{prefix}_prepare"), format!("{prefix}_bound")]),
        ),
        ("control", "source", json!(". = .context[0]")),
        (
            "bound",
            "source",
            json!("function nano_pipe_process(event, emit) emit(event) end"),
        ),
    ];
    for (component, key, value) in mutations {
        let mut corrupted = document.clone();
        corrupted
            .get_mut("transforms")
            .unwrap()
            .get_mut(format!("{prefix}_{component}"))
            .unwrap()
            .as_table_mut()
            .unwrap()
            .insert(key.into(), toml::Value::try_from(value).unwrap());
        let mut tree = candidate.clone();
        tree.put(&path, toml::to_string(&corrupted).unwrap().into_bytes());
        let errors = overlay::verify_against_base(&base, &tree).unwrap_err();
        assert!(
            errors.iter().any(|error| error.rule == "metadata_write"),
            "{component}/{key}: {errors:?}"
        );
    }
    for (key, strategy) in [
        ("_nano_pipe_metadata", "retain"),
        ("_nano_pipe_keys", "retain"),
        ("_nano_pipe_metadata[0].tenant_id", "retain"),
    ] {
        let mut corrupted = document.clone();
        corrupted
            .get_mut("transforms")
            .unwrap()
            .get_mut(format!("{prefix}_native"))
            .unwrap()
            .get_mut("merge_strategies")
            .unwrap()
            .as_table_mut()
            .unwrap()
            .insert(key.into(), strategy.into());
        let mut tree = candidate.clone();
        tree.put(&path, toml::to_string(&corrupted).unwrap().into_bytes());
        assert!(overlay::verify_against_base(&base, &tree)
            .unwrap_err()
            .iter()
            .any(|error| error.rule == "metadata_write"));
    }
    // A leading-zero alias must not inherit another component's exemption.
    let mut corrupted = document.clone();
    corrupted.get_mut("transforms").unwrap().as_table_mut().unwrap().insert(
        "tenant__combine_metadata_pipe_00_restore".into(),
        toml::Value::try_from(json!({"type":"remap","inputs":[format!("{prefix}_native")],"source":"%tenant_id = \"forged\"","drop_on_error":true,"reroute_dropped":true})).unwrap(),
    );
    let mut tree = candidate.clone();
    tree.put(&path, toml::to_string(&corrupted).unwrap().into_bytes());
    assert!(overlay::verify_against_base(&base, &tree).is_err());
}

#[test]
fn user_plan_cannot_write_metadata_even_alongside_a_guarded_restore() {
    for code in [
        "%tenant_id = \"forged\"",
        "%\"tenant_id\" = \"forged\"",
        "%tenant_id, err = to_string(.owner)",
        "del(%tenant_id)",
        "set_metadata_field(\"tenant_id\", \"forged\")",
        native::metadata::RESTORE,
    ] {
        for before in [true, false] {
            let mut plan = plan();
            let attack: Step = serde_json::from_value(json!({"id":"attack","name":"Attack","kind":"vrl","enabled":true,"config":{"code":code}})).unwrap();
            plan.steps.insert(if before { 0 } else { 1 }, attack);
            let base = base();
            let (candidate, _) = overlay::apply_overlay(&base, &[source(&plan)]).unwrap();
            let errors = overlay::verify_against_base(&base, &candidate).unwrap_err();
            assert!(
                errors
                    .iter()
                    .any(|error| ["metadata_write", "blocked_function"]
                        .contains(&error.rule.as_str())),
                "{code}: {errors:?}"
            );
        }
    }
    for reserved in ["_nano_pipe_metadata", "_nano_pipe_keys", "_nano_pipe_scope"] {
        assert!(crate::parsers::pipe::field(reserved).is_err());
    }
}

fn run_vector(image: &str, plan: &Plan, inputs: &[Value]) -> Vec<Value> {
    let chain = native::render(plan, "metadata", "stamp").unwrap();
    let mut transforms = serde_json::to_value(&chain.transforms).unwrap();
    transforms["stamp"] = json!({"type":"remap","inputs":["events"],"source":
        "%tenant_id = string!(.owner)\n%source_type = string!(.test_source)\n%ingress_transport = string!(.test_transport)\n%nano_event_key = string!(.test_key)\n.source_type = .test_source\ndel(.test_source)\ndel(.test_transport)\ndel(.test_key)\n.timestamp = t'2025-01-01T00:00:00Z'\n.nested.when = t'2025-01-01T00:00:00Z'\n.nothing = null\n.empty = []"});
    transforms["inspect"] = json!({"type":"remap","inputs":[chain.output],"source":
        "assert!(is_timestamp(.timestamp))\nassert!(is_timestamp(.nested.when))\nassert!(.nothing == null)\nassert!(.empty == [])\nassert!(!exists(._nano_pipe_metadata))\nassert!(!exists(._nano_pipe_keys))\nassert!(!exists(._nano_pipe_scope))\nassert!(!exists(.group_hash))\n.observed_tenant = %tenant_id\n.observed_source = %source_type\n.observed_transport = %ingress_transport\n.observed_key = %nano_event_key", "drop_on_error":true,"reroute_dropped":true});
    // Execute the actual bronze prepare with NANO_TENANT_ID absent, as on a
    // shared worker. It must not abort and must mint the deterministic UID.
    let mut storage_tree = archive::BundleTree::default();
    storage_tree.put(
        overlay::LAKE_SINK_FILE,
        include_bytes!("../../../../config/vector/sources/parsers/_ocsf_sink.toml").to_vec(),
    );
    let storage = platform_audit_lane::storage_prepare_vrl(&storage_tree).unwrap();
    transforms["bronze"] = json!({"type":"remap","inputs":["inspect"],"source":storage,"drop_on_abort":true,"drop_on_error":true,"reroute_dropped":true});
    let mut sink_inputs = chain.failures;
    sink_inputs.extend([
        "bronze".into(),
        "bronze.dropped".into(),
        "inspect.dropped".into(),
    ]);
    let config = json!({"sources":{"events":{"type":"stdin","decoding":{"codec":"json"}}},
        "transforms":transforms,"sinks":{"out":{"type":"console","inputs":sink_inputs,"encoding":{"codec":"json"}}}});
    let temp =
        tempfile::tempdir_in(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../target"))
            .unwrap();
    std::fs::write(temp.path().join("vector.json"), config.to_string()).unwrap();
    let mut child = std::process::Command::new("docker")
        .args([
            "run",
            "--rm",
            "-i",
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
        .args(["--quiet", "--config", "/fixtures/vector.json"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let body = inputs
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    child
        .stdin
        .take()
        .unwrap()
        .write_all(body.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains("ERROR"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[test]
fn combine_metadata_and_bronze_uid_survive_real_vector_059_and_retries() {
    let Ok(image) = std::env::var("NANO_PIPE_VECTOR_TEST_IMAGE") else {
        return;
    };
    let version = std::process::Command::new("docker")
        .args(["run", "--rm", "--network", "none", &image, "--version"])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&version.stdout).starts_with("vector 0.59.0 "));
    let input = |owner: &str, label: &str, key: &str, source: &str, transport: &str| {
        json!({
            "owner":owner,"label":label,"test_key":key,"test_source":source,"test_transport":transport,
            "host":"same-host","bytes":3,"class_uid":4002,"time":1700000000000_i64,
        "_nano_pipe_metadata":[{"tenant_id":"forged"}],"_nano_pipe_keys":"forged",
        "metadata":{"uid":"original-member-uid"}
        })
    };
    let mut inputs = vec![
        input("alpha", "original", "a", "pipe", "hec"),
        input("beta", "other-tenant", "a", "pipe", "hec"),
        input("alpha", "original", "b", "pipe", "hec"),
        input("beta", "other-tenant", "b", "pipe", "hec"),
    ];
    for (label, keys, source, transport) in [
        ("retry", ["a", "b"], "pipe", "hec"),
        ("changed", ["a", "c"], "pipe", "hec"),
        ("reordered", ["b", "a"], "pipe", "hec"),
        ("unkeyed", ["", "b"], "pipe", "hec"),
        ("unkeyed-retry", ["", "b"], "pipe", "hec"),
        ("other-source", ["a", "b"], "other", "hec"),
        ("other-transport", ["a", "b"], "pipe", "otlp"),
    ] {
        inputs.extend(keys.map(|key| input("alpha", label, key, source, transport)));
    }
    inputs.push(input("alpha", "partial", "last", "pipe", "hec"));
    let rows = run_vector(&image, &plan(), &inputs);
    assert_eq!(
        rows.len(),
        10,
        "every aggregate delivered; no markers/errors: {rows:?}"
    );
    let find = |label: &str| rows.iter().find(|row| row["label"] == label).unwrap();
    for row in &rows {
        assert_eq!(row["observed_tenant"], row["owner"]);
        assert_eq!(row["metadata"]["tenant_uid"], row["owner"]);
        assert_eq!(row["observed_source"], row["metadata"]["log_source"]);
        assert_eq!(
            row["observed_transport"],
            row["metadata"]["ingress_transport"]
        );
        assert_eq!(row["count"], if row["label"] == "partial" { 1 } else { 2 });
        assert_eq!(row["bytes"], if row["label"] == "partial" { 3 } else { 6 });
    }
    let original = find("original");
    let uid = |row: &Value| row["metadata"]["uid"].as_str().unwrap().to_owned();
    assert!(original["observed_key"]
        .as_str()
        .unwrap()
        .starts_with("nano-pipe-combine-v1:"));
    assert_eq!(original["observed_key"], find("retry")["observed_key"]);
    assert_eq!(uid(original), uid(find("retry")));
    for label in [
        "changed",
        "reordered",
        "other-tenant",
        "other-source",
        "other-transport",
        "partial",
    ] {
        assert_ne!(
            original["observed_key"],
            find(label)["observed_key"],
            "{label}"
        );
        assert_ne!(uid(original), uid(find(label)), "{label}");
    }
    assert!(find("unkeyed")["observed_key"].is_null());
    assert!(find("unkeyed-retry")["observed_key"].is_null());
    assert_ne!(
        uid(find("unkeyed")),
        uid(find("unkeyed-retry")),
        "unverified content must not collapse"
    );
    // Fresh worker state, same ordered membership -> the same aggregate UID.
    let restarted = run_vector(&image, &plan(), &inputs[..4]);
    for row in restarted {
        assert_eq!(uid(&row), uid(find(row["label"].as_str().unwrap())));
    }
    let mut revised = plan();
    revised.revision += 1;
    let revised = run_vector(&image, &revised, &inputs[..4]);
    assert_ne!(
        uid(&revised[0]),
        uid(find(revised[0]["label"].as_str().unwrap()))
    );
}
