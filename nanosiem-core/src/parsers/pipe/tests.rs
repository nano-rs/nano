// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;
use crate::parsers::VrlValidator;
use serde_json::json;

fn step(kind: &str, config: Value) -> Step {
    Step {
        id: kind.into(),
        name: kind.into(),
        kind: kind.into(),
        enabled: true,
        condition: None,
        config: config.as_object().unwrap().clone(),
    }
}
fn plan(steps: Vec<Step>) -> Plan {
    Plan {
        version: 2,
        revision: 1,
        steps,
    }
}
async fn execute(steps: Vec<Step>, input: Value) -> Value {
    let plan = plan(steps);
    let code = format!("{HEADER}{}\n{BODY}", serde_json::to_string(&plan).unwrap());
    let results = VrlValidator::new()
        .test_vrl_batch(&code, &[input.to_string()])
        .await
        .unwrap();
    assert!(results[0].success, "{code}\n{:?}", results[0].error);
    results[0].output.clone().unwrap()
}

#[tokio::test]
async fn fields_compile_and_execute_multiple_typed_operations() {
    let output = execute(
        vec![step(
            "fields",
            json!({"operation":"batch", "operations":[
                {"operation":"rename","field":"old","target":"new"},
                {"operation":"remove","field":"secret"},
                {"operation":"set","field":"note","value":"\n[sinks.example]\n'''"}
            ]}),
        )],
        json!({"old":7,"secret":"private"}),
    )
    .await;
    assert_eq!(output, json!({"new":7,"note":"\n[sinks.example]\n'''"}));
}

#[tokio::test]
async fn mask_executes_sha256_md5_and_unicode_partial_masking() {
    for (algorithm, length) in [("sha256", 64), ("md5", 32)] {
        let output = execute(
            vec![step(
                "mask",
                json!({"operation":"hash","algorithm":algorithm,"fields":["user"]}),
            )],
            json!({"user":"alice"}),
        )
        .await;
        assert_eq!(output["user"].as_str().unwrap().len(), length);
    }
    let output = execute(vec![step("mask", json!({"operation":"partial","fields":["user"],"keepStart":1,"keepEnd":1,"replacement":"*"}))], json!({"user":"Ålice"})).await;
    assert_eq!(output["user"], "Å***e");
}

#[tokio::test]
async fn filter_discards_matching_events_and_never_runs_later_steps() {
    let steps = vec![
        step(
            "filter",
            json!({"predicate":".action == \"heartbeat\"","action":"drop"}),
        ),
        step("set", json!({"field":"processed","value":true})),
    ];
    assert_eq!(
        execute(steps.clone(), json!({"action":"heartbeat"})).await,
        json!([])
    );
    assert_eq!(
        execute(steps, json!({"action":"deny"})).await,
        json!({"action":"deny","processed":true})
    );
    assert_eq!(
        execute(
            vec![step(
                "filter",
                json!({"predicate":".ok == true","action":"keep"})
            )],
            json!({"ok":false})
        )
        .await,
        json!([])
    );
}

#[tokio::test]
async fn sampling_is_deterministic_keyed_and_supports_exemptions() {
    let sampling = step(
        "sample",
        json!({"ratio":3,"groupBy":"message","exempt":".critical == true"}),
    );
    let code = compile_step(&sampling).unwrap();
    let inputs: Vec<String> = (0..30)
        .map(|i| json!({"message":format!("event-{i}")}).to_string())
        .collect();
    let validator = VrlValidator::new();
    let first = validator.test_vrl_batch(&code, &inputs).await.unwrap();
    let second = validator.test_vrl_batch(&code, &inputs).await.unwrap();
    assert!(
        first.iter().all(|r| r.success),
        "{:?}",
        first
            .iter()
            .filter_map(|r| r.error.as_ref())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        first.iter().map(|r| &r.output).collect::<Vec<_>>(),
        second.iter().map(|r| &r.output).collect::<Vec<_>>()
    );
    let kept = first
        .iter()
        .filter(|r| r.output.as_ref().is_some_and(Value::is_object))
        .count();
    assert!(kept > 0 && kept < 30);
    assert!(
        execute(vec![sampling], json!({"message":"always","critical":true}))
            .await
            .is_object()
    );
}

#[tokio::test]
async fn split_emits_children_with_context_and_applies_following_steps_to_each() {
    let split = step(
        "split",
        json!({"field":".items","as":".item","keep":["class_uid"],"max":4}),
    );
    let mut local = step("vrl", json!({"code":"seed = 8"}));
    local.id = "before".into();
    let mut after = step("vrl", json!({"code":".item = int!(.item) + seed"}));
    after.id = "after".into();
    let output = execute(
        vec![local, split, after],
        json!({"class_uid":1001,"items":[1,2],"unused":"x"}),
    )
    .await;
    assert_eq!(
        output,
        json!([{"class_uid":1001,"item":9},{"class_uid":1001,"item":10}])
    );
}

#[tokio::test]
async fn split_limit_errors_instead_of_silently_truncating() {
    let code = compile_step(&step("split", json!({"field":"items","as":"item","max":1}))).unwrap();
    let tested = VrlValidator::new()
        .test_vrl_batch(&code, &[json!({"items":[1,2]}).to_string()])
        .await
        .unwrap();
    assert!(!tested[0].success);
}

#[test]
fn stored_plans_require_exact_marker_and_reject_config_injection() {
    assert!(
        vrl::compiler::compile(BODY, &crate::parsers::validator::safe_vrl_functions()).is_err(),
        "Old builders must reject the marker, never treat it as an identity parser"
    );
    let plan = plan(vec![step(
        "set",
        json!({"field":"foo\"; abort","value":"safe"}),
    )]);
    let source = format!("{HEADER}{}\n{BODY}", serde_json::to_string(&plan).unwrap());
    assert!(stored_plan(&source).unwrap().is_some());
    assert!(stored_plan(&(source + "\nabort")).is_err());
    assert!(condition("true } .a = 1 #").is_err());
    assert!(field("metadata.tenant_uid").is_err());
    for config in [
        json!({"ratio":0}),
        json!({"ratio":1.5}),
        json!({"ratio":1000001}),
    ] {
        assert!(compile_step(&step("sample", config)).is_err());
    }
}

#[test]
fn conditions_use_vrl_raw_literal_rules_and_reject_statements() {
    for value in [
        r"s'ends\\' == .message",
        r"match(string!(.message), r'\\')",
        r#".message == "escaped\";#""#,
        "!(.ok == false)",
    ] {
        assert!(
            condition(value).is_ok(),
            "valid VRL condition rejected: {value}"
        );
    }
    for value in [
        r"s'ends\\'; .changed = true; true",
        "true # hidden",
        "# hidden true",
        "true; false",
        ".x = true",
        "(true; false)",
        "del(.x) != null",
    ] {
        assert!(condition(value).is_err(), "statement accepted: {value}");
    }
}

#[test]
fn deeply_nested_conditions_are_refused_without_overflowing_the_stack() {
    for value in [
        format!("{}true", "!".repeat(4000)),
        format!("{}1{}", "[".repeat(2040), "]".repeat(2040)),
        format!("{}true{}", "(".repeat(2040), ")".repeat(2040)),
        format!("{}1{}", "abs(".repeat(1000), ")".repeat(1000)),
    ] {
        assert!(condition(&value).is_err());
    }
    assert!(condition(&format!("{}true", "!".repeat(32))).is_ok());
}

#[test]
fn input_ids_are_canonical_push_or_pull_uuids() {
    use super::input::{canonical, of_stamp, parse_list, predicate};
    let id = "6f1c0c1e-2b8f-4d7e-9a51-0c5e6c1d2a10";
    assert_eq!(canonical(&format!("push:{}", id.to_uppercase())).unwrap(), format!("push:{id}"));
    assert_eq!(canonical(&format!(" pull:{id} ")).unwrap(), format!("pull:{id}"));
    for bad in [
        format!("feed:{id}"),
        format!("other:{id}"),
        format!("push:{{{id}}}"),
        format!("push:{}", id.replace('-', "")),
        "push:".into(),
        id.to_string(),
        format!("push:{id}\" || true || \""),
    ] {
        assert!(canonical(&bad).is_err(), "{bad}");
    }
    assert_eq!(of_stamp(id), Some(format!("push:{id}")));
    assert_eq!(of_stamp(&format!("pull:{id}")), Some(format!("pull:{id}")));
    assert_eq!(of_stamp("not-a-uuid"), None);
    let inputs = parse_list(&serde_json::json!([format!("push:{id}"), format!("push:{id}"), format!("pull:{id}")])).unwrap();
    assert_eq!(inputs.len(), 2);
    assert_eq!(
        predicate(&inputs),
        format!("(%nano_credential_id == \"{id}\" || %nano_credential_id == \"pull:{id}\")")
    );
    // The compiled predicate is a single read-only expression.
    super::condition(&predicate(&inputs)).unwrap();
    assert!(parse_list(&serde_json::json!([])).is_err());
    assert!(parse_list(&serde_json::json!(vec![format!("push:{id}"); 65])).is_err());
}
