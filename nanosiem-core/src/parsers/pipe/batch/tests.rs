// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;
use serde_json::json;
fn plan(kind: &str, config: Value) -> Plan {
    Plan {
        version: 2,
        revision: 1,
        steps: vec![Step {
            id: kind.into(),
            name: kind.into(),
            kind: kind.into(),
            enabled: true,
            condition: None,
            config: config.as_object().unwrap().clone(),
        }],
    }
}
#[test]
fn dedupe_executes_lru_eviction_and_duplicate_refresh() {
    let plan = plan("dedupe", json!({"fields":["message"],"cacheEvents":2}));
    let inputs: Vec<_> = ["a", "b", "a", "c", "b"]
        .into_iter()
        .map(|s| json!({"message":s}))
        .collect();
    let rows = run(&plan, &inputs, None).unwrap();
    assert_eq!(
        rows.iter()
            .flat_map(|row| &row.outputs)
            .map(|out| out["message"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec!["a", "b", "c", "b"]
    );
    assert_eq!(rows[2].disposition, "filtered");
    assert_eq!(rows[2].traces[0].outputs.len(), 0);
}
#[test]
fn dedupe_distinguishes_missing_null_and_value_types() {
    let plan = plan("dedupe", json!({"fields":["key"],"cacheEvents":10}));
    let rows = run(
        &plan,
        &[
            json!({}),
            json!({"key":null}),
            json!({"key":1}),
            json!({"key":"1"}),
            json!({"key":null}),
        ],
        None,
    )
    .unwrap();
    assert_eq!(
        rows.iter().map(|row| row.outputs.len()).collect::<Vec<_>>(),
        vec![1, 1, 1, 1, 0]
    );
}
#[test]
fn reduce_counts_merges_and_preserves_last_event_ocsf_identity() {
    let plan = plan(
        "combine",
        json!({"keys":["host"],"countField":"unmapped.count","maxEvents":2,"timeoutSec":1,"merge":{"bytes":"sum","message":"concat_newline"}}),
    );
    let inputs = [
        json!({"class_uid":4002,"host":"a","bytes":1,"message":"one"}),
        json!({"class_uid":4002,"host":"a","bytes":3,"message":"two"}),
        json!({"class_uid":4002,"host":"b","bytes":9,"message":"other"}),
    ];
    let rows = run(&plan, &inputs, None).unwrap();
    assert_eq!(
        rows[0].outputs[0],
        json!({"class_uid":4002,"host":"a","bytes":4,"message":"one\ntwo","unmapped":{"count":2}})
    );
    assert_eq!(rows[1].disposition, "combined");
    assert!(rows[1].outputs.is_empty());
    assert_eq!(rows[2].outputs[0]["unmapped"]["count"], 1);
}

#[test]
fn reduce_matches_vector_spaces_null_coalescing_and_missing_group_keys() {
    let plan = plan(
        "combine",
        json!({"keys":["host"],"countField":"count","maxEvents":10,"timeoutSec":1,"merge":{"message":"concat","last":"retain","values":"array"}}),
    );
    let inputs = [
        json!({"message":"one","last":"a"}),
        json!({"host":null,"message":"two","last":null,"values":7,"context":"last"}),
    ];
    let rows = run(&plan, &inputs, None).unwrap();
    assert_eq!(
        rows[0].outputs[0],
        json!({"host":null,"message":"one two","last":"a","values":[null,7],"context":"last","count":2})
    );
    assert!(rows[1].outputs.is_empty());
}

#[test]
fn reduce_reports_bad_merge_rows_and_still_combines_valid_members() {
    let plan = plan(
        "combine",
        json!({"keys":["host"],"countField":"count","maxEvents":10,"timeoutSec":1,"merge":{"bytes":"sum"}}),
    );
    let rows = run(
        &plan,
        &[
            json!({"host":"a","bytes":2}),
            json!({"host":"a","bytes":"bad"}),
            json!({"host":"a","bytes":3}),
        ],
        None,
    )
    .unwrap();
    assert_eq!(rows[0].outputs[0]["bytes"], 5);
    assert_eq!(rows[0].outputs[0]["count"], 2);
    assert_eq!(rows[1].disposition, "error");
}

#[test]
fn route_runtime_condition_failures_are_non_matches_and_compile_failures_reject() {
    let mut plan = plan(
        "route",
        json!({"routes":[{"label":"match","predicate":"int!(.missing) == 1"}],"field":"unmapped.branch","fallback":"keep"}),
    );
    let rows = run(&plan, &[json!({"message":"x","unmapped":"old"})], None).unwrap();
    assert_eq!(rows[0].outputs[0]["unmapped"]["branch"], "unmatched");
    assert!(rows[0].error.is_none());
    plan.steps[0].config.insert(
        "routes".into(),
        json!([{"label":"bad","predicate":"undefined_function()"}]),
    );
    // Malformed conditions become actionable event errors, never true branches.
    assert!(run(&plan, &[json!({})], None).unwrap()[0].error.is_some());
}

#[tokio::test]
async fn validator_sample_chain_runs_native_state_and_separate_extensions() {
    let mut plan = plan("dedupe", json!({"fields":["message"],"cacheEvents":10}));
    plan.steps.insert(
        0,
        Step {
            id: "set".into(),
            name: "Set".into(),
            kind: "set".into(),
            enabled: true,
            condition: None,
            config: json!({"field":"added","value":true})
                .as_object()
                .unwrap()
                .clone(),
        },
    );
    let code = plan.stored().unwrap();
    let inputs: Vec<_> = [
        json!({"message":"a"}),
        json!({"message":"a"}),
        json!({"message":"b"}),
    ]
    .iter()
    .map(Value::to_string)
    .collect();
    let results = crate::parsers::validator::VrlValidator::new()
        .test_vrl_chain_batch(&[&code, ".extended = true"], &inputs)
        .await
        .unwrap();
    assert!(results.iter().all(|result| result.success));
    assert_eq!(results[0].output.as_ref().unwrap()["extended"], true);
    assert_eq!(results[1].output, Some(json!([])));
    assert_eq!(results[2].output.as_ref().unwrap()["added"], true);
}

#[test]
fn native_configs_reject_unknown_settings_identity_writes_and_ambiguous_lookups() {
    assert!(plan("dedupe", json!({"fields":["message"],"ttlSec":30}))
        .validate()
        .is_err());
    assert!(plan(
        "combine",
        json!({"keys":["host"],"countField":"metadata.tenant_id"})
    )
    .validate()
    .is_err());
    assert!(plan(
        "route",
        json!({"routes":[{"label":"same","predicate":"true"},{"label":"same","predicate":"false"}]})
    )
    .validate()
    .is_err());
    assert!(plan("lookup", json!({"table":"table","version":"1","match":{"key":"message"},"outputs":{"value":"owner"},"rows":[{"key":"x","value":"a"},{"key":"x","value":"b"}]})).validate().is_err());
}
#[test]
fn route_first_fanout_and_drop_have_single_lake_output_semantics() {
    let cfg = json!({"mode":"fanout","field":"unmapped.branch","routes":[{"label":"one","predicate":"true"},{"label":"two","predicate":"true"}],"fallback":"drop"});
    let mut plan = plan("route", cfg);
    let inputs = [json!({"message":"x"})];
    let rows = run(&plan, &inputs, None).unwrap();
    assert_eq!(rows[0].outputs.len(), 2);
    assert_eq!(rows[0].outputs[1]["unmapped"]["branch"], "two");
    plan.steps[0].config.insert("mode".into(), json!("first"));
    assert_eq!(run(&plan, &inputs, None).unwrap()[0].outputs.len(), 1);
    plan.steps[0].config.insert(
        "routes".into(),
        json!([{"label":"drop","predicate":"true","drop":true}]),
    );
    assert!(run(&plan, &inputs, None).unwrap()[0].outputs.is_empty());
}

#[test]
fn fanout_partial_dedupe_retains_the_input_and_extension_empty_is_a_drop() {
    let mut plan = plan(
        "route",
        json!({"mode":"fanout","routes":[{"label":"one","predicate":"true"},{"label":"two","predicate":"true"}]}),
    );
    plan.steps.push(Step {
        id: "dedupe".into(),
        name: "Dedupe".into(),
        kind: "dedupe".into(),
        enabled: true,
        condition: None,
        config: json!({"fields":["message"],"cacheEvents":10})
            .as_object()
            .unwrap()
            .clone(),
    });
    let rows = run(&plan, &[json!({"message":"a"})], None).unwrap();
    assert_eq!(rows[0].outputs.len(), 1);
    assert_eq!(rows[0].disposition, "retained");
    assert_eq!(rows[0].traces[0].outputs.len(), 2);
    let rows = run(&plan, &[json!({"message":"a"})], Some(". = []")).unwrap();
    assert!(rows[0].outputs.is_empty());
    assert_eq!(rows[0].disposition, "filtered");
}

#[test]
fn cumulative_sampling_does_not_relabel_an_earlier_filter_drop() {
    let mut plan = plan("dedupe", json!({"fields":["message"],"cacheEvents":10}));
    plan.steps.insert(
        0,
        Step {
            id: "sample".into(),
            name: "Sample".into(),
            kind: "sample".into(),
            enabled: true,
            condition: None,
            config: json!({"ratio":1}).as_object().unwrap().clone(),
        },
    );
    plan.steps.insert(
        0,
        Step {
            id: "filter".into(),
            name: "Filter".into(),
            kind: "filter".into(),
            enabled: true,
            condition: None,
            config: json!({"predicate":"true","action":"drop"})
                .as_object()
                .unwrap()
                .clone(),
        },
    );
    let rows = run(&plan, &[json!({"message":"a"})], None).unwrap();
    assert!(rows[0].outputs.is_empty());
    assert_eq!(rows[0].disposition, "filtered");
}
#[test]
fn lookup_matches_owned_snapshot_and_maps_fields_with_explicit_missing_policy() {
    let cfg = json!({"table":"owners","version":"1","rows":[{"key":"hello","value":"alice"}],"match":{"key":"message"},"outputs":{"value":"unmapped.owner"},"missing":"leave"});
    let mut plan = plan("lookup", cfg);
    let inputs = [json!({"message":"hello"}), json!({"message":"absent"})];
    let rows = run(&plan, &inputs, None).unwrap();
    assert_eq!(rows[0].outputs[0]["unmapped"]["owner"], "alice");
    assert_eq!(rows[1].outputs[0], inputs[1]);
    plan.steps[0]
        .config
        .insert("missing".into(), json!("error"));
    assert_eq!(run(&plan, &inputs, None).unwrap()[1].disposition, "error");
    plan.steps[0]
        .config
        .insert("rows".into(), json!([{"key":"1","value":"numeric"}]));
    assert_eq!(
        run(&plan, &[json!({"message":1.0})], None).unwrap()[0].outputs[0]["unmapped"]["owner"],
        "numeric"
    );
}
#[test]
fn native_condition_bypass_and_vrl_variable_scope_match_transform_boundaries() {
    let mut plan = plan("dedupe", json!({"fields":["message"],"cacheEvents":10}));
    plan.steps[0].condition = Some(".enabled == true".into());
    let inputs = [
        json!({"message":"a","enabled":false}),
        json!({"message":"a","enabled":false}),
        json!({"message":"a","enabled":true}),
        json!({"message":"a","enabled":true}),
    ];
    let rows = run(&plan, &inputs, None).unwrap();
    assert_eq!(
        rows.iter().map(|row| row.outputs.len()).collect::<Vec<_>>(),
        vec![1, 1, 1, 0]
    );
    assert!(rows[0].traces[0].bypassed);
}

#[test]
fn combine_flushes_oldest_key_on_cardinality_overflow_without_losing_members() {
    let plan = plan(
        "combine",
        json!({"keys":["key"],"countField":"count","maxEvents":100,"timeoutSec":60}),
    );
    let mut events: Vec<_> = (0..=native::MAX_GROUPS)
        .map(|key| json!({"key":key,"message":"first"}))
        .collect();
    events.push(json!({"key":0,"message":"again"}));
    let rows = run(&plan, &events, None).unwrap();
    assert_eq!(
        rows.iter().map(|row| row.outputs.len()).sum::<usize>(),
        events.len()
    );
    assert!(rows
        .iter()
        .flat_map(|row| &row.outputs)
        .all(|event| event["count"] == 1));
    assert_eq!(rows[0].outputs[0]["message"], "first");
    assert_eq!(rows.last().unwrap().outputs[0]["message"], "again");
}

#[test]
fn legacy_state_limits_are_accepted_but_effective_limits_are_hard_bounded() {
    let dedupe = plan("dedupe", json!({"fields":["message"],"cacheEvents":50000}));
    let Native::Dedupe { capacity, .. } = native::parse(&dedupe.steps[0]).unwrap() else {
        panic!()
    };
    assert_eq!(capacity, native::MAX_DEDUPE_EVENTS);
    let combine = plan("combine", json!({"keys":["key"],"timeoutSec":60}));
    let Native::Combine { timeout, .. } = native::parse(&combine.steps[0]).unwrap() else {
        panic!()
    };
    assert_eq!(timeout, native::MAX_EXPIRE_SEC);
}

#[test]
fn combine_mints_an_aggregate_identity_instead_of_inheriting_a_member_uid() {
    let plan = plan("combine", json!({"keys":["host"],"countField":"count","maxEvents":2,"timeoutSec":1}));
    let rows = run(&plan, &[
        json!({"host":"a","metadata":{"uid":"first-member","product":"sensor"}}),
        json!({"host":"a","metadata":{"uid":"last-member","product":"sensor"}}),
    ], None).unwrap();
    let output = &rows[0].outputs[0];
    assert_eq!(output["count"], 2);
    assert_eq!(output["metadata"]["product"], "sensor");
    assert!(output["metadata"].get("uid").is_none());
}

/// NAN-3625: a lane fed by a push credential and a pull source routes each
/// event by the input it arrived on. The payload's own `metadata` claims are
/// ignored; only the seeded platform identity counts.
#[test]
fn route_by_input_routes_push_and_pull_events_in_preview() {
    const PUSH: &str = "6f1c0c1e-2b8f-4d7e-9a51-0c5e6c1d2a10";
    const PULL: &str = "0b7e4d33-8c2a-4f6e-b1d9-5a3f2e7c9d01";
    let plan = plan(
        "route",
        json!({"mode":"first","field":"unmapped.input_branch","fallback":"keep","routes":[
            {"label":"pushed","inputs":[format!("push:{PUSH}")]},
            {"label":"pulled_errors","inputs":[format!("pull:{PULL}")],"predicate":".level == \"error\""},
            {"label":"pulled_dropped","inputs":[format!("pull:{PULL}")],"drop":true}
        ]}),
    );
    let forged = json!({"nano_credential_id": PUSH, "nano_input": format!("push:{PUSH}")});
    let events = vec![
        json!({"message":"a","metadata":forged}),
        json!({"message":"b","level":"error","metadata":forged}),
        json!({"message":"c","level":"info","metadata":forged}),
        json!({"message":"d","metadata":forged}),
    ];
    let sources = vec![
        Some(format!("push:{PUSH}")),
        Some(format!("pull:{}", PULL.to_ascii_uppercase())),
        Some(format!("pull:{PULL}")),
        None,
    ];
    let rows = run_from(&plan, &events, None, Some(&sources)).unwrap();
    let branch = |i: usize| {
        rows[i]
            .outputs
            .first()
            .map(|out| out["unmapped"]["input_branch"].as_str().unwrap().to_string())
    };
    assert_eq!(branch(0).as_deref(), Some("pushed"));
    assert_eq!(branch(1).as_deref(), Some("pulled_errors"));
    assert_eq!(branch(2), None);
    assert_eq!(rows[2].disposition, "filtered");
    // No input identity: the forged payload claim does not match "pushed".
    assert_eq!(branch(3).as_deref(), Some("unmatched"));
    // Without seeded inputs (saved release samples), nothing matches by input.
    let rows = run(&plan, &events, None).unwrap();
    assert!(rows
        .iter()
        .all(|row| row.outputs[0]["unmapped"]["input_branch"] == "unmatched"));
    assert!(run_from(&plan, &events, None, Some(&sources[..2])).is_err());
    assert!(run_from(&plan, &events[..1], None, Some(&[Some(format!("feed:{PUSH}"))])).is_err());
}

#[test]
fn route_by_input_is_refused_after_combine() {
    let mut plan = plan(
        "route",
        json!({"routes":[{"label":"x","inputs":["push:6f1c0c1e-2b8f-4d7e-9a51-0c5e6c1d2a10"]}]}),
    );
    plan.steps.insert(
        0,
        Step {
            id: "combine".into(),
            name: "Combine".into(),
            kind: "combine".into(),
            enabled: true,
            condition: None,
            config: json!({"keys":["host"]}).as_object().unwrap().clone(),
        },
    );
    assert!(plan.validate().unwrap_err().contains("before a Combine"));
    plan.steps.swap(0, 1);
    plan.validate().unwrap();
}
