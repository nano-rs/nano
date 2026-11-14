// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5234: a process that never registered a parser-test worker (this test
//! harness, like any binary whose `main` does not dispatch the worker) must
//! not execute tenant VRL in-process. Before NAN-5234 this test's program ran
//! inside the calling process and succeeded.

use nanosiem_core::parsers::VrlValidator;

#[tokio::test]
async fn parser_tests_never_execute_in_an_unregistered_process() {
    let validator = VrlValidator::new();
    // The draft is valid: only execution is refused.
    assert!(validator.validate_vrl(".x = 1").await.unwrap().valid);
    match validator.test_vrl(".x = 1", "{}").await {
        Err(error) => assert!(error.to_string().contains("isolation is unavailable"), "{error}"),
        Ok(result) => panic!("executed in-process: {result:?}"),
    }

    let batch = validator.test_vrl_batch(".x = 1", &["{}".to_string()]).await;
    assert!(batch.is_err(), "executed in-process: {batch:?}");
    let chain = validator.test_vrl_chain(&[".x = 1", ".y = 2"], "{}").await;
    assert!(chain.is_err(), "executed in-process: {chain:?}");
}

/// NAN-5396 (P1): the parser-test path never compiles tenant VRL in the API
/// process. A program that only the COMPILER rejects gets the isolation
/// refusal here, not a compile diagnostic: the compile would have run in the
/// worker, and there is none.
#[tokio::test]
async fn the_test_path_never_compiles_in_the_api_process() {
    let validator = VrlValidator::new();
    let compile_only_error = ".x = no_such_function_nan5396()";
    assert!(!validator.validate_vrl(compile_only_error).await.unwrap().valid);
    match validator.test_vrl(compile_only_error, "{}").await {
        Err(error) => assert!(error.to_string().contains("isolation is unavailable"), "{error}"),
        Ok(result) => panic!("compiled in the API process: {result:?}"),
    }
    let batch = validator.test_vrl_batch(compile_only_error, &["{}".to_string()]).await;
    assert!(batch.is_err(), "compiled in the API process: {batch:?}");
    let chain = validator.test_vrl_chain(&[".x = 1", compile_only_error], "{}").await;
    assert!(chain.is_err(), "compiled in the API process: {chain:?}");
    // The text gates still run here, before any worker: refused, not queued.
    let gated = validator.test_vrl(".x = exec('ls')", "{}").await.unwrap();
    assert!(!gated.success);
    assert!(gated.error.unwrap().contains("forbidden"));
}

/// NAN-5400: `POST /api/log-sources/validate-vrl` (view-only) validates
/// through `validate_vrl_isolated`, which never compiles tenant VRL in the API
/// process. A program only the COMPILER rejects gets the isolation refusal
/// here, not a compile diagnostic; the text gates still answer in-process.
#[tokio::test]
async fn the_validate_endpoint_never_compiles_in_the_api_process() {
    let validator = VrlValidator::new();
    match validator.validate_vrl_isolated(".x = no_such_function_nan5400()").await {
        Err(error) => assert!(error.to_string().contains("isolation is unavailable"), "{error}"),
        Ok(result) => panic!("compiled in the API process: {result:?}"),
    }
    // A valid program is not validated in-process either.
    assert!(validator.validate_vrl_isolated(".x = 1").await.is_err());
    let gated = validator.validate_vrl_isolated(".x = exec('ls')").await.unwrap();
    assert!(!gated.valid);
    assert!(gated.error.unwrap().contains("forbidden"));
}

fn stored_plan(steps: &[(&str, serde_json::Value)]) -> String {
    use nanosiem_core::parsers::pipe::{Plan, Step};
    Plan {
        version: 2,
        revision: 1,
        steps: steps
            .iter()
            .enumerate()
            .map(|(index, (kind, config))| Step {
                id: format!("s{index}"),
                name: kind.to_string(),
                kind: kind.to_string(),
                enabled: true,
                condition: None,
                config: config.as_object().unwrap().clone(),
            })
            .collect(),
    }
    .stored()
    .unwrap()
}

/// NAN-5400 (Codex P1 on #9523): a stored Nano Pipe plan's validation
/// compiles its advanced VRL steps (the metadata-write check compiles each
/// twice). None of that may run in the API process: with no worker, every
/// plan, including one whose advanced VRL writes event metadata (a
/// compiler-derived refusal), gets the isolation refusal, on the validate
/// endpoint and on every test path.
#[tokio::test]
async fn stored_plans_never_compile_in_the_api_process() {
    use serde_json::json;
    let validator = VrlValidator::new();
    let metadata_write = stored_plan(&[("vrl", json!({"code": "%source_type = \"spoofed\""}))]);
    let advanced = stored_plan(&[("vrl", json!({"code": ".parsed = upcase!(.message)"}))]);
    let native = stored_plan(&[
        ("vrl", json!({"code": "%source_type = \"spoofed\""})),
        ("dedupe", json!({"fields": ["message"]})),
    ]);
    // In-process validation (save/deploy) still refuses the metadata write.
    let refused = validator.validate_vrl(&metadata_write).await.unwrap();
    assert!(!refused.valid);
    assert!(refused.error.unwrap().contains("metadata"));

    for source in [&metadata_write, &advanced, &native] {
        let isolated = validator.validate_vrl_isolated(source).await;
        assert!(isolated.is_err(), "validated in the API process: {isolated:?}");
        let single = validator.test_vrl(source, r#"{"message":"x"}"#).await;
        assert!(single.is_err(), "compiled in the API process: {single:?}");
        let batch = validator.test_vrl_batch(source, &[r#"{"message":"x"}"#.to_string()]).await;
        assert!(batch.is_err(), "compiled in the API process: {batch:?}");
        let chain = validator.test_vrl_chain(&[source.as_str(), ".y = 1"], "x").await;
        assert!(chain.is_err(), "compiled in the API process: {chain:?}");
    }
}
