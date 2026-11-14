// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5396 (P1): on the parser-test path the only compile of tenant VRL is
//! the bounded worker's, and it reports exactly what validation would have:
//! the same diagnostics for a plain program, `stage N: ...` for a chain, and
//! a stored Nano Pipe plan resolved and compiled as its deployed program.

use nanosiem_core::parsers::{test_sandbox::register_worker_executable, VrlValidator};
use std::path::Path;

fn validator() -> VrlValidator {
    register_worker_executable(Path::new(env!("CARGO_BIN_EXE_nanosiem-api")).to_path_buf());
    VrlValidator::new()
}

const COMPILE_ERROR: &str = ".x = no_such_function_nan5396()";

/// The parser-test gate is process-wide: run these serially.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn a_compile_error_reads_as_the_validation_error_it_replaces() {
    let _serial = SERIAL.lock().await;
    let validator = validator();
    let expected = validator.validate_vrl(COMPILE_ERROR).await.unwrap().error.unwrap();

    let single = validator.test_vrl(COMPILE_ERROR, "{}").await.unwrap();
    assert!(!single.success);
    assert_eq!(single.error.as_deref(), Some(expected.as_str()));

    let batch = validator
        .test_vrl_batch(COMPILE_ERROR, &["{}".to_string(), "not json".to_string()])
        .await
        .unwrap();
    for row in &batch {
        assert!(!row.success);
        assert_eq!(row.error.as_deref(), Some(expected.as_str()));
    }

    let chain = validator.test_vrl_chain(&[".a = 1", COMPILE_ERROR], "{}").await.unwrap();
    assert!(!chain.success);
    assert_eq!(chain.error, Some(format!("stage 1: {expected}")));
}

#[tokio::test]
async fn a_valid_program_still_runs_in_the_worker() {
    let _serial = SERIAL.lock().await;
    let validator = validator();
    let result = validator.test_vrl(".parsed = upcase!(.message)", r#"{"message":"hi"}"#).await.unwrap();
    assert!(result.success, "{:?}", result.error);
    assert_eq!(result.output.unwrap()["parsed"], "HI");
}

/// NAN-5400: the validate endpoint's isolated validation, through the real
/// worker, returns exactly what in-process validation returns.
#[tokio::test]
async fn isolated_validation_through_the_worker_matches_validate_vrl() {
    let _serial = SERIAL.lock().await;
    let validator = validator();
    for source in [
        ".parsed = upcase!(.message)",
        ".timestamp = now()\n.message = .message",
        COMPILE_ERROR,
        ".foo = { bar",
        ".foo = exec('ls')",
        "",
    ] {
        assert_eq!(
            validator.validate_vrl_isolated(source).await.unwrap(),
            validator.validate_vrl(source).await.unwrap(),
            "{source}"
        );
    }
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

/// NAN-5400: stored plans are validated in full by the real worker, with the
/// same verdict as in-process validation, stateless and native alike; and a
/// test reports a refused plan with that same error.
#[tokio::test]
async fn stored_plans_validate_in_the_worker_like_validate_vrl() {
    use serde_json::json;
    let _serial = SERIAL.lock().await;
    let validator = validator();
    let stateless_ok = stored_plan(&[("set", json!({"field": "note", "value": "'''"}))]);
    let metadata_write = stored_plan(&[("vrl", json!({"code": "%source_type = \"spoofed\""}))]);
    let off_allowlist = stored_plan(&[("vrl", json!({"code": "log(.message)"}))]);
    let advanced_ok = stored_plan(&[("vrl", json!({"code": ".parsed = upcase!(.message)"}))]);
    let native_ok = stored_plan(&[
        ("vrl", json!({"code": ".parsed = upcase!(.message)"})),
        ("dedupe", json!({"fields": ["message"]})),
    ]);
    let native_bad_route = stored_plan(&[(
        "route",
        json!({"routes": [{"label": "a", "predicate": "get_hostname!() == \"x\""}]}),
    )]);
    let native_metadata_write = stored_plan(&[
        ("vrl", json!({"code": "%source_type = \"spoofed\""})),
        ("dedupe", json!({"fields": ["message"]})),
    ]);
    let edited_body = stateless_ok.replace("nano_pipe_plan_v2()", ".");
    for source in [
        &stateless_ok,
        &metadata_write,
        &off_allowlist,
        &advanced_ok,
        &native_ok,
        &native_bad_route,
        &native_metadata_write,
        &edited_body,
    ] {
        assert_eq!(
            validator.validate_vrl_isolated(source).await.unwrap(),
            validator.validate_vrl(source).await.unwrap(),
            "{source}"
        );
    }

    let input = r#"{"message":"hi"}"#;
    // Stateless: runs, or fails with exactly the validation error.
    let ran = validator.test_vrl(&advanced_ok, input).await.unwrap();
    assert!(ran.success, "{:?}", ran.error);
    assert_eq!(ran.output.unwrap()["parsed"], "HI");
    let refused = validator.test_vrl(&metadata_write, input).await.unwrap();
    assert!(!refused.success);
    assert_eq!(refused.error, validator.validate_vrl(&metadata_write).await.unwrap().error);
    // Native: runs, or every sample fails with the validation error.
    let ran = validator.test_vrl_batch(&native_ok, &[input.to_string()]).await.unwrap();
    assert!(ran[0].success, "{:?}", ran[0].error);
    let refused = validator
        .test_vrl_batch(&native_metadata_write, &[input.to_string(), input.to_string()])
        .await
        .unwrap();
    let expected = validator.validate_vrl(&native_metadata_write).await.unwrap().error;
    assert!(expected.is_some());
    for row in &refused {
        assert!(!row.success);
        assert_eq!(row.error, expected);
    }
}
