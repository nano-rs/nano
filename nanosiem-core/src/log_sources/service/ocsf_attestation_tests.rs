// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

fn ran(output: serde_json::Value) -> ParserTestResult {
    ParserTestResult {
        input: "x".into(),
        success: true,
        output: Some(output),
        error: None,
        extracted_field_count: 0,
        schema_validation: None,
    }
}

#[test]
fn ocsf_validation_does_not_run_after_vrl_failure() {
    let failed = ParserTestResult {
        input: "x".into(),
        success: false,
        output: None,
        error: Some("abort".into()),
        extracted_field_count: 0,
        schema_validation: None,
    };
    let result = apply_ocsf_validation(failed);
    assert!(result.schema_validation.is_none());
    assert_eq!(result.error.as_deref(), Some("abort"));
}

#[test]
fn invalid_ocsf_output_fails_the_sample_with_structured_paths() {
    let result = apply_ocsf_validation(ran(serde_json::json!({"class_uid": 4002, "bogus": 1})));
    assert!(!result.success);
    let validation = result.schema_validation.expect("OCSF result");
    assert!(validation.errors.iter().any(|e| e.attribute_path == "bogus"));
    assert!(result.error.unwrap().starts_with("OCSF validation failed: "));
}

#[test]
fn valid_ocsf_output_passes_after_vrl_success() {
    let result = apply_ocsf_validation(ran(serde_json::json!({
        "activity_id": 3, "category_uid": 4, "class_uid": 4002, "type_uid": 400203,
        "severity_id": 1, "time": 1786406400000_i64,
        "metadata": {"product": {"name": "nano"}, "version": crate::parsers::ocsf_validation_version()},
        "http_request": {"http_method": "GET", "url": {"path": "/"}}
    })));
    assert!(result.success, "{:?}", result.error);
    assert!(result.schema_validation.unwrap().valid);
}

#[test]
fn sample_receipt_is_framed_and_order_sensitive() {
    let ab = ocsf_samples_sha256(&["a".into(), "b".into()]);
    assert_ne!(ab, ocsf_samples_sha256(&["b".into(), "a".into()]));
    assert_ne!(ab, ocsf_samples_sha256(&["ab".into()]));
    assert_eq!(ab.len(), 64);
}

#[test]
fn parser_receipt_changes_when_enabled_extension_changes() {
    let v = "1.9.0";
    let base = ocsf_parser_sha256(v, ". = {}", false, Some("ignored"));
    assert_eq!(base, ocsf_parser_sha256(v, ". = {}", false, Some("other")), "disabled extension is not part of the generation");
    let on = ocsf_parser_sha256(v, ". = {}", true, Some(".a = 1"));
    assert_ne!(base, on);
    assert_ne!(on, ocsf_parser_sha256(v, ". = {}", true, Some(".a = 2")));
    assert_ne!(base, ocsf_parser_sha256("2.0.0", ". = {}", false, None), "contract version is bound");
}

#[test]
fn sample_limits_are_enforced() {
    assert!(check_sample_limits(&vec!["x".to_string(); OCSF_MAX_SAMPLES]).is_ok());
    assert!(check_sample_limits(&vec!["x".to_string(); OCSF_MAX_SAMPLES + 1]).is_err());
    assert!(check_sample_limits(&["x".repeat(OCSF_MAX_SAMPLE_BYTES + 1)]).is_err());
}

#[test]
fn attestation_status_distinguishes_current_stale_and_none() {
    let at = chrono::Utc::now();
    assert_eq!(attestation_status(None, "1.9.0", "p").status, OcsfAttestationState::None);
    let receipt = |v: &str, p: &str| Some((v.to_string(), p.to_string(), 2, at));
    let current = attestation_status(receipt("1.9.0", "p"), "1.9.0", "p");
    assert_eq!(current.status, OcsfAttestationState::Current);
    assert_eq!(current.sample_count, Some(2));
    assert_eq!(attestation_status(receipt("1.9.0", "q"), "1.9.0", "p").status, OcsfAttestationState::Stale);
    assert_eq!(attestation_status(receipt("1.8.0", "p"), "1.9.0", "p").status, OcsfAttestationState::Stale);
}

/// The gate's two-batch run (one compile per stage) must produce what the
/// interactive per-sample chain does: extension over the parser's output,
/// with stage-indexed errors.
#[tokio::test]
async fn extension_runs_as_one_batch_over_parser_outputs() {
    let validator = crate::parsers::VrlValidator::new();
    let parser = r#"
if .message == "bad" { abort }
.a = 1
.parsed = string!(.message)
"#;
    let extension = r#"
if .parsed == "ext-bad" { .b = to_int!(.parsed) } else { .b = 2 }
"#;
    let samples = vec!["ok".to_string(), "ext-bad".to_string(), "ok2".to_string()];
    let results = run_ocsf_samples(&validator, parser, Some(extension), &samples)
        .await
        .expect("batch run");
    assert_eq!(results.len(), 3);
    for index in [0, 2] {
        let output = results[index].output.as_ref().expect("output");
        assert_eq!(output["a"], 1);
        assert_eq!(output["b"], 2, "extension ran on the parser's output");
        assert_eq!(output["parsed"], samples[index].as_str());
        // Not an OCSF event, so the contract check (not VRL) fails it.
        assert!(results[index].schema_validation.is_some());
    }
    assert!(!results[1].success);
    assert!(
        results[1].error.as_deref().unwrap_or("").starts_with("stage 1:"),
        "{:?}",
        results[1].error
    );

    let chained = run_ocsf_samples(&validator, parser, None, &samples).await.unwrap();
    assert!(chained[0].output.as_ref().unwrap().get("b").is_none());
}

/// NAN-5406: the publish/deploy gate compiles each stage ONCE for the whole
/// sample set, never once per sample: N samples cost one parser compile and
/// one extension compile.
#[tokio::test]
async fn the_gate_compiles_each_stage_once_whatever_the_sample_count() {
    use crate::parsers::test_sandbox::compile_counter;
    let validator = crate::parsers::VrlValidator::new();
    // Unique sources: the counter is keyed by program text and shared by
    // every test in this process.
    let parser = "# nan5406-parser-compile-once\n.parsed = string!(.message)";
    let extension = "# nan5406-extension-compile-once\n.ext = 1";
    let samples: Vec<String> = (0..25).map(|i| format!("sample {i}")).collect();
    let results = run_ocsf_samples(&validator, parser, Some(extension), &samples)
        .await
        .expect("gate run");
    assert_eq!(results.len(), samples.len());
    assert!(results.iter().all(|r| r.output.as_ref().is_some_and(|o| o["ext"] == 1)));
    assert_eq!(compile_counter::count(parser), 1, "one parser compile for {} samples", samples.len());
    assert_eq!(compile_counter::count(extension), 1, "one extension compile");

    let parser_only = "# nan5406-parser-only-compile-once\n.parsed = string!(.message)";
    run_ocsf_samples(&validator, parser_only, None, &samples).await.expect("gate run");
    assert_eq!(compile_counter::count(parser_only), 1);
}
