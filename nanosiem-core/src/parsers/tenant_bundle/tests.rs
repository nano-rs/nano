// SPDX-License-Identifier: AGPL-3.0-or-later

//! Acceptance tests for the tenant bundle build (NAN-2604) against the real
//! platform base: the source-bound `output-bound` bundle from the platform's
//! `test-fixtures/selected-parser-NAN-2433.js` (sha256 026bd73e…907e), i.e.
//! the bundle hosted-shared cells run today.

use super::archive::{self, BundleTree};
use super::build::{self, BuildInputs, ToolRun, VectorResults};
use super::model::*;
use super::overlay::{self, TenantName};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const BASE: &[u8] = include_bytes!("testdata/platform-base.tar.gz");
const DIGEST: &str = "sha256:ed2134fa8f9844c1ca6405260903c2c2c52f94af9e16bc8fa9de9655134e0b39";
const TENANT: &str = "acme";

/// A tiny OCSF-emitting parser: HTTP Activity from `"<method> <path>"`.
const GOOD_VRL: &str = r#"parts = split(string!(.message), " ")
. = {
  "class_uid": 4002,
  "category_uid": 4,
  "activity_id": 99,
  "time": 1700000000000,
  "http_request": { "http_method": parts[0] ?? "GET", "url": { "path": parts[1] ?? "/" } },
  "message": "acme"
}"#;

fn sha(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn base() -> BundleTree {
    archive::unpack(BASE).expect("fixture base unpacks")
}

fn source(slug: &str, vrl: &str) -> TenantSource {
    TenantSource {
        slug: slug.into(),
        log_source_id: Uuid::from_u128(0x5eed_0000 + slug.len() as u128),
        version_id: 7,
        version_number: 3,
        name: format!("{slug} parser"),
        parser_vrl: vrl.into(),
        extension_vrl: None,
        extension_enabled: false,
        vendor: Some("Acme".into()),
        product: Some("Widget".into()),
        category: None,
        namespace: "default".into(),
        timezone: "UTC".into(),
        sampling_ratio: None,
        sampling_exclude_condition: None,
        forked_from: None,
        samples: vec!["GET /index.html".into()],
    }
}

#[test]
fn pipe_stateless_plan_publishes_real_vrl_and_policy_drop_tests() {
    use crate::parsers::pipe::{Plan, Step, BODY, HEADER};
    let make = |id: &str, kind: &str, config: serde_json::Value| Step {
        id: id.into(),
        name: id.into(),
        kind: kind.into(),
        enabled: true,
        condition: None,
        config: config.as_object().unwrap().clone(),
    };
    let plan = Plan {
        version: 2,
        revision: 1,
        steps: vec![
            make(
                "filter",
                "filter",
                serde_json::json!({"predicate":".message == \"drop\"","action":"drop"}),
            ),
            make("parse", "vrl", serde_json::json!({"code":GOOD_VRL.replace("parts[0] ?? \"GET\"","parts[0]").replace("parts[1] ?? \"/\"","parts[1]")})),
            make(
                "mask",
                "mask",
                serde_json::json!({"fields":["message"],"operation":"replace","replacement":"'''quoted"}),
            ),
        ],
    };
    let stored = format!("{HEADER}{}\n{BODY}", serde_json::to_string(&plan).unwrap());
    let mut source = source("pipe-stateless", &stored);
    source.samples = vec!["drop".into(), "GET /safe".into()];
    assert_eq!(crate::parsers::pipe::evaluate(&plan,&serde_json::json!({"message":"drop","source_type":"pipe-stateless"})).unwrap(),serde_json::json!([]));
    let (candidate, generated) = overlay::apply_overlay(&base(), &[source.clone()]).unwrap();
    overlay::verify_against_base(&base(), &candidate).unwrap();
    let document: toml::Table = candidate
        .text(&generated[0].tenant.file())
        .unwrap()
        .parse()
        .unwrap();
    let program = document["transforms"]["tenant__pipe_stateless_parse"]["source"]
        .as_str()
        .unwrap();
    assert_eq!(program, plan.program().unwrap());
    assert!(!program.contains("nano_pipe_plan_v2()"));
    assert!(program.contains("'''quoted"));
    let tests = super::vector_tests::render(&[(&generated[0], source.samples.as_slice())]).unwrap();
    let tests: toml::Table = tests.parse().unwrap();
    let cases = tests["tests"].as_array().unwrap();
    assert!(cases[0].get("no_outputs_from").is_some());
    assert!(cases[0].get("outputs").is_none());
    assert!(cases[1].get("outputs").is_some());
    if let Ok(image) = std::env::var("NANO_PIPE_VECTOR_TEST_IMAGE") {
        let temp = tempfile::tempdir_in(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../target")).unwrap();
        let parser = candidate.text(&generated[0].tenant.file()).unwrap();
        let fixtures=format!("[sources.events]\ntype=\"stdin\"\n[transforms.source_router]\ntype=\"route\"\ninputs=[\"events\"]\n[transforms.source_router.route]\ntenant__pipe_stateless=\"true\"\n{parser}\n[sinks.test]\ntype=\"blackhole\"\ninputs=[\"tenant__pipe_stateless_output\",\"tenant__pipe_stateless_ocsf_prepare\"]\n{}",super::vector_tests::render(&[(&generated[0],source.samples.as_slice())]).unwrap());
        std::fs::write(temp.path().join("vector.toml"), fixtures).unwrap();
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
}

fn inputs(
    sources: Vec<TenantSource>,
    purpose: BuildPurpose,
    current: Option<Vec<u8>>,
) -> BuildInputs {
    let request = BuildRequest {
        schema_version: 1,
        build_id: "req-1".into(),
        tenant_id: TENANT.into(),
        tenant_uuid: Uuid::from_u128(42),
        purpose,
        runtime_image_digest: DIGEST.into(),
        base_sha256: sha(BASE),
        current_sha256: current.as_deref().map(sha),
        changed_sources: None,
        require_samples: false,
        pull_sources: None,
        pull_lanes: None,
        pull_capture: false,
    };
    BuildInputs {
        build_json: serde_json::to_vec(&request).unwrap(),
        sources_json: serde_json::to_vec(&TenantSources {
            schema_version: 1,
            tenant_id: TENANT.into(),
            sources,
        })
        .unwrap(),
        base: BASE.to_vec(),
        current,
    }
}

fn passing_vector(report: &BuildReport) -> VectorResults {
    let cases: String = report
        .sources
        .iter()
        .flat_map(|s| (0..s.samples).map(move |i| super::vector_tests::case_name(&s.slug, i)))
        .map(|name| format!("test {name} ... passed\n"))
        .collect();
    VectorResults {
        skipped: false,
        egress: Some("blocked".into()),
        version: Some("vector 0.57.0".into()),
        validate: Some(ToolRun {
            exit_code: 0,
            duration_ms: 1,
            output: "Validated".into(),
        }),
        test: Some(ToolRun {
            exit_code: 0,
            duration_ms: 1,
            output: cases,
        }),
        pull_validate: None,
    }
}

// -- overlay shape ----------------------------------------------------------

#[test]
fn empty_overlay_is_exactly_the_base() {
    let (candidate, generated) = overlay::apply_overlay(&base(), &[]).unwrap();
    assert!(generated.is_empty());
    assert_eq!(candidate, base());
    let verified = overlay::verify_against_base(&base(), &candidate).unwrap();
    assert!(verified.tenants.is_empty());
    assert_eq!(
        verified.hec_sources,
        [
            "apache_access",
            "aws_cloudtrail",
            "conduit_proxy",
            "otlp_log",
            "windows_event",
            "windows_sysmon"
        ]
    );
}

#[test]
fn overlay_adds_one_parser_file_and_only_wiring_items() {
    let (candidate, generated) =
        overlay::apply_overlay(&base(), &[source("acme-fw", GOOD_VRL)]).unwrap();
    let tenant = &generated[0].tenant;
    assert_eq!(tenant.name, "tenant__acme_fw");
    assert_eq!(tenant.file(), "sources/parsers/tenant__acme_fw.toml");
    let changed = super::diff::changed_paths(&base(), &candidate);
    assert_eq!(
        changed,
        [
            overlay::HEC_FILE,
            overlay::COMBINER_FILE,
            overlay::LAKE_SINK_FILE,
            overlay::ROUTER_FILE,
            "sources/parsers/tenant__acme_fw.toml",
        ]
    );
    let hec = candidate.text(overlay::HEC_FILE).unwrap();
    assert!(hec.contains("\"${VECTOR_AUTH_TOKEN}:nano-source-v1:acme-fw\", \"${VECTOR_AUTH_TOKEN}:nano-source-v1:apache_access\""), "sorted merge: {hec}");
    assert!(
        hec.contains("if !includes([\"acme-fw\", \"apache_access\""),
        "{hec}"
    );
    let router = candidate.text(overlay::ROUTER_FILE).unwrap();
    assert!(
        router.contains("tenant__acme_fw = '.source_type == \"acme-fw\"'\ngeneric = '!includes(")
    );
    assert!(router.contains("\"windows_event\", \"acme-fw\"], .source_type)"));
    let combiner = candidate.text(overlay::COMBINER_FILE).unwrap();
    assert!(combiner.contains("\"windows_event_log__ocsf__output\", \"tenant__acme_fw_output\"]"));
    assert!(combiner.contains("\"windows_event_log__ocsf__ocsf_prepare\", \"tenant__acme_fw_output\", \"tenant__acme_fw_ocsf_prepare\"]"));
    let sink = candidate.text(overlay::LAKE_SINK_FILE).unwrap();
    assert!(sink.contains("\"generic_ocsf_prepare\", \"tenant__acme_fw_ocsf_prepare\"]"));

    let verified = overlay::verify_against_base(&base(), &candidate).unwrap();
    assert_eq!(verified.tenants, [TenantName::new("acme-fw", false)]);
    assert!(verified.hec_sources.contains(&"acme-fw".to_string()));
    assert_eq!(
        verified.hec_config_sha256,
        sha(candidate.file(overlay::HEC_FILE).unwrap())
    );
    let (platform, _) = overlay::strip_overlay(&candidate).unwrap();
    assert_eq!(
        platform.files,
        base().files,
        "stripping the overlay must give the base back byte for byte"
    );
}

#[test]
fn every_tenant_remap_reroutes_runtime_errors_and_pins_its_label() {
    let mut s = source("acme", GOOD_VRL);
    s.extension_vrl = Some(".ext.team = \"soc\"".into());
    s.extension_enabled = true;
    let (candidate, _) = overlay::apply_overlay(&base(), &[s]).unwrap();
    let text = candidate.text("sources/parsers/tenant__acme.toml").unwrap();
    let table: toml::Table = text.parse().unwrap();
    let transforms = table["transforms"].as_table().unwrap();
    for name in ["tenant__acme_parse", "tenant__acme_extension"] {
        let t = transforms[name].as_table().unwrap();
        assert_eq!(t["drop_on_error"], toml::Value::Boolean(true), "{name}");
        assert_eq!(t["reroute_dropped"], toml::Value::Boolean(true), "{name}");
    }
    let output = transforms["tenant__acme_output"].as_table().unwrap();
    let inputs: Vec<&str> = output["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(
        inputs.contains(&"tenant__acme_parse.dropped")
            && inputs.contains(&"tenant__acme_extension.dropped")
    );
    let source = output["source"].as_str().unwrap();
    assert!(source.contains("st_val = \"acme\""), "{source}");
    assert!(
        !source.contains("st_val = .source_type"),
        "tenant VRL must not choose its storage label"
    );
    assert!(
        !text.contains("Generated at: 20"),
        "no clock in a content-addressed file"
    );
}

#[test]
fn same_inputs_give_byte_identical_output() {
    let run = || {
        build::generate(&inputs(
            vec![source("acme", GOOD_VRL), source("beta", GOOD_VRL)],
            BuildPurpose::Rollout,
            None,
        ))
    };
    let (a, b) = (run(), run());
    assert!(a.ok(), "{:?}", a.report.failure);
    assert_eq!(a.bundle, b.bundle);
    assert_eq!(a.tests_toml, b.tests_toml);
    let bundle = a.report.bundle.as_ref().unwrap();
    assert_eq!(bundle.content_sha256, sha(a.bundle.as_ref().unwrap()));
    assert_eq!(
        bundle.object_key,
        format!(
            "tenants/{}/parser-bundles/{}.tar.gz",
            Uuid::from_u128(42),
            bundle.content_sha256
        ),
        "the UUID form the renderer derives and 9001660 records, never the slug"
    );
    // Source order in the request does not matter.
    let reordered = build::generate(&inputs(
        vec![source("beta", GOOD_VRL), source("acme", GOOD_VRL)],
        BuildPurpose::Rollout,
        None,
    ));
    assert_eq!(reordered.bundle, a.bundle);
}

// -- structural guard ---------------------------------------------------------

fn candidate() -> BundleTree {
    overlay::apply_overlay(&base(), &[source("acme", GOOD_VRL)])
        .unwrap()
        .0
}

fn rules(result: Result<overlay::VerifiedOverlay, Vec<GuardFinding>>) -> Vec<String> {
    result
        .expect_err("guard must refuse")
        .into_iter()
        .map(|f| f.rule)
        .collect()
}

#[test]
fn an_overlay_that_touches_a_platform_file_is_rejected() {
    for path in [
        "sources/parsers/_pipeline.toml",
        "07-output-guards.toml",
        "sources/parsers/apache_http_server__ocsf_.toml",
        "backup/_router.toml",
    ] {
        let mut tampered = candidate();
        let mut data = tampered.files[path].clone();
        data.extend_from_slice(b"\n# tenant edit\n");
        tampered.put(path, data);
        let result = overlay::verify_against_base(&base(), &tampered);
        let findings = result.expect_err(path);
        assert!(
            findings
                .iter()
                .any(|f| f.rule == "platform_identical" && f.path.as_deref() == Some(path)),
            "{path}: {findings:?}"
        );
    }
    // A platform byte inside a wiring file (not a tenant item) is caught too.
    let mut tampered = candidate();
    let sink = tampered
        .text(overlay::LAKE_SINK_FILE)
        .unwrap()
        .replace("if tenant_id == \"\" { abort }", "");
    tampered.put(overlay::LAKE_SINK_FILE, sink.into_bytes());
    assert!(rules(overlay::verify_against_base(&base(), &tampered))
        .contains(&"platform_identical".to_string()));
    // An extra non-tenant item in a wiring list.
    let mut tampered = candidate();
    let sink = tampered.text(overlay::LAKE_SINK_FILE).unwrap().replace(
        "\"tenant__acme_ocsf_prepare\"]",
        "\"tenant__acme_ocsf_prepare\", \"evil\"]",
    );
    tampered.put(overlay::LAKE_SINK_FILE, sink.into_bytes());
    assert!(overlay::verify_against_base(&base(), &tampered).is_err());
    // Removing a platform file.
    let mut tampered = candidate();
    tampered.files.remove("92-metrics.toml");
    assert!(rules(overlay::verify_against_base(&base(), &tampered))
        .contains(&"platform_identical".to_string()));
    // A new file that is not a tenant parser file.
    let mut tampered = candidate();
    tampered.put(
        "sources/parsers/zz_extra.toml",
        b"[sinks.x]\ntype = \"blackhole\"\ninputs = [\"tenant__acme_output\"]\n".to_vec(),
    );
    assert!(rules(overlay::verify_against_base(&base(), &tampered))
        .contains(&"overlay_scope".to_string()));
}

#[test]
fn tenant_files_may_only_hold_their_own_transforms() {
    let file = "sources/parsers/tenant__acme.toml";
    let append = |extra: &str| {
        let mut t = candidate();
        let mut text = t.text(file).unwrap().to_string();
        text.push_str(extra);
        t.put(file, text.into_bytes());
        rules(overlay::verify_against_base(&base(), &t))
    };
    assert!(append("\n[sinks.tenant__acme_exfil]\ntype = \"http\"\ninputs = [\"tenant__acme_output\"]\nuri = \"http://x\"\n").contains(&"component_kind".to_string()));
    assert!(append("\n[transforms.windows_sniffer]\ntype = \"remap\"\ninputs = [\"source_router.windows_event_log__ocsf_\"]\nsource = '.'\n").contains(&"namespace".to_string()));
    assert!(append("\n[transforms.tenant__acme_extension]\ntype = \"remap\"\ninputs = [\"source_router.windows_event_log__ocsf_\"]\nsource = '.'\n").contains(&"inputs".to_string()));
    // A global option must be top-level; appended it would land inside the
    // last transform (which Vector itself rejects), so prepend it.
    let mut t = candidate();
    let text = format!("data_dir = \"/tmp\"\n{}", t.text(file).unwrap());
    t.put(file, text.into_bytes());
    assert!(
        rules(overlay::verify_against_base(&base(), &t)).contains(&"component_kind".to_string())
    );
    // Turning off the runtime safety net.
    let mut t = candidate();
    let text =
        t.text(file)
            .unwrap()
            .replacen("reroute_dropped = true", "reroute_dropped = false", 1);
    t.put(file, text.into_bytes());
    assert!(
        rules(overlay::verify_against_base(&base(), &t)).contains(&"runtime_safety".to_string())
    );
}

#[test]
fn blocked_functions_metadata_writes_and_platform_slugs_fail_the_build() {
    let run =
        |s: TenantSource| build::generate(&inputs(vec![s], BuildPurpose::Rollout, None)).report;

    let report = run(source(
        "acme",
        ".secret = get_env_var!(\"NANO_LAKE_SECRET_ACCESS_KEY\")",
    ));
    let failure = report.failure.unwrap();
    assert_eq!(failure.stage, Stage::StructuralGuard);
    assert_eq!(failure.source.as_deref(), Some("acme"));
    assert!(
        failure.message.contains("get_env_var"),
        "{}",
        failure.message
    );
    assert!(report.bundle.is_none());

    let report = run(source("acme", "%tenant_id = \"another-tenant\"\n.x = 1"));
    assert!(
        report.checks[0]
            .findings
            .iter()
            .any(|f| f.rule == "metadata_write"),
        "{:?}",
        report.checks
    );

    let report = run(source("acme", ".tok = get_secret(\"splunk_hec_token\")"));
    assert_eq!(report.failure.unwrap().stage, Stage::StructuralGuard);

    let report = run(source("apache_access", GOOD_VRL));
    let failure = report.failure.unwrap();
    assert_eq!(failure.stage, Stage::Overlay);
    assert!(failure.message.contains("merge the platform update"), "{}", failure.message);
    assert!(!failure.message.contains("platform source") && !failure.message.contains("fork"), "{}", failure.message);
}

#[test]
fn tenant_text_cannot_reach_environment_interpolation() {
    let (candidate, _) = overlay::apply_overlay(
        &base(),
        &[source(
            "acme",
            ".k = \"${NANO_LAKE_SECRET_ACCESS_KEY}\" + \"$HOME\"",
        )],
    )
    .unwrap();
    let text = candidate.text("sources/parsers/tenant__acme.toml").unwrap();
    assert!(
        text.contains("\"$${NANO_LAKE_SECRET_ACCESS_KEY}\" + \"$$HOME\""),
        "{text}"
    );
    overlay::verify_against_base(&base(), &candidate).unwrap();
    let env = build::placeholder_env(&candidate);
    assert!(
        !env.iter().any(|(name, _)| name == "HOME"),
        "escaped tenant text must not become a variable"
    );
    assert!(
        env.iter()
            .any(|(name, _)| name == "NANO_LAKE_SECRET_ACCESS_KEY"),
        "the platform sink's own variable still gets a placeholder"
    );
    assert!(env
        .iter()
        .all(|(_, value)| value.starts_with("unused-") || value == "http://127.0.0.1:9"));
    // An unescaped `$` smuggled into a tenant file is refused.
    let mut t = candidate.clone();
    let raw = text.replace("$${NANO", "${NANO");
    t.put("sources/parsers/tenant__acme.toml", raw.into_bytes());
    assert!(rules(overlay::verify_against_base(&base(), &t)).contains(&"interpolation".to_string()));
}

// -- finalize -------------------------------------------------------------------

#[test]
fn finalize_passes_only_with_clean_validate_test_and_sandbox() {
    let outcome = build::generate(&inputs(
        vec![source("acme", GOOD_VRL)],
        BuildPurpose::Rollout,
        None,
    ));
    assert!(outcome.ok());
    let bundle = outcome.bundle.clone().unwrap();
    let pass = build::finalize_report(
        outcome.report.clone(),
        &passing_vector(&outcome.report),
        Some(&bundle),
        Some(DIGEST),
    );
    assert_eq!(pass.verdict, Verdict::Passed, "{:?}", pass.failure);
    assert!(pass.bundle.is_some());
    let names: Vec<&str> = pass.checks.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "structural_guard",
            "sandbox_egress",
            "vector_validate",
            "vector_test"
        ]
    );

    // Vector rejects what VrlValidator accepted: the Vector error is the message.
    let mut rejected = passing_vector(&outcome.report);
    rejected.validate = Some(ToolRun {
        exit_code: 78,
        duration_ms: 5,
        output: "x Transform \"tenant__acme_parse\":\nerror[E103]: unhandled fallible assignment\n"
            .into(),
    });
    let fail = build::finalize_report(
        outcome.report.clone(),
        &rejected,
        Some(&bundle),
        Some(DIGEST),
    );
    let failure = fail.failure.clone().unwrap();
    assert_eq!(failure.stage, Stage::VectorValidate);
    assert_eq!(failure.source.as_deref(), Some("acme"));
    assert_eq!(failure.component.as_deref(), Some("tenant__acme_parse"));
    assert!(failure.message.contains("E103"));
    assert!(fail.bundle.is_none(), "a failed build emits no artifact");

    // A sample that did not come out as OCSF.
    let mut test_failed = passing_vector(&outcome.report);
    test_failed.test = Some(ToolRun {
        exit_code: 1,
        duration_ms: 3,
        output: "test tenant acme sample 1 ... failed\n".into(),
    });
    let fail = build::finalize_report(
        outcome.report.clone(),
        &test_failed,
        Some(&bundle),
        Some(DIGEST),
    );
    assert_eq!(fail.failure.unwrap().stage, Stage::VectorTest);

    // An open network voids the build.
    let mut open = passing_vector(&outcome.report);
    open.egress = Some("open:1.1.1.1:443".into());
    let fail = build::finalize_report(outcome.report.clone(), &open, Some(&bundle), Some(DIGEST));
    assert_eq!(fail.failure.unwrap().stage, Stage::Sandbox);

    // The Vector stage must have run in the image build.json names.
    let other = format!("sha256:{}", "0".repeat(64));
    let fail = build::finalize_report(
        outcome.report.clone(),
        &passing_vector(&outcome.report),
        Some(&bundle),
        Some(&other),
    );
    assert_eq!(fail.failure.unwrap().stage, Stage::Inputs);

    // The artifact cannot change between stages.
    let fail = build::finalize_report(
        outcome.report.clone(),
        &passing_vector(&outcome.report),
        Some(b"other"),
        Some(DIGEST),
    );
    assert_eq!(fail.failure.unwrap().stage, Stage::Package);
}

// -- sandbox egress: the k8s_api_unauthenticated exception (NAN-2987) ----------

const K8S_API: &str = "10.21.0.40:443";

/// The sandbox probe of a pod that reaches only an unauthenticated API.
fn k8s_probe(anonymous_api: Option<Result<u16, String>>) -> build::SandboxProbe {
    build::SandboxProbe {
        k8s_api: Some(K8S_API.into()),
        stage_token_present: Some(false),
        finalize_token_present: false,
        anonymous_api,
    }
}

fn sandbox_check(report: &BuildReport) -> &Check {
    report.checks.iter().find(|c| c.name == "sandbox_egress").unwrap()
}

/// Finalize a clean build whose Vector stage recorded `egress`, under `probe`.
fn finalize_with(egress: &str, probe: &build::SandboxProbe) -> BuildReport {
    let outcome = build::generate(&inputs(
        vec![source("acme", GOOD_VRL)],
        BuildPurpose::Rollout,
        None,
    ));
    assert!(outcome.ok());
    let bundle = outcome.bundle.clone().unwrap();
    let mut results = passing_vector(&outcome.report);
    results.egress = Some(egress.into());
    build::finalize_report_with_sandbox(outcome.report, &results, probe, Some(&bundle), Some(DIGEST))
}

#[test]
fn sandbox_passes_with_exception_only_for_an_unauthenticated_k8s_api() {
    for status in [401, 403] {
        let report = finalize_with(&format!("open:{K8S_API}"), &k8s_probe(Some(Ok(status))));
        assert_eq!(report.verdict, Verdict::Passed, "{status}: {:?}", report.failure);
        let sandbox = sandbox_check(&report);
        // the platform's verifier parses passed|failed|skipped and requires passed:
        // the exception is a named field beside it, never a new status.
        assert_eq!(sandbox.status, CheckStatus::Passed);
        assert_eq!(sandbox.exception.as_deref(), Some("k8s_api_unauthenticated"));
        assert_eq!(sandbox.output.as_deref(), Some("open:10.21.0.40:443"));
        let json = serde_json::to_value(sandbox).unwrap();
        assert_eq!(json["status"], "passed");
        assert_eq!(json["exception"], "k8s_api_unauthenticated");
        assert_eq!(json["output"], "open:10.21.0.40:443");
    }
}

#[test]
fn sandbox_fully_blocked_passes_without_an_exception() {
    // Even with the API known, a blocked network is a plain pass.
    for probe in [build::SandboxProbe::default(), k8s_probe(None)] {
        let report = finalize_with("blocked", &probe);
        assert_eq!(report.verdict, Verdict::Passed, "{:?}", report.failure);
        let sandbox = sandbox_check(&report);
        assert_eq!(sandbox.status, CheckStatus::Passed);
        assert_eq!(sandbox.exception, None);
        assert_eq!(sandbox.output, None);
        let json = serde_json::to_value(sandbox).unwrap();
        assert!(json.get("exception").is_none(), "{json}");
    }
}

#[test]
fn sandbox_fails_when_the_k8s_api_is_not_the_only_open_target() {
    let egress = format!("open:1.1.1.1:443\nopen:{K8S_API}");
    let report = finalize_with(&egress, &k8s_probe(Some(Ok(403))));
    assert_eq!(report.verdict, Verdict::Failed);
    let failure = report.failure.clone().unwrap();
    assert_eq!(failure.stage, Stage::Sandbox);
    assert!(failure.message.contains("open:1.1.1.1:443"), "{}", failure.message);
    let sandbox = sandbox_check(&report);
    assert_eq!(sandbox.status, CheckStatus::Failed);
    assert_eq!(sandbox.exception, None);
    assert_eq!(sandbox.output.as_deref(), Some("open:1.1.1.1:443, open:10.21.0.40:443"));
    assert!(report.bundle.is_none());

    // Some other single target is not the API, whatever the probe says.
    let report = finalize_with("open:8.8.8.8:53", &k8s_probe(Some(Ok(403))));
    assert_eq!(report.failure.unwrap().stage, Stage::Sandbox);

    // The API on another port is another target.
    let report = finalize_with("open:10.21.0.40:6443", &k8s_probe(Some(Ok(403))));
    assert_eq!(report.failure.unwrap().stage, Stage::Sandbox);

    // No API known to finalize (the default probe): the API target fails as before.
    let report = finalize_with(&format!("open:{K8S_API}"), &build::SandboxProbe::default());
    assert_eq!(sandbox_check(&report).status, CheckStatus::Failed);
    assert!(report.failure.unwrap().message.contains("network egress"));
}

#[test]
fn sandbox_fails_when_a_service_account_token_is_mounted() {
    let egress = format!("open:{K8S_API}");
    for (stage, finalize) in [(Some(true), false), (Some(false), true), (Some(true), true)] {
        let mut probe = k8s_probe(Some(Ok(403)));
        probe.stage_token_present = stage;
        probe.finalize_token_present = finalize;
        let report = finalize_with(&egress, &probe);
        assert_eq!(report.verdict, Verdict::Failed, "{stage:?}/{finalize}");
        let failure = report.failure.clone().unwrap();
        assert_eq!(failure.stage, Stage::Sandbox);
        assert!(failure.message.contains("service-account token"), "{}", failure.message);
        assert_eq!(sandbox_check(&report).status, CheckStatus::Failed);
        assert_eq!(sandbox_check(&report).exception, None);
    }
    // A Vector stage that did not record its token mount proves nothing.
    let mut probe = k8s_probe(Some(Ok(403)));
    probe.stage_token_present = None;
    let report = finalize_with(&egress, &probe);
    assert!(report.failure.unwrap().message.contains("not recorded"));
}

#[test]
fn sandbox_fails_when_anonymous_api_is_not_refused() {
    let egress = format!("open:{K8S_API}");
    for (anonymous, needle) in [
        (Some(Ok(200)), "returned 200"),
        (Some(Ok(204)), "returned 204"),
        (Some(Ok(302)), "returned 302"),
        (Some(Ok(500)), "returned 500"),
        (Some(Err("connection reset".to_string())), "could not be verified"),
        (None, "was not probed"),
    ] {
        let report = finalize_with(&egress, &k8s_probe(anonymous.clone()));
        assert_eq!(report.verdict, Verdict::Failed, "{anonymous:?}");
        let failure = report.failure.clone().unwrap();
        assert_eq!(failure.stage, Stage::Sandbox);
        assert!(failure.message.contains(needle), "{anonymous:?}: {}", failure.message);
        let sandbox = sandbox_check(&report);
        assert_eq!(sandbox.status, CheckStatus::Failed);
        assert_eq!(sandbox.exception, None);
        assert_eq!(sandbox.output.as_deref(), Some("open:10.21.0.40:443"));
    }
}

/// The exception never replaces an earlier root cause, and a sandbox failure
/// fails the build even when everything else passed.
#[test]
fn sandbox_exception_keeps_an_earlier_failure() {
    let outcome = build::generate(&inputs(
        vec![source("acme", GOOD_VRL)],
        BuildPurpose::Rollout,
        None,
    ));
    let results = VectorResults {
        egress: Some(format!("open:{K8S_API}")),
        ..passing_vector(&outcome.report)
    };
    // The bundle changed between stages: Package fails, the sandbox still passes.
    let report = build::finalize_report_with_sandbox(
        outcome.report.clone(),
        &results,
        &k8s_probe(Some(Ok(403))),
        Some(b"other"),
        Some(DIGEST),
    );
    assert_eq!(report.failure.as_ref().unwrap().stage, Stage::Package);
    assert_eq!(sandbox_check(&report).status, CheckStatus::Passed);
}

#[test]
fn sandbox_probe_gathers_env_tokens_and_the_anonymous_request() {
    let dir = tempfile::tempdir().unwrap();
    let env = |name: &str| match name {
        "KUBERNETES_SERVICE_HOST" => Some("10.21.0.40".to_string()),
        "KUBERNETES_SERVICE_PORT" => Some("443".to_string()),
        _ => None,
    };
    std::fs::write(dir.path().join(build::SA_TOKEN_FILE), "absent\n").unwrap();

    // Only the API open: the anonymous request is made against /api.
    let mut asked = None;
    let probe = build::SandboxProbe::gather(dir.path(), Some("open:10.21.0.40:443"), env, false, |url| {
        asked = Some(url.to_string());
        Ok(403)
    });
    assert_eq!(asked.as_deref(), Some("https://10.21.0.40:443/api"));
    assert_eq!(probe.k8s_api.as_deref(), Some(K8S_API));
    assert_eq!(probe.stage_token_present, Some(false));
    assert_eq!(probe.anonymous_api, Some(Ok(403)));

    // Blocked, or another target open too: no request at all.
    for egress in ["blocked", "open:1.1.1.1:443\nopen:10.21.0.40:443"] {
        let probe = build::SandboxProbe::gather(dir.path(), Some(egress), env, false, |_| {
            panic!("no anonymous request when the API is not the only open target")
        });
        assert_eq!(probe.anonymous_api, None);
    }

    // Token recorded present; port defaults to 443; IPv6 hosts are bracketed.
    std::fs::write(dir.path().join(build::SA_TOKEN_FILE), "present\n").unwrap();
    let env6 = |name: &str| (name == "KUBERNETES_SERVICE_HOST").then(|| "fd00::1".to_string());
    let mut asked = None;
    let probe = build::SandboxProbe::gather(dir.path(), Some("open:fd00::1:443"), env6, true, |url| {
        asked = Some(url.to_string());
        Ok(401)
    });
    assert_eq!(asked.as_deref(), Some("https://[fd00::1]:443/api"));
    assert_eq!(probe.stage_token_present, Some(true));
    assert!(probe.finalize_token_present);

    // No API in the environment: nothing to tolerate.
    let probe = build::SandboxProbe::gather(dir.path(), Some("open:10.21.0.40:443"), |_| None, false, |_| {
        panic!("no API known")
    });
    assert_eq!(probe.k8s_api, None);
}

/// The anonymous request against a fake API: status codes come through
/// as-is, no credentials are sent and redirects are not followed.
#[test]
fn anonymous_api_status_reads_the_fake_apis_status() {
    use std::io::{BufRead, BufReader, Write};
    for (status, reason) in [(403, "Forbidden"), (401, "Unauthorized"), (200, "OK"), (302, "Found")] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut head = Vec::new();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
                head.push(line.to_ascii_lowercase());
            }
            let mut stream = stream;
            write!(
                stream,
                "HTTP/1.1 {status} {reason}\r\nlocation: http://127.0.0.1:9/\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
            )
            .unwrap();
            head
        });
        let got = build::anonymous_api_status(&format!("http://{addr}/api")).unwrap();
        assert_eq!(got, status);
        let head = server.join().unwrap();
        assert!(head[0].starts_with("get /api "), "{head:?}");
        assert!(!head.iter().any(|h| h.starts_with("authorization")), "{head:?}");
    }
    // Nothing listening: an error, never a status.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    assert!(build::anonymous_api_status(&format!("http://{addr}/api")).is_err());
}

/// NAN-2969: a generate failure (a platform slug the overlay refuses) must
/// survive finalize. The sandbox probe, a skipped Vector stage and missing
/// results all fire later, and none of them may replace the root cause.
#[test]
fn finalize_keeps_the_first_failure() {
    let outcome = build::generate(&inputs(
        vec![source("apache_access", GOOD_VRL)],
        BuildPurpose::Rollout,
        None,
    ));
    let generate_failure = outcome.report.failure.clone().expect("generate fails");
    assert_eq!(generate_failure.stage, Stage::Overlay);
    assert!(generate_failure.message.contains("merge the platform update"));

    // Generate failed + the sandbox had egress + the Vector stage skipped.
    let results = VectorResults {
        skipped: true,
        egress: Some("open:1.1.1.1:443".into()),
        version: None,
        validate: None,
        test: None,
        pull_validate: None,
    };
    let report = build::finalize_report(outcome.report.clone(), &results, None, Some(DIGEST));
    assert_eq!(report.verdict, Verdict::Failed);
    assert_eq!(report.failure.as_ref(), Some(&generate_failure));
    // The sandbox check still records the open network on its own.
    let sandbox = report
        .checks
        .iter()
        .find(|c| c.name == "sandbox_egress")
        .unwrap();
    assert_eq!(sandbox.status, CheckStatus::Failed);

    // Same with a Vector stage that ran and failed everything.
    let mut failing = passing_vector(&outcome.report);
    failing.egress = Some("open:1.1.1.1:443".into());
    failing.validate = Some(ToolRun {
        exit_code: 78,
        duration_ms: 1,
        output: "error: boom".into(),
    });
    let report = build::finalize_report(
        outcome.report.clone(),
        &failing,
        None,
        Some(&format!("sha256:{}", "0".repeat(64))),
    );
    assert_eq!(report.failure.as_ref(), Some(&generate_failure));

    // A finalize-time failure is kept over the sandbox too.
    let ok = build::generate(&inputs(
        vec![source("acme", GOOD_VRL)],
        BuildPurpose::Rollout,
        None,
    ));
    let mut open = passing_vector(&ok.report);
    open.egress = Some("open:1.1.1.1:443".into());
    let report = build::finalize_report(ok.report.clone(), &open, Some(b"other"), Some(DIGEST));
    assert_eq!(report.failure.unwrap().stage, Stage::Package);
}

/// NAN-2650: staging pinned the detection-jobs image as the cell runtime.
/// A runtime image with no `vector` binary must fail the build with that
/// reason, never pass on whatever the missing binary's exit codes look like.
#[test]
fn finalize_refuses_a_runtime_image_without_a_vector_binary() {
    let outcome = build::generate(&inputs(
        vec![source("acme", GOOD_VRL)],
        BuildPurpose::Rollout,
        None,
    ));
    let bundle = outcome.bundle.clone().unwrap();
    for version in [
        None,
        Some("/opt/nano/vector-check.sh: line 38: /usr/bin/vector: No such file or directory"),
        Some(""),
        Some("nanosiem-jobs 0.1.703"),
    ] {
        let mut results = passing_vector(&outcome.report);
        results.version = version.map(str::to_string);
        let report =
            build::finalize_report(outcome.report.clone(), &results, Some(&bundle), Some(DIGEST));
        assert_eq!(report.verdict, Verdict::Failed, "{version:?}");
        let failure = report.failure.unwrap();
        assert_eq!(failure.stage, Stage::Inputs, "{version:?}");
        assert!(
            failure.message.contains("has no `vector` binary"),
            "{version:?}: {}",
            failure.message
        );
        assert!(report.bundle.is_none());
    }
    for version in [
        "vector 0.57.0",
        "vector 0.57.0 (x86_64-unknown-linux-gnu 8e3d1d6 2026-08-12 10:10:10.000000000)",
    ] {
        let mut results = passing_vector(&outcome.report);
        results.version = Some(version.into());
        let report =
            build::finalize_report(outcome.report.clone(), &results, Some(&bundle), Some(DIGEST));
        assert_eq!(report.verdict, Verdict::Passed, "{version}: {:?}", report.failure);
    }
}

#[test]
fn inputs_are_bound_to_one_tenant_and_the_declared_base() {
    let mut i = inputs(vec![source("acme", GOOD_VRL)], BuildPurpose::Rollout, None);
    let mut doc: serde_json::Value = serde_json::from_slice(&i.sources_json).unwrap();
    doc["tenant_id"] = "other-tenant".into();
    i.sources_json = serde_json::to_vec(&doc).unwrap();
    let failure = build::generate(&i).report.failure.unwrap();
    assert_eq!(failure.stage, Stage::Inputs);
    assert!(failure.message.contains("different tenant"));

    let mut i = inputs(vec![], BuildPurpose::Rollout, None);
    i.base.push(0);
    assert!(build::generate(&i)
        .report
        .failure
        .unwrap()
        .message
        .contains("base_sha256"));

    let mut i = inputs(vec![], BuildPurpose::Rollout, None);
    let mut doc: serde_json::Value = serde_json::from_slice(&i.build_json).unwrap();
    doc["surprise"] = true.into();
    i.build_json = serde_json::to_vec(&doc).unwrap();
    assert_eq!(
        build::generate(&i).report.failure.unwrap().stage,
        Stage::Inputs
    );
}

// -- decision (a): merge candidate ------------------------------------------------

#[test]
fn merge_candidate_diffs_a_newer_base_without_replacing_the_current_bundle() {
    let mut fork = source("apache_custom", GOOD_VRL);
    fork.forked_from = Some("apache_access".into());
    let current = build::generate(&inputs(vec![fork.clone()], BuildPurpose::Rollout, None));
    let current_bundle = current.bundle.unwrap();

    // A newer platform release changes the Apache parser the tenant forked.
    let mut newer = base();
    let apache = "sources/parsers/apache_http_server__ocsf_.toml";
    let mut text = newer.text(apache).unwrap().to_string();
    text.push_str("\n# platform release N+1\n");
    newer.put(apache, text.into_bytes());
    let newer_packed = archive::pack(&newer).unwrap();

    let mut i = inputs(
        vec![fork],
        BuildPurpose::MergeCandidate,
        Some(current_bundle.clone()),
    );
    i.base = newer_packed.clone();
    let mut request: BuildRequest = serde_json::from_slice(&i.build_json).unwrap();
    request.base_sha256 = sha(&newer_packed);
    i.build_json = serde_json::to_vec(&request).unwrap();

    let outcome = build::generate(&i);
    assert!(outcome.ok(), "{:?}", outcome.report.failure);
    let merge = outcome.report.merge.clone().unwrap();
    assert!(!merge.replaces_current);
    assert_eq!(merge.current_sha256, sha(&current_bundle));
    assert_eq!(merge.platform_files_changed, [apache]);
    assert!(
        merge.overlay_files_changed.is_empty(),
        "the tenant overlay itself did not change: {merge:?}"
    );
    assert_eq!(merge.fork_upstream.len(), 1);
    assert!(merge.fork_upstream[0].upstream_changed);
    assert_eq!(
        merge.fork_upstream[0].platform_file.as_deref(),
        Some(apache)
    );
    let diff = outcome.merge_diff.unwrap();
    assert!(diff.contains("+# platform release N+1"), "{diff}");
    assert_eq!(merge.diff_sha256, sha(diff.as_bytes()));
    // The candidate is a new artifact; the current bundle's bytes are untouched.
    assert_ne!(
        outcome.report.bundle.unwrap().content_sha256,
        sha(&current_bundle)
    );
}

#[test]
fn merge_candidate_requires_the_current_bundle() {
    let i = inputs(vec![], BuildPurpose::MergeCandidate, None);
    assert!(build::generate(&i)
        .report
        .failure
        .unwrap()
        .message
        .contains("current_sha256"));
}

#[test]
fn vector_test_cases_carry_samples_verbatim_and_escaped() {
    let mut s = source("acme", GOOD_VRL);
    s.samples = vec!["GET /$HOME \"quoted\"\nsecond line".into()];
    let outcome = build::generate(&inputs(vec![s], BuildPurpose::Rollout, None));
    let tests = outcome.tests_toml.unwrap();
    let parsed: toml::Table = tests.replace("$$", "$").parse().unwrap();
    let case = &parsed["tests"].as_array().unwrap()[0];
    assert_eq!(case["name"].as_str(), Some("tenant acme sample 1"));
    assert_eq!(
        case["inputs"][0]["insert_at"].as_str(),
        Some("tenant__acme_parse")
    );
    assert_eq!(
        case["inputs"][0]["log_fields"]["message"].as_str(),
        Some("GET /$HOME \"quoted\"\nsecond line")
    );
    assert_eq!(
        case["outputs"][0]["extract_from"].as_str(),
        Some("tenant__acme_ocsf_prepare")
    );
    assert!(!super::scan::has_unescaped_dollar(&tests));
}

// -- canonical report digest (onboarding open item 1) -------------------------

fn inputs_with_build_id(build_id: &str) -> BuildInputs {
    let mut built = inputs(vec![source("acme", GOOD_VRL)], BuildPurpose::Rollout, None);
    let mut request: serde_json::Value = serde_json::from_slice(&built.build_json).unwrap();
    request["build_id"] = serde_json::json!(build_id);
    built.build_json = serde_json::to_vec(&request).unwrap();
    built
}

fn vector_run(report: &BuildReport, duration_ms: u64, stamp: &str) -> VectorResults {
    let mut results = passing_vector(report);
    for run in [results.validate.as_mut().unwrap(), results.test.as_mut().unwrap()] {
        run.duration_ms = duration_ms;
        run.output = format!("{stamp} INFO vector: loaded\n{}", run.output);
    }
    results
}

/// The files the Vector stage leaves in `/results` (`VectorResults::read`).
fn write_results(results: &VectorResults, dir: &std::path::Path) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("egress.txt"), results.egress.as_deref().unwrap()).unwrap();
    std::fs::write(dir.join("version.txt"), results.version.as_deref().unwrap()).unwrap();
    for (stem, run) in [("validate", results.validate.as_ref().unwrap()), ("test", results.test.as_ref().unwrap())] {
        std::fs::write(dir.join(format!("{stem}.rc")), run.exit_code.to_string()).unwrap();
        std::fs::write(dir.join(format!("{stem}.ms")), run.duration_ms.to_string()).unwrap();
        std::fs::write(dir.join(format!("{stem}.out")), &run.output).unwrap();
    }
}

/// Two Jobs over identical inputs (fresh build_id, different wall-clock
/// timings and Vector log timestamps) give the same `report_sha256`, through
/// the real finalize path (report.json, summary.json, the log result line).
#[test]
fn identical_inputs_give_the_same_report_sha256_across_rebuilds() {
    let run = |build_id: &str, duration_ms: u64, stamp: &str| {
        let dir = tempfile::tempdir().unwrap();
        let (input, work, results, out) = (dir.path().join("input"), dir.path().join("work"),
            dir.path().join("results"), dir.path().join("out"));
        let built = inputs_with_build_id(build_id);
        for (name, data) in [(build::BUILD_FILE, &built.build_json), (build::SOURCES_FILE, &built.sources_json),
                             (build::BASE_FILE, &built.base)] {
            std::fs::create_dir_all(&input).unwrap();
            std::fs::write(input.join(name), data).unwrap();
        }
        let generated = build::run_generate(&input, &work).unwrap();
        assert!(generated.ok(), "{:?}", generated.report.failure);
        write_results(&vector_run(&generated.report, duration_ms, stamp), &results);
        let mut log = Vec::new();
        let summary = build::run_finalize(&work, &results, &out, None, Some(DIGEST), &mut log).unwrap();
        let report_bytes = std::fs::read(out.join(build::REPORT_FILE)).unwrap();
        let report: BuildReport = serde_json::from_slice(&report_bytes).unwrap();
        (summary, report, report_bytes)
    };
    let (a, report_a, bytes_a) = run("req-first", 1_200, "2026-09-23T06:30:00.001Z");
    let (b, report_b, bytes_b) = run("req-rebuilt-after-ttl", 9_876, "2026-09-23T08:31:17.999Z");
    assert_eq!(a.verdict, Verdict::Passed);
    assert_ne!(a.build_id, b.build_id);
    assert_ne!(bytes_a, bytes_b, "the files differ (build_id, timings, tool output)");
    assert_ne!(report_a.inputs.build_sha256, report_b.inputs.build_sha256);
    assert_eq!(report_a.inputs.build_request_sha256, report_b.inputs.build_request_sha256);
    assert_eq!(a.content_sha256, b.content_sha256);
    assert_eq!(a.report_sha256, b.report_sha256, "canonical report digest is stable across rebuilds");
    assert_eq!(report_a.report_sha256.as_deref(), Some(a.report_sha256.as_str()), "report.json carries it");
    assert_eq!(build::canonical_report_sha256(&report_a), a.report_sha256, "recomputable from report.json");
    assert_eq!(a.report_file_sha256, sha(&bytes_a), "the file digest stays available");
    assert_ne!(a.report_sha256, a.report_file_sha256);
}

/// The digest still binds everything that decides what was validated.
#[test]
fn report_sha256_changes_with_what_was_validated() {
    let generated = build::generate(&inputs_with_build_id("req-1"));
    let bundle = generated.bundle.clone().unwrap();
    let report = build::finalize_report(generated.report.clone(), &passing_vector(&generated.report), Some(&bundle), Some(DIGEST));
    let digest = build::canonical_report_sha256(&report);
    let mut mutated = report.clone();
    mutated.build_id = "another".into();
    mutated.timings_ms.generate_ms += 5;
    mutated.report_sha256 = Some("f".repeat(64));
    assert_eq!(build::canonical_report_sha256(&mutated), digest, "excluded fields");
    for change in [
        |r: &mut BuildReport| r.inputs.tenant_sources_sha256 = "0".repeat(64),
        |r: &mut BuildReport| r.inputs.base_sha256 = "0".repeat(64),
        |r: &mut BuildReport| r.inputs.build_request_sha256 = Some("0".repeat(64)),
        |r: &mut BuildReport| r.versions.runtime_image_digest = "sha256:x".into(),
        |r: &mut BuildReport| r.verdict = Verdict::Failed,
        |r: &mut BuildReport| r.checks[0].status = CheckStatus::Failed,
        |r: &mut BuildReport| r.sources[0].version_number += 1,
        |r: &mut BuildReport| r.bundle.as_mut().unwrap().content_sha256 = "0".repeat(64),
    ] {
        let mut changed = report.clone();
        change(&mut changed);
        assert_ne!(build::canonical_report_sha256(&changed), digest);
    }
    // A different request (other than its build_id) is a different digest.
    let mut other = inputs_with_build_id("req-1");
    let mut request: serde_json::Value = serde_json::from_slice(&other.build_json).unwrap();
    request["require_samples"] = serde_json::json!(true);
    other.build_json = serde_json::to_vec(&request).unwrap();
    assert_ne!(build::generate(&other).report.inputs.build_request_sha256, generated.report.inputs.build_request_sha256);
}

// -- NAN-2977: the zero-parser (plumbing-only) platform base ------------------

const ZERO_BASE: &[u8] = include_bytes!("testdata/platform-base-zero.tar.gz");
const ZERO_BASE_V2: &[u8] = include_bytes!("testdata/platform-base-zero-collector-v2.tar.gz");

fn zero_inputs(sources: Vec<TenantSource>) -> BuildInputs {
    let mut inputs = inputs(sources, BuildPurpose::Rollout, None);
    let mut request: BuildRequest = serde_json::from_slice(&inputs.build_json).unwrap();
    request.base_sha256 = sha(ZERO_BASE);
    inputs.build_json = serde_json::to_vec(&request).unwrap();
    inputs.base = ZERO_BASE.to_vec();
    inputs
}

#[test]
fn the_zero_base_ships_no_source_parsers_only_plumbing() {
    for (packed, plumbing) in [(ZERO_BASE, vec!["otlp_log"]), (ZERO_BASE_V2, vec!["otlp_log", "unknown"])] {
        let base = archive::unpack(packed).unwrap();
        assert_eq!(overlay::platform_slugs(&base).unwrap(), plumbing);
        let parser_files: Vec<&String> = base
            .files
            .keys()
            .filter(|p| p.starts_with("sources/parsers/") && p.ends_with(".toml"))
            .filter(|p| !p.trim_start_matches("sources/parsers/").starts_with('_'))
            .collect();
        assert!(parser_files.is_empty(), "no source parser: {parser_files:?}");
        for slug in ["apache_access", "aws_cloudtrail", "conduit_proxy", "otlp_log", "windows_event", "windows_sysmon"] {
            assert_eq!(overlay::platform_parser_file(&base, slug), None, "{slug}");
        }
        // The empty overlay is exactly the base.
        let (candidate, generated) = overlay::apply_overlay(&base, &[]).unwrap();
        assert!(generated.is_empty());
        assert_eq!(archive::pack(&candidate).unwrap(), archive::pack(&base).unwrap());
    }
}

#[test]
fn catalog_parsers_build_as_tenant_parsers_on_the_zero_base() {
    // Formerly refused: apache_access was a base parser (NAN-2969).
    let outcome = build::generate(&zero_inputs(vec![source("apache_access", GOOD_VRL)]));
    assert!(outcome.ok(), "{:?}", outcome.report.failure);
    let report = build::finalize_report(outcome.report.clone(), &passing_vector(&outcome.report), outcome.bundle.as_deref(), Some(DIGEST));
    assert_eq!(report.verdict, Verdict::Passed, "{:?}", report.failure);

    // OTLP -> OCSF from the catalog on the otlp_log plumbing slug: its route
    // is added, the platform's HEC token/allowlist entry is reused (never
    // duplicated), and the overlay strips back to the exact base.
    let base = archive::unpack(ZERO_BASE_V2).unwrap();
    let (candidate, _) = overlay::apply_overlay(&base, &[source("otlp_log", GOOD_VRL)]).unwrap();
    let hec = candidate.text("02-hec-source.toml").unwrap();
    assert_eq!(hec.matches("nano-source-v1:otlp_log\"").count(), 1, "one otlp_log token");
    let router = candidate.text("sources/parsers/_router.toml").unwrap();
    assert!(router.contains("'.source_type == \"otlp_log\"'"), "tenant route");
    assert!(router.contains("generic = '!includes([\"otlp_log\"]"), "generic lane excludes it");
    let verified = overlay::verify_against_base(&base, &candidate).unwrap();
    assert_eq!(verified.hec_sources, vec!["otlp_log", "unknown"], "a plumbing slug adds no source");
    let (platform, tenants) = overlay::strip_overlay(&candidate).unwrap();
    assert_eq!(tenants.len(), 1);
    assert_eq!(archive::pack(&platform).unwrap(), archive::pack(&base).unwrap());

    // The undeclared lane is never a tenant parser.
    let error = overlay::apply_overlay(&base, &[source("unknown", GOOD_VRL)]).unwrap_err();
    assert!(error.to_string().contains("reserved ingestion slug"), "{error}");
}

// -- NAN-3197: per-source sampling on shared tenancy --------------------------

fn sampled(slug: &str, ratio: Option<f64>, exclude: Option<&str>) -> TenantSource {
    let mut s = source(slug, GOOD_VRL);
    s.sampling_ratio = ratio;
    s.sampling_exclude_condition = exclude.map(str::to_string);
    s
}

fn zero_base() -> BundleTree {
    archive::unpack(ZERO_BASE).unwrap()
}

fn transforms(tree: &BundleTree, path: &str) -> toml::Table {
    let table: toml::Table = tree.text(path).unwrap().parse().unwrap();
    table["transforms"].as_table().unwrap().clone()
}

/// The `inputs` of `[transforms.<name>]`, read as text: the lake sink file
/// carries `${VAR:-n}` interpolations and is not TOML until Vector expands it.
fn inputs_of(tree: &BundleTree, path: &str, name: &str) -> Vec<String> {
    let text = tree.text(path).unwrap();
    let section = &text[text.find(&format!("[transforms.{name}]\n")).unwrap()..];
    let line = section.lines().find(|l| l.starts_with("inputs = [")).unwrap();
    let list: toml::Table = line.parse().unwrap();
    list["inputs"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect()
}

/// A ratio below 1 on a catalog (platform catalog) slug samples both lanes
/// of that tenant parser: the combiner reads `_sample`, the lake lane reads
/// `_ocsf_sample`, parser health stays pre-sampling, and the guard accepts it.
#[test]
fn sampling_below_one_samples_both_lanes_of_a_catalog_slug() {
    for slug in ["windows_event", "apache_access", "otlp_log"] {
        let base = zero_base();
        let source = sampled(slug, Some(0.1), Some(".severity_id >= 4"));
        let (candidate, generated) = overlay::apply_overlay(&base, &[source]).unwrap();
        let tenant = &generated[0].tenant;
        assert!(tenant.sampled && tenant.ocsf_sampled, "{slug}");
        let name = &tenant.name;
        let file = transforms(&candidate, &tenant.file());
        assert_eq!(file[&format!("{name}_sample")]["type"].as_str(), Some("sample"), "{slug}");
        let ocsf = &file[&format!("{name}_ocsf_sample")];
        assert_eq!(ocsf["type"].as_str(), Some("sample"), "{slug}");
        assert_eq!(ocsf["ratio"].as_float(), Some(0.1), "{slug}");
        assert_eq!(ocsf["inputs"].as_array().unwrap()[0].as_str(), Some(format!("{name}_ocsf_prepare").as_str()));

        let lake = inputs_of(&candidate, overlay::LAKE_SINK_FILE, "ocsf_lake_storage_prepare");
        assert!(lake.contains(&format!("{name}_ocsf_sample")), "{slug}: {lake:?}");
        assert!(!lake.contains(&format!("{name}_ocsf_prepare")), "{slug}: the unsampled lane must not also reach the lake");
        let combined = inputs_of(&candidate, overlay::COMBINER_FILE, "db_parsers_combined");
        assert!(combined.contains(&format!("{name}_sample")) && !combined.contains(&format!("{name}_output")), "{combined:?}");
        let health = inputs_of(&candidate, overlay::COMBINER_FILE, "db_parser_health");
        assert!(health.contains(&format!("{name}_output")) && health.contains(&format!("{name}_ocsf_prepare")), "{health:?}");

        let verified = overlay::verify_against_base(&base, &candidate).unwrap();
        assert_eq!(verified.tenants, generated.iter().map(|g| g.tenant.clone()).collect::<Vec<_>>());
        let (platform, tenants) = overlay::strip_overlay(&candidate).unwrap();
        assert!(tenants[0].ocsf_sampled);
        assert_eq!(archive::pack(&platform).unwrap(), archive::pack(&base).unwrap(), "{slug}");
    }
}

/// Ratio 1 or no ratio: no sample step anywhere, and the overlay is the
/// unsampled one byte for byte.
#[test]
fn ratio_one_or_none_emits_no_sample_step() {
    let base = zero_base();
    let (plain, _) = overlay::apply_overlay(&base, &[sampled("windows_event", None, None)]).unwrap();
    for (ratio, exclude) in [(Some(1.0), None), (None, Some(".severity_id >= 4")), (Some(1.0), Some(".x == 1"))] {
        let (candidate, generated) = overlay::apply_overlay(&base, &[sampled("windows_event", ratio, exclude)]).unwrap();
        assert!(!generated[0].tenant.sampled && !generated[0].tenant.ocsf_sampled);
        assert!(!generated[0].components.iter().any(|c| c.ends_with("_sample")), "{:?}", generated[0].components);
        assert_eq!(candidate, plain, "{ratio:?} {exclude:?}");
    }
}

/// The exclude condition is honoured on both lanes and parse failures are
/// never sampled away: the UDM lane (where failures land) excludes
/// `_nano_parser_failure`, and the OCSF verdict is computed by the prepare.
#[test]
fn sampling_honours_the_exclude_condition_and_keeps_parse_failures() {
    let (candidate, generated) =
        overlay::apply_overlay(&zero_base(), &[sampled("windows_event", Some(0.05), Some(".severity_id >= 4"))]).unwrap();
    let name = &generated[0].tenant.name;
    let file = transforms(&candidate, &generated[0].tenant.file());
    assert_eq!(
        file[&format!("{name}_sample")]["exclude"].as_str(),
        Some("(to_bool(._nano_parser_failure) ?? false) || (.severity_id >= 4)")
    );
    assert_eq!(
        file[&format!("{name}_ocsf_sample")]["exclude"].as_str(),
        Some("(to_bool(._nano_parser_failure) ?? false) || (to_bool(._nano_sampling_exclude) ?? false)")
    );
    let prepare = file[&format!("{name}_ocsf_prepare")]["source"].as_str().unwrap();
    assert!(prepare.contains("nano_sampling_exclude = (.severity_id >= 4) == true"), "{prepare}");
    // Failures: both remaps reroute runtime errors into `_output`, which the
    // UDM sample never drops; the OCSF split keeps parse errors off its lane.
    let output = file[&format!("{name}_output")]["inputs"].as_array().unwrap();
    assert!(output.iter().any(|i| i.as_str() == Some(&format!("{name}_parse.dropped"))), "{output:?}");
    let split = file[&format!("{name}_ocsf_split")]["route"]["ocsf"].as_str().unwrap();
    assert!(split.contains("!exists(.parse_error) && !exists(.metadata.parse_error)"), "{split}");
}

/// Extensions: an extension (or an extension-only stub) on a catalog slug is
/// sampled after the extension, on both lanes.
#[test]
fn sampling_applies_after_an_extension() {
    for parser_vrl in [GOOD_VRL, ""] {
        let mut s = sampled("windows_event", Some(0.5), Some(".ext.keep == true"));
        s.parser_vrl = parser_vrl.into();
        s.extension_vrl = Some(".ext.keep = true".into());
        s.extension_enabled = true;
        let base = zero_base();
        let (candidate, generated) = overlay::apply_overlay(&base, &[s]).unwrap();
        let name = &generated[0].tenant.name;
        assert_eq!(generated[0].entry_component, if parser_vrl.is_empty() { format!("{name}_extension") } else { format!("{name}_parse") });
        let file = transforms(&candidate, &generated[0].tenant.file());
        assert_eq!(file[&format!("{name}_ocsf_split")]["inputs"].as_array().unwrap()[0].as_str(), Some(format!("{name}_extension").as_str()));
        assert!(file.contains_key(&format!("{name}_ocsf_sample")));
        overlay::verify_against_base(&base, &candidate).unwrap();
    }
}

/// Tenant isolation: one source's sampling changes only that source's
/// parser file and its own wiring items; every other source's file and
/// every platform byte are identical to the unsampled overlay.
#[test]
fn sampling_one_source_leaves_other_sources_and_the_platform_unchanged() {
    let base = zero_base();
    let others = || vec![source("acme-fw", GOOD_VRL), source("apache_access", GOOD_VRL)];
    let mut plain_sources = others();
    plain_sources.push(sampled("windows_event", None, None));
    let mut sampled_sources = others();
    sampled_sources.push(sampled("windows_event", Some(0.1), Some(".severity_id >= 4")));
    let (plain, _) = overlay::apply_overlay(&base, &plain_sources).unwrap();
    let (with, generated) = overlay::apply_overlay(&base, &sampled_sources).unwrap();
    let changed = super::diff::changed_paths(&plain, &with);
    assert_eq!(
        changed,
        [overlay::COMBINER_FILE, overlay::LAKE_SINK_FILE, "sources/parsers/tenant__windows_event.toml"],
        "only the sampled source's file and its own combiner/lake items"
    );
    for g in generated.iter().filter(|g| g.tenant.slug != "windows_event") {
        assert_eq!(plain.file(&g.tenant.file()), with.file(&g.tenant.file()), "{}", g.tenant.slug);
        assert!(!g.tenant.sampled && !g.tenant.ocsf_sampled);
    }
    let lake = inputs_of(&with, overlay::LAKE_SINK_FILE, "ocsf_lake_storage_prepare");
    assert!(lake.contains(&"tenant__acme_fw_ocsf_prepare".to_string()) && lake.contains(&"tenant__apache_access_ocsf_prepare".to_string()), "{lake:?}");
    let (platform, _) = overlay::strip_overlay(&with).unwrap();
    assert_eq!(archive::pack(&platform).unwrap(), archive::pack(&base).unwrap());
}

/// A bundle built before NAN-3197 (`_sample` without `_ocsf_sample`, lake
/// lane on `_ocsf_prepare`) still strips back to its base.
#[test]
fn a_pre_nan3197_sampled_bundle_still_strips() {
    let base = zero_base();
    let (mut candidate, generated) =
        overlay::apply_overlay(&base, &[sampled("windows_event", Some(0.5), None)]).unwrap();
    let tenant = &generated[0].tenant;
    let file = candidate.text(&tenant.file()).unwrap().to_string();
    let start = file.find("\n[transforms.tenant__windows_event_ocsf_sample]").unwrap();
    let end = start + 1 + file[start + 1..].find("\n[transforms.").unwrap();
    candidate.put(&tenant.file(), format!("{}{}", &file[..start], &file[end..]).into_bytes());
    let sink = candidate.text(overlay::LAKE_SINK_FILE).unwrap().replace("tenant__windows_event_ocsf_sample", "tenant__windows_event_ocsf_prepare");
    candidate.put(overlay::LAKE_SINK_FILE, sink.into_bytes());
    let verified = overlay::verify_against_base(&base, &candidate).unwrap();
    assert!(verified.tenants[0].sampled && !verified.tenants[0].ocsf_sampled);
}

#[test]
fn source_test_configs_preserve_cases_and_exact_transform_dependencies() {
    let mut first = source("first", GOOD_VRL);
    first.samples = vec![
        "GET /$HOME/NANO_SHARD_INTERPOLATION_0_".into(),
        "invalid".into(),
    ];
    let outcome = build::generate(&inputs(
        vec![first, source("second", GOOD_VRL)],
        BuildPurpose::Rollout,
        None,
    ));
    assert!(outcome.ok(), "{:?}", outcome.report.failure);
    let combined: toml::Table = outcome.tests_toml.as_ref().unwrap().parse().unwrap();
    let tree = archive::unpack(outcome.bundle.as_ref().unwrap()).unwrap();
    assert_eq!(outcome.source_test_configs.len(), 2);
    let mut actual_cases = Vec::new();
    for text in &outcome.source_test_configs {
        // The runtime substitutes these typed defaults before parsing TOML.
        let typed =
            regex::Regex::new(r"(?m)(=\s*)\$\{[A-Za-z_][A-Za-z0-9_]*:-([^}\n]+)\}").unwrap();
        let concrete = typed.replace_all(text, "${1}${2}");
        let shard: toml::Table = concrete.parse().unwrap();
        assert!(text.contains("${VECTOR_RATE_LIMIT_PER_CLIENT_EPS:-500000}"));
        let transforms = shard["transforms"].as_table().unwrap();
        let tests = shard["tests"].as_array().unwrap();
        actual_cases.extend(tests.iter().cloned());
        let name = tests[0]["name"].as_str().unwrap();
        let (own, other) = if name.contains("first") {
            ("first", "second")
        } else {
            ("second", "first")
        };
        assert!(transforms.contains_key(&format!("tenant__{own}_parse")));
        assert!(!transforms
            .keys()
            .any(|key| key.starts_with(&format!("tenant__{other}_"))));
        for (component, transform) in transforms {
            let original = tree
                .files
                .iter()
                .filter(|(path, _)| {
                    matches!(
                        path.rsplit_once('/').map(|(p, _)| p).unwrap_or(""),
                        "" | "sources/parsers" | "sources/configs"
                    )
                })
                .filter_map(|(_, bytes)| std::str::from_utf8(bytes).ok())
                .filter_map(|text| {
                    typed
                        .replace_all(text, "${1}${2}")
                        .parse::<toml::Table>()
                        .ok()
                })
                .find_map(|doc| doc.get("transforms")?.get(component).cloned());
            assert_eq!(Some(transform), original.as_ref(), "changed {component}");
            for input in transform.get("inputs").unwrap().as_array().unwrap() {
                let upstream = input.as_str().unwrap().split('.').next().unwrap();
                assert!(
                    transforms.contains_key(upstream)
                        || shard
                            .get("sources")
                            .and_then(|sources| sources.get(upstream))
                            .is_some(),
                    "missing {upstream}"
                );
            }
        }
    }
    assert_eq!(actual_cases, *combined["tests"].as_array().unwrap());
}

/// Run on the train with the pinned Vector fork; no local core test build needed.
#[test]
#[ignore = "requires Docker and NANO_PIPE_VECTOR_TEST_IMAGE; memory-capped Vector integration"]
fn source_test_configs_vector_equivalence() {
    let image = std::env::var("NANO_PIPE_VECTOR_TEST_IMAGE").expect("pin Vector image");
    let vrl = format!("assert!(.message == \"GET /index.html\")\n{GOOD_VRL}")
        .replace("parts[0] ?? \"GET\"", "parts[0]")
        .replace("parts[1] ?? \"/\"", "parts[1]");
    for bad in [None, Some("first"), Some("second")] {
        let mut sources = vec![source("first", &vrl), source("second", &vrl)];
        if let Some(bad) = bad {
            sources.iter_mut().find(|s| s.slug == bad).unwrap().samples = vec!["bad sample".into()];
        }
        let outcome = build::generate(&inputs(sources, BuildPurpose::Rollout, None));
        assert!(outcome.ok(), "{:?}", outcome.report.failure);
        let tree = archive::unpack(outcome.bundle.as_ref().unwrap()).unwrap();
        let temp = tempfile::tempdir_in(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../target"),
        ).unwrap();
        for (path, bytes) in &tree.files {
            let dest = temp.path().join(path);
            std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
            std::fs::write(dest, bytes).unwrap();
        }
        std::fs::write(temp.path().join("tests.toml"), outcome.tests_toml.unwrap()).unwrap();
        for (index, shard) in outcome.source_test_configs.iter().enumerate() {
            std::fs::write(
                temp.path().join(format!("shard-{index}.toml.disabled")),
                shard,
            )
            .unwrap();
        }
        let run = |args: &[&str]| {
            let mut command = std::process::Command::new("docker");
            command
                .args([
                    "run",
                    "--rm",
                    "--network",
                    "none",
                    "--memory",
                    "2g",
                    "--cpus",
                    "2",
                    "--ulimit",
                    "core=0",
                    "--entrypoint",
                    "/usr/bin/vector",
                    "-v",
                ])
                .arg(format!("{}:/fixtures:ro", temp.path().display()));
            for (key, value) in &outcome.env {
                command.args(["-e", &format!("{key}={value}")]);
            }
            command
                .arg(&image)
                .args(["--dangerously-allow-env-var-interpolation", "test"])
                .args(args)
                .output()
                .unwrap()
        };
        let combined = run(&[
            "--config-dir",
            "/fixtures",
            "--config-dir",
            "/fixtures/sources/parsers",
            "--config-dir",
            "/fixtures/sources/configs",
        ]);
        assert_eq!(
            combined.status.success(),
            bad.is_none(),
            "combined: {:?}\n{}\n{}",
            combined.status,
            String::from_utf8_lossy(&combined.stdout),
            String::from_utf8_lossy(&combined.stderr)
        );
        for (index, slug) in ["first", "second"].iter().enumerate() {
            let shard = run(&[
                "--config-toml",
                &format!("/fixtures/shard-{index}.toml.disabled"),
            ]);
            assert_eq!(
                shard.status.success(),
                bad != Some(*slug),
                "{slug}: {:?}\n{}\n{}",
                shard.status,
                String::from_utf8_lossy(&shard.stdout),
                String::from_utf8_lossy(&shard.stderr)
            );
        }
    }
}

#[test]
fn source_test_configs_only_include_changed_sources_with_samples() {
    let mut request = inputs(
        vec![source("first", GOOD_VRL), source("second", GOOD_VRL)],
        BuildPurpose::Rollout,
        None,
    );
    let mut json: serde_json::Value = serde_json::from_slice(&request.build_json).unwrap();
    json["changed_sources"] = serde_json::json!(["second"]);
    request.build_json = serde_json::to_vec(&json).unwrap();
    let outcome = build::generate(&request);
    assert!(outcome.ok(), "{:?}", outcome.report.failure);
    assert_eq!(outcome.source_test_configs.len(), 1);
    let text = &outcome.source_test_configs[0];
    assert!(text.contains("tenant second sample 1"));
    assert!(!text.contains("[transforms.tenant__first_"));
    let empty = build::generate(&inputs(Vec::new(), BuildPurpose::Rollout, None));
    assert!(empty.ok(), "{:?}", empty.report.failure);
    assert!(empty.source_test_configs.is_empty());
}


#[test]
fn connect_first_enrolls_only_authentication_and_preserves_the_generic_lane() {
    let raw = source("vercel", "");
    let sources = TenantSources { schema_version: 1, tenant_id: TENANT.into(), sources: vec![raw.clone()] };
    sources.validate(TENANT).unwrap();
    let platform = base();
    let (connected, generated) = overlay::apply_overlay(&platform, &[raw.clone()]).unwrap();
    assert!(generated.is_empty(), "no new parser lane");
    assert_eq!(connected.file(overlay::ROUTER_FILE), platform.file(overlay::ROUTER_FILE));
    assert_eq!(connected.file(overlay::LAKE_SINK_FILE), platform.file(overlay::LAKE_SINK_FILE));
    let verified = overlay::verify_against_base(&platform, &connected).unwrap();
    assert!(verified.hec_sources.contains(&"vercel".into()));
    assert_eq!(verified.unparsed_sources, vec!["vercel"]);
    assert!(connected.text(overlay::HEC_FILE).unwrap().contains(":nano-source-v1:vercel"));
    // The only switch is the normal parser overlay. The transport identity
    // and private delivery token stay byte-identical across publication.
    let (parsed, generated) = overlay::apply_overlay(&platform, &[source("vercel", GOOD_VRL)]).unwrap();
    let parsed_verified = overlay::verify_against_base(&platform, &parsed).unwrap();
    assert_eq!(parsed_verified.hec_sources, verified.hec_sources);
    assert_eq!(parsed.file(overlay::HEC_FILE), connected.file(overlay::HEC_FILE));
    assert_eq!(generated.len(), 1);
    assert!(parsed.file(overlay::UNPARSED_SOURCES_FILE).is_none());
}

#[test]
fn connect_first_guard_refuses_reserved_duplicate_and_forged_enrollments() {
    let platform = base();
    for slug in ["unknown", "default", "audit", "otlp_log", "otlp_metric", "otlp_trace"] {
        assert!(overlay::apply_overlay(&platform, &[source(slug, "")]).is_err(), "{slug}");
    }
    let (connected, _) = overlay::apply_overlay(&platform, &[source("vercel", "")]).unwrap();
    for bytes in [br#"["unknown"]"#.as_slice(), br#"["vercel","vercel"]"#, br#"["vercel", "z"]"#, br#"["not-enrolled"]"#] {
        let mut forged = connected.clone();
        forged.put(overlay::UNPARSED_SOURCES_FILE, bytes.to_vec());
        assert!(overlay::verify_against_base(&platform, &forged).is_err());
    }
    let mut forged = connected.clone();
    forged.put(overlay::ROUTER_FILE, b"[transforms.evil]\ntype=\"remap\"".to_vec());
    assert!(overlay::verify_against_base(&platform, &forged).is_err());
}


#[tokio::test]
async fn connect_first_generic_lane_retains_feed_identity_and_raw_payload() {
    let platform = base();
    let (connected, _) = overlay::apply_overlay(&platform, &[source("vercel", "")]).unwrap();
    let pipeline: toml::Table = connected.text("sources/parsers/_pipeline.toml").unwrap().parse().unwrap();
    let generic = pipeline["transforms"]["generic_parser"]["source"].as_str().unwrap();
    let prepare = pipeline["transforms"]["generic_ocsf_prepare"]["source"].as_str().unwrap();
    let validator = crate::parsers::VrlValidator::new();
    let raw = r#"{"deployment":"web-24","status":200}"#;
    let input = serde_json::json!({"message": raw, "source_type":"vercel"}).to_string();
    let result = validator.test_vrl_chain(&[generic, prepare], &input).await.unwrap();
    assert!(result.success, "{:?}", result.error);
    let output = result.output.unwrap();
    assert_eq!(output["source_type"], "vercel");
    assert_eq!(output["event"]["class_uid"], 0);
    assert_eq!(output["event"]["metadata"]["log_name"], "vercel");
    let retained: serde_json::Value = serde_json::from_str(output["event"]["raw_data"].as_str().unwrap()).unwrap();
    assert_eq!(retained["message"], raw);
    assert_eq!(retained["metadata"]["parser_type"], "generic");
}
