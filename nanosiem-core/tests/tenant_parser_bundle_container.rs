// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2604 container acceptance: the whole build Job, rehearsed with
//! `run-local.sh` in the cell's pinned Vector image under `docker --network none`.
//!
//! Needs docker and the pinned image; opt in with
//! `NANO_PARSER_BUNDLE_CONTAINER_TESTS=1`. Without it every test returns early.

use std::path::{Path, PathBuf};
use std::process::Command;

use nanosiem_core::parsers::tenant_bundle::{archive, build, model::*};
use nanosiem_core::parsers::VrlValidator;
use sha2::{Digest, Sha256};

const BASE: &[u8] = include_bytes!("../src/parsers/tenant_bundle/testdata/platform-base.tar.gz");
const IMAGE: &str = "ghcr.io/nano-rs/vector:0.59.0-nano.12-debian@sha256:add06b5413292f53db629161c8f3805e8a3ed61bcb0785b5a0f252ae5ae0ecea";

const GOOD_VRL: &str = r#"parts = split(string!(.message), " ")
. = {
  "class_uid": 4002,
  "category_uid": 4,
  "activity_id": 99,
  "time": 1700000000000,
  "http_request": { "http_method": parts[0], "url": { "path": parts[1] } },
  "message": "cost $5 for ${HOME}"
}"#;

fn enabled() -> bool {
    let on = std::env::var("NANO_PARSER_BUNDLE_CONTAINER_TESTS").as_deref() == Ok("1");
    if !on {
        eprintln!("skipped: set NANO_PARSER_BUNDLE_CONTAINER_TESTS=1 (needs docker + {IMAGE})");
    }
    on
}

fn harness() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../deploy/parser-bundle-build/run-local.sh")
}

/// Scratch space the docker daemon can see: test runners may give the test a
/// private /tmp, so stay under the target dir.
fn scratch() -> tempfile::TempDir {
    tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap()
}

fn sha(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn source(vrl: &str, samples: &[&str]) -> serde_json::Value {
    serde_json::json!({
        "slug": "acme-web",
        "log_source_id": "11111111-1111-4111-8111-111111111111",
        "version_id": 9,
        "version_number": 2,
        "name": "Acme web",
        "parser_vrl": vrl,
        "samples": samples,
    })
}

/// Write one build request and run the Job rehearsal; returns (out dir, report).
fn run_build(dir: &Path, source: serde_json::Value, network: &str) -> (PathBuf, BuildReport) {
    run_build_on(dir, BASE, source, network)
}

/// [`run_build`] on a given platform base.
fn run_build_on(dir: &Path, base: &[u8], source: serde_json::Value, network: &str) -> (PathBuf, BuildReport) {
    run_build_with(dir, base, source, network, serde_json::json!({}))
}

/// [`run_build_on`] with extra `build.json` fields (`extra` is merged in).
fn run_build_with(
    dir: &Path,
    base: &[u8],
    source: serde_json::Value,
    network: &str,
    extra: serde_json::Value,
) -> (PathBuf, BuildReport) {
    let input = dir.join("input");
    let out = dir.join("out");
    std::fs::create_dir_all(&input).unwrap();
    std::fs::write(input.join("base.tar.gz"), base).unwrap();
    let mut build = serde_json::json!({
        "schema_version": 1,
        "build_id": "container-test",
        "tenant_id": "acme",
        "tenant_uuid": "00000000-0000-4000-8000-000000000042",
        "purpose": "rollout",
        "runtime_image_digest": IMAGE.rsplit('@').next().unwrap(),
        "base_sha256": sha(base),
    });
    for (key, value) in extra.as_object().expect("extra is an object") {
        build[key] = value.clone();
    }
    std::fs::write(input.join("build.json"), build.to_string()).unwrap();
    std::fs::write(
        input.join("tenant-sources.json"),
        serde_json::json!({"schema_version": 1, "tenant_id": "acme", "sources": [source]})
            .to_string(),
    )
    .unwrap();
    let status = Command::new("bash")
        .arg(harness())
        .arg(&input)
        .arg(&out)
        .env(
            "NANO_PARSER_BUNDLE_BUILD_BIN",
            env!("CARGO_BIN_EXE_nano-parser-bundle-build"),
        )
        .env("NANO_VECTOR_IMAGE", IMAGE)
        .env("NANO_LOCAL_DOCKER_NETWORK", network)
        .env("NANO_LOCAL_TMPDIR", env!("CARGO_TARGET_TMPDIR"))
        .status()
        .expect("run-local.sh runs");
    assert!(status.success(), "the rehearsal itself must not error");
    let report = serde_json::from_slice(&std::fs::read(out.join("report.json")).unwrap()).unwrap();
    (out, report)
}

#[test]
fn a_good_parser_passes_in_the_pinned_image_and_rebuilds_byte_identically() {
    if !enabled() {
        return;
    }
    let tmp = scratch();
    let (out, report) = run_build(
        &tmp.path().join("a"),
        source(GOOD_VRL, &["GET /index.html", "POST /login"]),
        "none",
    );
    assert_eq!(report.verdict, Verdict::Passed, "{:?}", report.failure);
    assert!(report
        .versions
        .vector
        .as_deref()
        .unwrap()
        .starts_with("vector 0.59.0"));
    let checks: Vec<(&str, CheckStatus)> = report
        .checks
        .iter()
        .map(|c| (c.name.as_str(), c.status))
        .collect();
    assert_eq!(
        checks,
        [
            ("structural_guard", CheckStatus::Passed),
            ("sandbox_egress", CheckStatus::Passed),
            ("vector_validate", CheckStatus::Passed),
            ("vector_test", CheckStatus::Passed),
        ]
    );
    let bundle = std::fs::read(out.join("bundle.tar.gz")).unwrap();
    assert_eq!(report.bundle.as_ref().unwrap().content_sha256, sha(&bundle));

    let (out_b, report_b) = run_build(
        &tmp.path().join("b"),
        source(GOOD_VRL, &["GET /index.html", "POST /login"]),
        "none",
    );
    assert_eq!(
        std::fs::read(out_b.join("bundle.tar.gz")).unwrap(),
        bundle,
        "same inputs, same bytes"
    );
    assert_eq!(report_b.bundle, report.bundle);
}

#[test]
fn vector_rejects_what_vrl_validator_accepts_and_the_build_shows_vectors_error() {
    if !enabled() {
        return;
    }
    // `.severity` is a valid VRL program — the SIEM's in-process validator
    // accepts it — but as a sampling exclusion it is a Vector *condition*,
    // which must return a boolean. Only the cell's binary knows that.
    let condition = ".severity";
    let checked = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(VrlValidator::new().validate_vrl(condition))
        .unwrap();
    assert!(
        checked.valid,
        "VrlValidator accepts the condition: {:?}",
        checked.error
    );

    let mut s = source(GOOD_VRL, &["GET /"]);
    s["sampling_ratio"] = 0.5.into();
    s["sampling_exclude_condition"] = condition.into();
    let tmp = scratch();
    let (out, report) = run_build(tmp.path(), s, "none");
    let failure = report.failure.expect("build fails");
    assert_eq!(failure.stage, Stage::VectorValidate);
    assert_eq!(failure.source.as_deref(), Some("acme-web"));
    assert_eq!(
        failure.component.as_deref(),
        Some("tenant__acme_web_sample")
    );
    assert!(
        failure.message.starts_with("x Transform \"tenant__acme_web_sample\": exclude: VRL conditions must return a boolean"),
        "the SIEM shows Vector's own error: {}",
        failure.message
    );
    assert!(
        !out.join("bundle.tar.gz").exists(),
        "a failed build emits no artifact"
    );
}

#[test]
fn a_runtime_error_passes_the_build_and_becomes_a_parse_failure_row() {
    if !enabled() {
        return;
    }
    // Compiles fine; errors at runtime on any non-JSON event.
    let vrl = ". = parse_json!(.message)";
    let tmp = scratch();
    let (out, report) = run_build(
        tmp.path(),
        source(
            vrl,
            &[r#"{"class_uid": 4002, "time": 1700000000000, "message": "ok"}"#],
        ),
        "none",
    );
    assert_eq!(report.verdict, Verdict::Passed, "{:?}", report.failure);

    // Run the built bundle in the pinned image with a poison event: Vector
    // must reroute it (no crash, no OCSF row from the parser) and the lake
    // lane must still carry it as a parse failure under the tenant's label.
    let bundle = std::fs::read(out.join("bundle.tar.gz")).unwrap();
    let env = build::placeholder_env(&archive::unpack(&bundle).unwrap());
    let extra = tmp.path().join("extra");
    std::fs::create_dir_all(&extra).unwrap();
    std::fs::write(
        extra.join("runtime.toml"),
        r#"[[tests]]
name = "runtime error becomes a parse_failure row"
no_outputs_from = ["tenant__acme_web_ocsf_prepare"]

[[tests.inputs]]
insert_at = "tenant__acme_web_parse"
type = "log"

[tests.inputs.log_fields]
message = "this is not json"

[[tests.outputs]]
extract_from = "tenant__acme_web_output"

[[tests.outputs.conditions]]
type = "vrl"
source = '''
meta = parse_json!(.metadata)
assert!(meta.parse_failure == true, "no parse_failure flag")
assert!(contains(string!(meta.parse_stage), "tenant__acme_web_parse"), "failure not attributed to the parse stage")
assert_eq!(.source_type, "acme-web")
'''

[[tests.outputs]]
extract_from = "ocsf_output_guard"

[[tests.outputs.conditions]]
type = "vrl"
# metadata.log_source is "unknown" on this lane today: a platform-base bug
# (NAN-2612), not the tenant overlay. The row still carries its source.
source = '''
assert_eq!(.metadata.tenant_uid, "acme")
raw = string!(.raw_data)
assert!(contains(raw, "parse_failure"), "the lake row lost the failure")
assert!(contains(raw, "acme-web"), "the lake row lost its source")
'''
"#,
    )
    .unwrap();
    let mut command = Command::new("docker");
    command.args([
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--user",
        "65534:65534",
        "--cap-drop",
        "ALL",
    ]);
    command.args([
        "--tmpfs",
        "/tmp:rw,size=64m,mode=1777",
        "-e",
        "NANO_TENANT_ID=acme",
    ]);
    for (name, value) in &env {
        command.args(["-e", &format!("{name}={value}")]);
    }
    command
        .arg("-v")
        .arg(format!("{}:/o:ro", out.display()))
        .arg("-v")
        .arg(format!("{}:/x:ro", extra.display()))
        .args(["--entrypoint", "/bin/bash", IMAGE, "-c"])
        .arg(
            "set -e; c=/tmp/cell; mkdir -p $c/dynamic/sources/parsers $c/dynamic/sources/configs; \
             gzip -dc /o/bundle.tar.gz | tar --touch -xf - -C $c; \
             cp -R $c/sources/parsers/. $c/dynamic/sources/parsers/; cp -R $c/sources/configs/. $c/dynamic/sources/configs/; \
             exec vector --dangerously-allow-env-var-interpolation test --config-dir $c \
               --config-dir $c/dynamic/sources/parsers --config-dir $c/dynamic/sources/configs --config-toml /x/runtime.toml",
        );
    let output = command.output().expect("docker runs");
    let text = String::from_utf8_lossy(&output.stdout).to_string()
        + &String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{text}");
    assert!(
        text.contains("test runtime error becomes a parse_failure row ... passed"),
        "{text}"
    );
}

#[test]
fn a_sandbox_that_can_reach_the_network_voids_the_build() {
    if !enabled() {
        return;
    }
    // The Job relies on a deny-all NetworkPolicy; the Vector stage verifies
    // it on every build. Give the rehearsal a real network: if the host can
    // reach the internet, the probe must find it and fail the build.
    let online = Command::new("bash")
        .args(["-c", "timeout 3 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443'"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !online {
        eprintln!("skipped: this host has no internet to leak");
        return;
    }
    let tmp = scratch();
    let (out, report) = run_build(tmp.path(), source(GOOD_VRL, &["GET /"]), "bridge");
    let failure = report.failure.expect("an open sandbox must fail the build");
    assert_eq!(failure.stage, Stage::Sandbox, "{failure:?}");
    assert!(failure.message.contains("open:"), "{}", failure.message);
    assert!(!out.join("bundle.tar.gz").exists());
}

/// NAN-2977: on the zero-parser (plumbing-only) collector-v2 base, catalog
/// parsers build as tenant parsers in the pinned image: apache_access (a
/// former platform source) and an OTLP parser on the otlp_log plumbing slug.
#[test]
fn catalog_parsers_build_on_the_zero_parser_base_in_the_pinned_image() {
    if !enabled() {
        return;
    }
    const ZERO_V2: &[u8] = include_bytes!("../src/parsers/tenant_bundle/testdata/platform-base-zero-collector-v2.tar.gz");
    let tmp = scratch();
    for slug in ["apache_access", "otlp_log"] {
        let mut declared = source(GOOD_VRL, &["GET /index.html", "POST /login"]);
        declared["slug"] = slug.into();
        let (_, report) = run_build_on(&tmp.path().join(slug), ZERO_V2, declared, "none");
        assert_eq!(report.verdict, Verdict::Passed, "{slug}: {:?}", report.failure);
    }
}

/// NAN-3712: a runtime-config pull bundle (code only, router and capture tap
/// over the stamp glob) validates in the pinned Vector image together with
/// the sample runtime config: one source per template variant, loaded from
/// `dynamic/pull` as the pull runtime loads it (Event Hubs included: the
/// fork's `azure_event_hubs`, with a `$$Default` consumer group).
#[test]
fn a_runtime_pull_bundle_validates_with_every_template_in_the_pinned_image() {
    if !enabled() {
        return;
    }
    const ZERO: &[u8] = include_bytes!("../src/parsers/tenant_bundle/testdata/platform-base-zero.tar.gz");
    let tmp = scratch();
    let mut declared = source(GOOD_VRL, &["GET /index.html"]);
    declared["slug"] = "apache_access".into();
    for capture in [false, true] {
        let (out, report) = run_build_with(
            &tmp.path().join(format!("capture-{capture}")),
            ZERO,
            declared.clone(),
            "none",
            serde_json::json!({"pull_lanes": ["apache_access"], "pull_capture": capture}),
        );
        assert_eq!(report.verdict, Verdict::Passed, "capture={capture}: {:?}", report.failure);
        let pull = report.pull_bundle.as_ref().expect("a runtime pull bundle");
        assert_eq!(pull.pull_runtime_contract.as_deref(), Some("nano-pull-runtime-v1"));
        let check = report
            .checks
            .iter()
            .find(|c| c.name == "vector_validate_pull")
            .expect("the pull bundle was validated");
        assert_eq!(check.status, CheckStatus::Passed, "{:?}", check.output);
        assert!(out.join("pull-bundle.tar.gz").exists());
    }
}

/// NAN-3079: the next zero-parser base module (generic lane writes `unmapped`
/// as one JSON string) passes a catalog-parser build in the pinned Vector
/// image: Vector itself accepts the edited generic lane.
#[test]
fn catalog_parsers_build_on_the_nan3079_zero_base_in_the_pinned_image() {
    if !enabled() {
        return;
    }
    use base64::Engine as _;
    let module = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(
        "../workers/hosted-ingest/src/selected-parser-zero-nan3079.js",
    ))
    .unwrap();
    let json = module
        .split_once("Object.freeze(")
        .and_then(|(_, rest)| rest.strip_suffix(");\n"))
        .expect("module shape");
    let selected: serde_json::Value = serde_json::from_str(json).unwrap();
    let chunks: String = selected["output-bound"]["chunks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap())
        .collect();
    let base = base64::engine::general_purpose::STANDARD.decode(chunks).unwrap();
    assert_eq!(sha(&base), "9041031b163345de35c700d067595b9ddec328be3f0cc12db3cc8808e73fba95");
    let tmp = scratch();
    for slug in ["conduit_proxy", "otlp_log"] {
        let mut declared = source(GOOD_VRL, &["GET /index.html", "POST /login"]);
        declared["slug"] = slug.into();
        let (_, report) = run_build_on(&tmp.path().join(slug), &base, declared, "none");
        assert_eq!(report.verdict, Verdict::Passed, "{slug}: {:?}", report.failure);
    }
}

/// NAN-3085: the next zero-parser base module (adds the 100 ms loss probe on
/// :9599) passes a catalog-parser build in the pinned Vector image: Vector
/// itself accepts the probe source, filter condition and exporter.
#[test]
fn catalog_parsers_build_on_the_nan3085_zero_base_in_the_pinned_image() {
    if !enabled() {
        return;
    }
    use base64::Engine as _;
    let module = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(
        "../workers/hosted-ingest/src/selected-parser-zero-nan3085.js",
    ))
    .unwrap();
    let json = module
        .split_once("Object.freeze(")
        .and_then(|(_, rest)| rest.strip_suffix(");\n"))
        .expect("module shape");
    let selected: serde_json::Value = serde_json::from_str(json).unwrap();
    let chunks: String = selected["output-bound"]["chunks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap())
        .collect();
    let base = base64::engine::general_purpose::STANDARD.decode(chunks).unwrap();
    assert_eq!(sha(&base), "491d59a5002fd49d705fe788249ed9ffe30846aa589ed91b5956f6bd617cbed6");
    let tmp = scratch();
    for slug in ["conduit_proxy", "otlp_log"] {
        let mut declared = source(GOOD_VRL, &["GET /index.html", "POST /login"]);
        declared["slug"] = slug.into();
        let (_, report) = run_build_on(&tmp.path().join(slug), &base, declared, "none");
        assert_eq!(report.verdict, Verdict::Passed, "{slug}: {:?}", report.failure);
    }
}

/// NAN-3197: a sampled catalog source (ratio < 1, an exclude condition, with
/// and without an extension) builds on the zero-parser base in the pinned
/// Vector image: Vector accepts both sample steps, the prepare VRL that
/// evaluates the exclude condition and the rewired lake lane.
#[test]
fn a_sampled_catalog_source_builds_on_the_zero_parser_base_in_the_pinned_image() {
    if !enabled() {
        return;
    }
    const ZERO_V2: &[u8] = include_bytes!("../src/parsers/tenant_bundle/testdata/platform-base-zero-collector-v2.tar.gz");
    let tmp = scratch();
    for (case, extension) in [("plain", None), ("extension", Some(".ext = { \"team\": \"red\" }"))] {
        let mut declared = source(GOOD_VRL, &["GET /index.html", "POST /login"]);
        declared["slug"] = "apache_access".into();
        declared["sampling_ratio"] = 0.1.into();
        declared["sampling_exclude_condition"] = "(to_int(.class_uid) ?? 0) == 4002".into();
        if let Some(vrl) = extension {
            declared["extension_vrl"] = vrl.into();
            declared["extension_enabled"] = true.into();
        }
        let (out, report) = run_build_on(&tmp.path().join(case), ZERO_V2, declared, "none");
        assert_eq!(report.verdict, Verdict::Passed, "{case}: {:?}", report.failure);
        let tree = archive::unpack(&std::fs::read(out.join("bundle.tar.gz")).unwrap()).unwrap();
        let parser = tree.text("sources/parsers/tenant__apache_access.toml").unwrap();
        assert!(parser.contains("[transforms.tenant__apache_access_ocsf_sample]"), "{case}");
        let sink = tree.text("sources/parsers/_ocsf_sink.toml").unwrap();
        assert!(sink.contains("\"tenant__apache_access_ocsf_sample\"]"), "{case}");
    }
}

#[test]
fn connect_first_authentication_only_bundle_validates_and_keeps_its_token_on_publish() {
    if !enabled() { return; }
    const ZERO_V2: &[u8] = include_bytes!("../src/parsers/tenant_bundle/testdata/platform-base-zero-collector-v2.tar.gz");
    let scratch = scratch();
    let (raw_out, raw) = run_build_on(&scratch.path().join("raw"), ZERO_V2,
        source("", &["{\"nano_ingress_probe\":true}"]), "none");
    assert_eq!(raw.verdict, Verdict::Passed, "{:?}", raw.failure);
    assert!(raw.sources[0].components.is_empty());
    let raw_tree = archive::unpack(&std::fs::read(raw_out.join("bundle.tar.gz")).unwrap()).unwrap();
    let base = archive::unpack(ZERO_V2).unwrap();
    assert_eq!(raw_tree.file("sources/parsers/_router.toml"), base.file("sources/parsers/_router.toml"));
    let (parsed_out, parsed) = run_build_on(&scratch.path().join("parsed"), ZERO_V2,
        source(GOOD_VRL, &["GET /index.html"]), "none");
    assert_eq!(parsed.verdict, Verdict::Passed, "{:?}", parsed.failure);
    let parsed_tree = archive::unpack(&std::fs::read(parsed_out.join("bundle.tar.gz")).unwrap()).unwrap();
    assert_eq!(raw.bundle.unwrap().hec_sources, parsed.bundle.unwrap().hec_sources);
    assert_eq!(raw_tree.file("02-hec-source.toml"), parsed_tree.file("02-hec-source.toml"),
        "the same transport token and source identity survive parser publication");
}
