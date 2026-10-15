// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3369: the lanes-subset pull bundle, on the zero-parser platform base
//! (plus the NAN-2999 audit plumbing lane, which a pull bundle must drop).

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::archive::{self, BundleTree};
use super::build::{self, BuildInputs, ToolRun, VectorResults};
use super::model::*;
use super::overlay::{self, OverlayProfile};
use super::platform_audit_lane;
use super::pull;

pub(super) const ZERO_BASE: &[u8] = include_bytes!("testdata/platform-base-zero.tar.gz");
pub(super) const DIGEST: &str = "sha256:ed2134fa8f9844c1ca6405260903c2c2c52f94af9e16bc8fa9de9655134e0b39";
pub(super) const TENANT: &str = "acme";
pub(super) const TENANT_UUID: u128 = 0xbbbb_bbbb_0000_4000_8000_0000_0000_0042;

pub(super) const OCSF_VRL: &str = r#"parts = split(string!(.message), " ")
. = {
  "class_uid": 4002,
  "category_uid": 4,
  "activity_id": 99,
  "time": 1700000000000,
  "http_request": { "http_method": parts[0] ?? "GET", "url": { "path": parts[1] ?? "/" } },
  "message": "acme"
}"#;

pub(super) fn sha(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// The zero base with the audit plumbing lane: what lean tenants run.
pub(super) fn base() -> BundleTree {
    let zero = archive::unpack(ZERO_BASE).unwrap();
    platform_audit_lane::add_platform_audit_lane(&zero).unwrap()
}

pub(super) fn packed_base() -> Vec<u8> {
    archive::pack(&base()).unwrap()
}

pub(super) fn source(slug: &str, vrl: &str) -> TenantSource {
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
        samples: Vec::new(),
    }
}

/// A tenant override of a catalog lane: the published version carries an
/// enabled extension (as the test-bed tenant's `apache_access` does).
fn overridden(slug: &str, marker: &str) -> TenantSource {
    let mut s = source(slug, OCSF_VRL);
    s.extension_vrl = Some(format!(".unmapped.override = \"{marker}\""));
    s.extension_enabled = true;
    s.version_number = 4;
    s
}

pub(super) fn tenant_sources() -> Vec<TenantSource> {
    vec![
        source("aws_cloudtrail", OCSF_VRL),
        overridden("apache_access", "v1"),
        source("windows_sysmon", OCSF_VRL),
    ]
}

pub(super) fn pull_source(id: u128, slug: &str, kind: PullSourceKind) -> PullSource {
    PullSource {
        source_id: Uuid::from_u128(id),
        slug: slug.into(),
        kind,
        sqs_client_concurrency: None,
        sqs_max_number_of_messages: None,
        backlog_cutoff_unix_ms: None,
    }
}

pub(super) fn pulls() -> Vec<PullSource> {
    vec![
        pull_source(0xa1, "aws_cloudtrail", PullSourceKind::AwsS3),
        pull_source(0xa2, "apache_access", PullSourceKind::AwsSqs),
    ]
}

pub(super) fn inputs(sources: Vec<TenantSource>, pull_sources: Option<Vec<PullSource>>) -> BuildInputs {
    inputs_with(sources, pull_sources, false)
}

/// NAN-3623: [`inputs`] with `pull_capture`.
pub(super) fn inputs_with(
    sources: Vec<TenantSource>,
    pull_sources: Option<Vec<PullSource>>,
    pull_capture: bool,
) -> BuildInputs {
    let base = packed_base();
    let request = BuildRequest {
        schema_version: 1,
        build_id: "req-1".into(),
        tenant_id: TENANT.into(),
        tenant_uuid: Uuid::from_u128(TENANT_UUID),
        purpose: BuildPurpose::Rollout,
        runtime_image_digest: DIGEST.into(),
        base_sha256: sha(&base),
        current_sha256: None,
        changed_sources: None,
        require_samples: false,
        pull_sources,
        pull_lanes: None,
        pull_capture,
    };
    BuildInputs {
        build_json: serde_json::to_vec(&request).unwrap(),
        sources_json: serde_json::to_vec(&TenantSources {
            schema_version: 1,
            tenant_id: TENANT.into(),
            sources,
        })
        .unwrap(),
        base,
        current: None,
    }
}

pub(super) fn generate(
    sources: Vec<TenantSource>,
    pull_sources: Option<Vec<PullSource>>,
) -> build::GenerateOutcome {
    let outcome = build::generate(&inputs(sources, pull_sources));
    assert!(outcome.ok(), "{:?}", outcome.report.failure);
    outcome
}

pub(super) fn pull_tree(outcome: &build::GenerateOutcome) -> BundleTree {
    archive::unpack(outcome.pull_bundle.as_deref().expect("a pull bundle")).unwrap()
}

pub(super) fn text<'a>(tree: &'a BundleTree, path: &str) -> &'a str {
    tree.text(path).unwrap()
}

pub(super) fn all_text(tree: &BundleTree) -> String {
    tree.files
        .values()
        .map(|data| String::from_utf8_lossy(data).into_owned())
        .collect()
}

fn inputs_of(tree: &BundleTree, path: &str, name: &str) -> Vec<String> {
    let text = tree.text(path).unwrap();
    let section = &text[text.find(&format!("[transforms.{name}]\n")).unwrap()..];
    let line = section
        .lines()
        .find(|l| l.starts_with("inputs = ["))
        .unwrap();
    let list: toml::Table = line.parse().unwrap();
    list["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect()
}

/// Vector results for a build without saved samples (no test cases to report).
pub(super) fn passing_vector(report: &BuildReport, pull_rc: Option<i32>) -> VectorResults {
    assert!(report.sources.iter().all(|s| s.samples == 0));
    let run = |output: &str, rc: i32| ToolRun {
        exit_code: rc,
        duration_ms: 1,
        output: output.into(),
    };
    VectorResults {
        skipped: false,
        egress: Some("blocked".into()),
        version: Some("vector 0.59.0".into()),
        validate: Some(run("Validated", 0)),
        test: Some(run("", 0)),
        pull_validate: pull_rc.map(|rc| {
            run(
                if rc == 0 {
                    "Validated"
                } else {
                    "x Transform \"nano_pull_x_stamp\": boom"
                },
                rc,
            )
        }),
    }
}

// -- the full bundle is untouched ----------------------------------------------

/// Acceptance: asking for a pull bundle changes nothing about the tenant
/// bundle: same bytes, same bundle facts, and a request without pull sources
/// serializes exactly as before (its `build_request_sha256` is unchanged).
#[test]
fn the_full_bundle_is_byte_identical_with_or_without_pull_sources() {
    let plain = generate(tenant_sources(), None);
    let with_pull = generate(tenant_sources(), Some(pulls()));
    assert!(plain.pull_bundle.is_none() && plain.report.pull_bundle.is_none());
    assert_eq!(plain.bundle, with_pull.bundle, "bundle.tar.gz bytes");
    assert_eq!(
        plain.report.bundle, with_pull.report.bundle,
        "report.bundle"
    );
    assert_eq!(plain.report.sources, with_pull.report.sources);
    assert_eq!(plain.tests_toml, with_pull.tests_toml);

    let request: serde_json::Value =
        serde_json::from_slice(&inputs(tenant_sources(), None).build_json).unwrap();
    assert!(
        request.get("pull_sources").is_none(),
        "absent pull_sources must not serialize"
    );
    let report = serde_json::to_value(&plain.report).unwrap();
    assert!(report.get("pull_bundle").is_none() && report.get("pull_pending").is_none());

    let out = with_pull.report.pull_bundle.as_ref().unwrap();
    assert_eq!(
        out.pull_bundle_sha256,
        sha(with_pull.pull_bundle.as_deref().unwrap())
    );
    assert_eq!(
        out.object_key,
        format!(
            "tenants/{}/pull-bundles/{}.tar.gz",
            Uuid::from_u128(TENANT_UUID),
            out.pull_bundle_sha256
        )
    );
    assert_eq!(out.lane_sources, vec!["apache_access", "aws_cloudtrail"]);
    assert_eq!(out.pull_sources.len(), 2);
    // NAN-3653: this builder always stamps the pull origin and reports it,
    // so the verifier gates on the pinned builder, not on a request field.
    assert!(out.pull_origin);
    assert_eq!(serde_json::to_value(out).unwrap()["pull_origin"], true);
    let bundle = archive::unpack(with_pull.pull_bundle.as_deref().unwrap()).unwrap();
    assert_eq!(
        text(&bundle, super::overlay::LAKE_SINK_FILE)
            .matches(pull::PULL_ORIGIN_MARKER)
            .count(),
        1
    );
    // Every placeholder the pull bundle interpolates reaches vector.env.
    for source in &out.pull_sources {
        let prefix = pull::env_prefix(source);
        assert!(
            with_pull
                .env
                .iter()
                .any(|(name, _)| name.starts_with(&prefix)),
            "{prefix}"
        );
    }
}

// -- shape of the pull bundle -----------------------------------------------------

#[test]
fn the_pull_bundle_carries_only_the_filtered_lanes_and_no_push_ingress() {
    let full_outcome = generate(tenant_sources(), Some(pulls()));
    let full = archive::unpack(full_outcome.bundle.as_deref().unwrap()).unwrap();
    let tree = pull_tree(&full_outcome);

    // Lanes: exactly the two pull slugs, byte-identical to the full bundle's.
    let lanes: BTreeSet<&str> = tree
        .files
        .keys()
        .filter(|p| p.contains(overlay::TENANT_PREFIX))
        .map(String::as_str)
        .collect();
    assert_eq!(
        lanes,
        BTreeSet::from([
            "sources/parsers/tenant__apache_access.toml",
            "sources/parsers/tenant__aws_cloudtrail.toml"
        ])
    );
    for lane in &lanes {
        assert_eq!(tree.file(lane), full.file(lane), "{lane}");
    }
    assert!(
        text(&tree, "sources/parsers/tenant__apache_access.toml").contains("override = \\\"v1\\\"")
            || text(&tree, "sources/parsers/tenant__apache_access.toml")
                .contains("override = \"v1\"")
    );

    // No push ingress, no audit plumbing, no enrichment lane, no docs.
    for gone in [
        overlay::HEC_FILE,
        "01-vector-source.toml",
        "03-otlp-source.toml",
        "04-otlp-lake-sink.toml",
        "06-cloudflare-direct-ingest.toml",
        platform_audit_lane::AUDIT_LANE_FILE,
        "sources/parsers/_enrichment.toml",
        "sources/configs/http_ingestion.toml",
        "sources/configs/splunk_hec.toml",
        "README.md",
        "backup/_router.toml",
    ] {
        assert!(
            tree.file(gone).is_none(),
            "{gone} must not be in the pull bundle"
        );
    }
    let everything = all_text(&tree);
    for push in [
        "[sources.http_ingest]",
        "[sources.splunk_hec_ingest]",
        "[sources.otlp_ingest]",
        "[sources.vector_native]",
        "[sources.enrichment_ingest]",
        "[sources.cloudflare_direct_ingest]",
        "nano_platform_audit",
    ] {
        assert!(!everything.contains(push), "{push} survived");
    }
    // The config dirs the container start copies still exist.
    assert!(tree.dirs.contains("sources/configs") && tree.dirs.contains("sources/parsers"));

    // Router: only the stamps feed it; only generic + the two tenant routes.
    let stamps: Vec<String> = pulls().iter().map(pull::stamp_component).collect();
    assert_eq!(
        inputs_of(&tree, overlay::ROUTER_FILE, "source_router"),
        stamps
    );
    let router = text(&tree, overlay::ROUTER_FILE);
    assert!(router.contains("tenant__aws_cloudtrail = '.source_type == \"aws_cloudtrail\"'"));
    assert!(
        router.contains("generic = '!includes([\"audit\", \"aws_cloudtrail\", \"apache_access\"]")
            || router.contains(
                "generic = '!includes([\"audit\", \"apache_access\", \"aws_cloudtrail\"]"
            ),
        "{router}"
    );
    // Lake prepare: generic + the two tenant lanes, not the audit lane.
    assert_eq!(
        inputs_of(&tree, overlay::LAKE_SINK_FILE, pull::LAKE_PREPARE),
        vec![
            "generic_ocsf_prepare",
            "tenant__apache_access_ocsf_prepare",
            "tenant__aws_cloudtrail_ocsf_prepare"
        ]
    );
    // Bronze sink + telemetry survive.
    assert!(text(&tree, overlay::LAKE_SINK_FILE).contains("[sinks.ocsf_parquet_bronze]"));
    assert!(everything.contains("[sinks.prometheus_metrics]"));
    assert!(everything.contains("[api]"));

    // Platform pull scaffolding: identity from the server row, acks on.
    let pulls_file = text(&tree, pull::PULL_SOURCES_FILE);
    for source in pulls() {
        let id = pull::source_component(&source);
        assert!(
            pulls_file.contains(&format!(
                "[sources.{id}]\ntype = \"{}\"",
                source.kind.as_str()
            )),
            "{pulls_file}"
        );
        assert!(pulls_file.contains(&format!(
            ".source_type = \"{}\"\n%source_type = \"{}\"",
            source.slug, source.slug
        )));
        assert!(pulls_file.contains(&format!(
            "%nano_credential_id = \"pull:{}\"",
            source.source_id.hyphenated()
        )));
    }
    assert!(pulls_file.contains(&format!(
        "%tenant_id = \"{}\"",
        Uuid::from_u128(TENANT_UUID).hyphenated()
    )));
    assert_eq!(
        pulls_file
            .matches("acknowledgements.enabled = true")
            .count(),
        2
    );
    assert!(pulls_file.contains("delete_failed_message = false"), "D-I");
    assert!(
        !pulls_file.contains("abort") && !pulls_file.contains("drop_on"),
        "the stamp can never drop an event"
    );
}

#[test]
fn every_pull_kind_renders_a_platform_source() {
    let all = vec![
        pull_source(1, "aws_cloudtrail", PullSourceKind::AwsS3),
        pull_source(2, "aws_cloudtrail", PullSourceKind::AwsSqs),
        pull_source(3, "apache_access", PullSourceKind::GcpPubsub),
        pull_source(4, "windows_sysmon", PullSourceKind::AzureEventHubs),
    ];
    let outcome = generate(tenant_sources(), Some(all.clone()));
    let tree = pull_tree(&outcome);
    let file = text(&tree, pull::PULL_SOURCES_FILE);
    assert!(file.contains("endpoint = \"http://aws.internal\""));
    assert!(file.contains("ack_deadline_secs = 600"));
    assert!(file.contains("type = \"azure_event_hubs\""));
    assert!(!file.contains("oauth.internal") && !file.contains("kafka"));
    assert_eq!(file.matches("acknowledgements.enabled = true").count(), 4);
    // Two pull sources may feed one lane; the lane is rendered once.
    assert_eq!(
        outcome.report.pull_bundle.as_ref().unwrap().lane_sources,
        vec!["apache_access", "aws_cloudtrail", "windows_sysmon"]
    );
    // The env names carry no tenant-controlled text, only the source id.
    let names: Vec<&str> = outcome
        .env
        .iter()
        .map(|(n, _)| n.as_str())
        .filter(|n| n.starts_with("NANO_PULL_"))
        .collect();
    assert!(
        names.iter().all(|n| n
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')),
        "{names:?}"
    );
}

// -- verification ------------------------------------------------------------------

#[test]
fn the_pull_bundle_verifies_against_its_filtered_base_and_nothing_else() {
    let uuid = Uuid::from_u128(TENANT_UUID);
    let (rendered, _) = pull::plan(&tenant_sources(), &pulls());
    let built = pull::build_pull_bundle(&base(), &tenant_sources(), &rendered, uuid, false).unwrap();
    let verified =
        overlay::verify_against_base_with(&built.base, &built.candidate, OverlayProfile::Pull)
            .unwrap();
    assert_eq!(
        verified
            .tenants
            .iter()
            .map(|t| t.slug.as_str())
            .collect::<Vec<_>>(),
        vec!["apache_access", "aws_cloudtrail"]
    );
    // The filtered base is deterministic.
    let again = pull::pull_base(&base(), &rendered, uuid, false).unwrap();
    assert_eq!(
        archive::pack(&again).unwrap(),
        archive::pack(&built.base).unwrap()
    );
    // The pull bundle is not a tenant bundle of the full base.
    assert!(overlay::verify_against_base(&base(), &built.candidate).is_err());

    // A platform byte changed (a pull source that would delete rejected batches).
    let mut tampered = built.candidate.clone();
    let file = text(&tampered, pull::PULL_SOURCES_FILE).replace(
        "delete_failed_message = false",
        "delete_failed_message = true",
    );
    tampered.put(pull::PULL_SOURCES_FILE, file.into_bytes());
    let rules: Vec<String> =
        overlay::verify_against_base_with(&built.base, &tampered, OverlayProfile::Pull)
            .unwrap_err()
            .into_iter()
            .map(|f| f.rule)
            .collect();
    assert!(
        rules.contains(&"platform_identical".to_string()),
        "{rules:?}"
    );

    // A push source smuggled in.
    let mut smuggled = built.candidate.clone();
    smuggled.put(
        overlay::HEC_FILE,
        base().file(overlay::HEC_FILE).unwrap().to_vec(),
    );
    assert!(
        overlay::verify_against_base_with(&built.base, &smuggled, OverlayProfile::Pull).is_err()
    );
}

#[test]
fn reserved_slugs_have_no_pull_lane() {
    for slug in ["audit", "otlp_log", "unknown"] {
        assert!(overlay::pull_slug_allowed(&base(), slug).is_err(), "{slug}");
    }
    assert!(overlay::pull_slug_allowed(&base(), "aws_cloudtrail").is_ok());
}

/// P0-5 acceptance: republishing the override of a pulled lane changes the
/// pull bundle; a change to a lane outside the filter changes only the
/// tenant bundle.
#[test]
fn pull_bundle_sha256_follows_only_the_filtered_lanes() {
    let sha_of = |sources: Vec<TenantSource>| {
        let outcome = generate(sources, Some(pulls()));
        (
            sha(outcome.bundle.as_deref().unwrap()),
            outcome.report.pull_bundle.unwrap().pull_bundle_sha256,
        )
    };
    let (full_a, pull_a) = sha_of(tenant_sources());
    let (full_b, pull_b) = sha_of(tenant_sources());
    assert_eq!((&full_a, &pull_a), (&full_b, &pull_b), "deterministic");

    let mut republished = tenant_sources();
    republished[1] = overridden("apache_access", "v2");
    let (full_c, pull_c) = sha_of(republished);
    assert_ne!(full_c, full_a);
    assert_ne!(pull_c, pull_a, "a pulled lane's override changed");

    let mut unrelated = tenant_sources();
    unrelated[2] = source("windows_sysmon", &OCSF_VRL.replace("acme", "other"));
    let (full_d, pull_d) = sha_of(unrelated);
    assert_ne!(full_d, full_a);
    assert_eq!(
        pull_d, pull_a,
        "a lane outside the filter must not move the pull bundle"
    );

    // The pull-source set is part of the bundle; its order is not.
    let mut reordered = pulls();
    reordered.reverse();
    let outcome = generate(tenant_sources(), Some(reordered));
    assert_eq!(
        outcome.report.pull_bundle.unwrap().pull_bundle_sha256,
        pull_a
    );
}

#[test]
fn pull_sources_without_a_lane_stay_pending() {
    let gcp = pull_source(0xb1, "gcp_audit", PullSourceKind::GcpPubsub);
    let only_pending = generate(tenant_sources(), Some(vec![gcp.clone()]));
    assert!(only_pending.pull_bundle.is_none() && only_pending.report.pull_bundle.is_none());
    assert_eq!(only_pending.report.pull_pending, vec![gcp.clone()]);

    let mut mixed = pulls();
    mixed.push(gcp.clone());
    let outcome = generate(tenant_sources(), Some(mixed));
    assert_eq!(outcome.report.pull_pending, vec![gcp]);
    let tree = pull_tree(&outcome);
    assert!(!all_text(&tree).contains("gcp_audit"));
}

#[test]
fn pull_requests_are_validated() {
    let bad = |pull: Vec<PullSource>| {
        let outcome = build::generate(&inputs(tenant_sources(), Some(pull)));
        assert!(!outcome.ok());
        outcome.report.failure.unwrap().message
    };
    let dup = pull_source(9, "aws_cloudtrail", PullSourceKind::AwsS3);
    assert!(bad(vec![dup.clone(), dup]).contains("unique"));
    assert!(bad(vec![pull_source(
        0,
        "aws_cloudtrail",
        PullSourceKind::AwsS3
    )])
    .contains("non-nil"));
    assert!(bad(vec![pull_source(9, "Bad Slug\"", PullSourceKind::AwsS3)]).contains("slugs"));
    let many: Vec<PullSource> = (1..=(MAX_PULL_SOURCES as u128 + 1))
        .map(|i| pull_source(i, "aws_cloudtrail", PullSourceKind::AwsSqs))
        .collect();
    assert!(bad(many).contains("too many"));
    // An unknown kind is refused at parse time.
    let mut json: serde_json::Value =
        serde_json::from_slice(&inputs(tenant_sources(), Some(pulls())).build_json).unwrap();
    json["pull_sources"][0]["kind"] = "http_client".into();
    let mut raw = inputs(tenant_sources(), None);
    raw.build_json = serde_json::to_vec(&json).unwrap();
    assert!(!build::generate(&raw).ok());
}

#[test]
fn a_base_without_an_acknowledged_bronze_sink_has_no_pull_bundle() {
    let mut no_acks = base();
    let sink =
        text(&no_acks, overlay::LAKE_SINK_FILE).replace("acknowledgements.enabled = true\n", "");
    no_acks.put(overlay::LAKE_SINK_FILE, sink.into_bytes());
    let error = pull::pull_base(&no_acks, &pulls(), Uuid::from_u128(TENANT_UUID), false).unwrap_err();
    assert!(error.to_string().contains("acknowledgements"), "{error}");
}

// -- R5: tenant VRL is never loaded from a path ---------------------------------

#[test]
fn a_tenant_transform_may_not_load_vrl_from_a_file() {
    let base = base();
    let (candidate, generated) =
        overlay::apply_overlay(&base, &[source("aws_cloudtrail", OCSF_VRL)]).unwrap();
    let tenant = &generated[0].tenant;
    let header = format!("[transforms.{}_parse]\n", tenant.name);
    for (key, line) in [
        (
            "file",
            "file = \"/etc/cloudflare/certs/cloudflare-containers-ca.crt\"\n",
        ),
        ("files", "files = [\"/etc/vector/00-base.toml\"]\n"),
    ] {
        let mut forged = candidate.clone();
        let edited = text(&forged, &tenant.file()).replacen(&header, &format!("{header}{line}"), 1);
        assert_ne!(
            edited,
            text(&forged, &tenant.file()),
            "the header is present"
        );
        forged.put(&tenant.file(), edited.into_bytes());
        let findings = overlay::verify_against_base(&base, &forged).unwrap_err();
        assert!(
            findings
                .iter()
                .any(|f| f.rule == "vrl_file" && f.message.contains(key)),
            "{key}: {findings:?}"
        );
    }
}

// -- finalize --------------------------------------------------------------------

#[test]
fn finalize_requires_the_pull_bundle_to_validate() {
    let outcome = generate(tenant_sources(), Some(pulls()));
    let finalize = |pull_rc: Option<i32>, pull: Option<&[u8]>| {
        build::finalize_report_with_pull(
            outcome.report.clone(),
            &passing_vector(&outcome.report, pull_rc),
            &build::SandboxProbe::default(),
            outcome.bundle.as_deref(),
            pull,
            Some(DIGEST),
        )
    };
    let passed = finalize(Some(0), outcome.pull_bundle.as_deref());
    assert_eq!(passed.verdict, Verdict::Passed, "{:?}", passed.failure);
    assert!(passed.pull_bundle.is_some());
    let check = passed
        .checks
        .iter()
        .find(|c| c.name == "vector_validate_pull")
        .unwrap();
    assert_eq!(check.status, CheckStatus::Passed);

    let failed = finalize(Some(78), outcome.pull_bundle.as_deref());
    assert_eq!(failed.verdict, Verdict::Failed);
    assert!(failed
        .failure
        .as_ref()
        .unwrap()
        .message
        .starts_with("pull bundle: "));
    assert!(
        failed.pull_bundle.is_none() && failed.bundle.is_none(),
        "nothing unvalidated reaches signing"
    );

    let missing = finalize(None, outcome.pull_bundle.as_deref());
    assert!(missing
        .failure
        .unwrap()
        .message
        .contains("no pull bundle validate result"));

    let swapped = finalize(Some(0), Some(b"not the generated bytes"));
    assert!(swapped
        .failure
        .unwrap()
        .message
        .contains("pull-bundle.tar.gz changed"));

    // A build without pull sources gets no pull check at all.
    let plain = generate(tenant_sources(), None);
    let report = build::finalize_report(
        plain.report.clone(),
        &passing_vector(&plain.report, None),
        plain.bundle.as_deref(),
        Some(DIGEST),
    );
    assert_eq!(report.verdict, Verdict::Passed);
    assert!(report
        .checks
        .iter()
        .all(|c| c.name != "vector_validate_pull"));
}

#[test]
fn the_job_stages_write_and_frame_the_pull_bundle() {
    let dir = tempfile::tempdir().unwrap();
    let (input, work, results, out) = (
        dir.path().join("in"),
        dir.path().join("work"),
        dir.path().join("res"),
        dir.path().join("out"),
    );
    std::fs::create_dir_all(&input).unwrap();
    let raw = inputs(tenant_sources(), Some(pulls()));
    std::fs::write(input.join(build::BUILD_FILE), &raw.build_json).unwrap();
    std::fs::write(input.join(build::SOURCES_FILE), &raw.sources_json).unwrap();
    std::fs::write(input.join(build::BASE_FILE), &raw.base).unwrap();
    let outcome = build::run_generate(&input, &work).unwrap();
    assert!(outcome.ok());
    let pull_bytes = std::fs::read(work.join(build::PULL_BUNDLE_FILE)).unwrap();
    let env = std::fs::read_to_string(work.join(build::ENV_FILE)).unwrap();
    assert!(env.contains("NANO_PULL_"), "{env}");

    std::fs::create_dir_all(&results).unwrap();
    for (name, value) in [
        ("egress.txt", "blocked"),
        ("version.txt", "vector 0.59.0"),
        ("validate.rc", "0"),
        ("validate.out", "Validated"),
        ("test.rc", "0"),
        ("test.out", ""),
        ("pull-validate.rc", "0"),
        ("pull-validate.out", "Validated"),
    ] {
        std::fs::write(results.join(name), value).unwrap();
    }
    let mut stdout = Vec::new();
    let summary =
        build::run_finalize(&work, &results, &out, None, Some(DIGEST), &mut stdout).unwrap();
    assert_eq!(summary.verdict, Verdict::Passed);
    assert_eq!(
        std::fs::read(out.join(build::PULL_BUNDLE_FILE)).unwrap(),
        pull_bytes
    );
    let log = String::from_utf8(stdout).unwrap();
    assert!(log.contains(&format!("\"path\":\"{}\"", build::PULL_BUNDLE_FILE)));
    assert!(log
        .lines()
        .last()
        .unwrap()
        .starts_with(build::LOG_RESULT_PREFIX));
}

// -- NAN-3288 P0 spike findings (NAN-3371 / NAN-3372 / NAN-3368) -----------------

/// The `[sources.<id>.sqs]` table of one rendered pull source.
fn sqs_table(file: &str, source: &PullSource) -> toml::Table {
    let neutral = file.replace("${", "_{");
    let table: toml::Table = neutral.parse().unwrap();
    table["sources"][&pull::source_component(source)]["sqs"]
        .as_table()
        .unwrap()
        .clone()
}

/// The stamp remap's VRL of one rendered pull source.
fn stamp_vrl(file: &str, source: &PullSource) -> String {
    let neutral = file.replace("${", "_{");
    let table: toml::Table = neutral.parse().unwrap();
    table["transforms"][&pull::stamp_component(source)]["source"]
        .as_str()
        .unwrap()
        .to_string()
}

/// P0-2 finding 2: `aws_s3` handles one receive serially, so the pollers are
/// the parallelism; one message per receive keeps a stuck object from holding
/// others. Defaults 4 / 1, explicit values within 1-8 / 1-2 render as given.
#[test]
fn aws_s3_renders_sqs_client_concurrency_and_messages_per_receive() {
    let defaulted = pull_source(0xa1, "aws_cloudtrail", PullSourceKind::AwsS3);
    let mut tuned = pull_source(0xa3, "apache_access", PullSourceKind::AwsS3);
    tuned.sqs_client_concurrency = Some(8);
    tuned.sqs_max_number_of_messages = Some(2);
    let sqs_only = pull_source(0xa2, "apache_access", PullSourceKind::AwsSqs);
    let outcome = generate(
        tenant_sources(),
        Some(vec![defaulted.clone(), tuned.clone(), sqs_only.clone()]),
    );
    let tree = pull_tree(&outcome);
    let file = text(&tree, pull::PULL_SOURCES_FILE);

    let sqs = sqs_table(file, &defaulted);
    assert_eq!(sqs["client_concurrency"].as_integer(), Some(4));
    assert_eq!(sqs["max_number_of_messages"].as_integer(), Some(1));
    assert_eq!(sqs["delete_failed_message"].as_bool(), Some(false));
    let sqs = sqs_table(file, &tuned);
    assert_eq!(sqs["client_concurrency"].as_integer(), Some(8));
    assert_eq!(sqs["max_number_of_messages"].as_integer(), Some(2));
    // aws_sqs has no `sqs` table and is untouched.
    let neutral: toml::Table = file.replace("${", "_{").parse().unwrap();
    let plain = neutral["sources"][&pull::source_component(&sqs_only)]
        .as_table()
        .unwrap();
    assert!(!plain.contains_key("client_concurrency") && !plain.contains_key("sqs"));

    // The tuning is part of the request identity only when set: an untuned
    // request serializes exactly as before.
    let request: serde_json::Value =
        serde_json::from_slice(&inputs(tenant_sources(), Some(pulls())).build_json).unwrap();
    assert!(request["pull_sources"][0]
        .get("sqs_client_concurrency")
        .is_none());
    assert!(request["pull_sources"][0]
        .get("sqs_max_number_of_messages")
        .is_none());
}

#[test]
fn sqs_tuning_out_of_range_or_on_another_kind_is_refused() {
    let refused = |pull: PullSource| {
        let outcome = build::generate(&inputs(tenant_sources(), Some(vec![pull.clone()])));
        assert!(!outcome.ok(), "{pull:?}");
        let message = outcome.report.failure.unwrap().message;
        assert!(message.contains("SQS tuning"), "{message}");
        // The filtered-base derivation refuses it on its own, too.
        assert!(pull::pull_base(&base(), &[pull], Uuid::from_u128(TENANT_UUID), false).is_err());
    };
    let s3 = || pull_source(0xa1, "aws_cloudtrail", PullSourceKind::AwsS3);
    for (concurrency, messages) in [
        (Some(0), None),
        (Some(9), None),
        (None, Some(0)),
        (None, Some(3)),
    ] {
        let mut p = s3();
        p.sqs_client_concurrency = concurrency;
        p.sqs_max_number_of_messages = messages;
        refused(p);
    }
    for kind in [
        PullSourceKind::AwsSqs,
        PullSourceKind::GcpPubsub,
        PullSourceKind::AzureEventHubs,
    ] {
        let mut p = pull_source(0xa1, "aws_cloudtrail", kind);
        p.sqs_client_concurrency = Some(2);
        refused(p);
    }
    let mut ok = s3();
    ok.sqs_client_concurrency = Some(1);
    ok.sqs_max_number_of_messages = Some(2);
    generate(tenant_sources(), Some(vec![ok]));
}

/// P0-2 finding 1: CloudTrail delivers `{"Records": [...]}` files; the lane
/// takes one record per `.message` (as on push), so the platform stamp
/// unnests, after the identity lines, only for `aws_s3` + `aws_cloudtrail`.
/// Digest files are not events. No abort or error path is added.
#[test]
fn the_cloudtrail_stamp_unnests_records_and_skips_digest_files() {
    let s3_trail = pull_source(0xa1, "aws_cloudtrail", PullSourceKind::AwsS3);
    let sqs_trail = pull_source(0xa2, "aws_cloudtrail", PullSourceKind::AwsSqs);
    let s3_other = pull_source(0xa3, "apache_access", PullSourceKind::AwsS3);
    assert_eq!(
        pull::envelope(&s3_trail),
        Some(pull::PullEnvelope::CloudTrailRecords)
    );
    assert_eq!(pull::envelope(&sqs_trail), None);
    assert_eq!(pull::envelope(&s3_other), None);

    let outcome = generate(
        tenant_sources(),
        Some(vec![s3_trail.clone(), sqs_trail.clone(), s3_other.clone()]),
    );
    let tree = pull_tree(&outcome);
    let file = text(&tree, pull::PULL_SOURCES_FILE);
    let vrl = stamp_vrl(file, &s3_trail);
    let identity = vrl.find("%nano_credential_id").unwrap();
    let unnest = vrl
        .find("map_values(nano_pull_records)")
        .expect("records unnest");
    assert!(identity < unnest, "identity is stamped before the split");
    assert!(vrl.contains("is_array(nano_pull_envelope.Records)"));
    let digest = pull::CLOUDTRAIL_DIGEST_SEGMENT;
    assert!(vrl.contains(&format!("\"{digest}\"")) && vrl.contains(&format!("\"/{digest}\"")));
    assert!(vrl.contains("  . = []\n"), "digest files emit no event");
    assert!(
        vrl.contains("del(.message)"),
        "the file body is not copied per record"
    );
    for other in [&sqs_trail, &s3_other] {
        assert!(!stamp_vrl(file, other).contains("Records"), "{other:?}");
    }
    assert!(
        !file.contains("abort") && !file.contains("drop_on") && !file.contains("!("),
        "the stamp has no abort or raising call"
    );
}

/// P0-2 / P0-3: the loss fence must not alarm on `discarded > 0` alone; the
/// pull bundle exports exactly the counters it needs on a small exporter.
#[test]
fn the_pull_bundle_exports_the_loss_fence_counters_on_their_own_exporter() {
    let outcome = generate(tenant_sources(), Some(pulls()));
    let tree = pull_tree(&outcome);
    let file = text(&tree, pull::PULL_SOURCES_FILE);
    let table: toml::Table = file.replace("${", "_{").parse().unwrap();
    assert_eq!(
        table["sources"][pull::PULL_LOSS_SOURCE]["type"].as_str(),
        Some("internal_metrics")
    );
    let select = &table["transforms"][pull::PULL_LOSS_SELECT];
    assert_eq!(select["type"].as_str(), Some("filter"));
    let condition = select["condition"].as_str().unwrap();
    for counter in [
        "component_discarded_events_total",
        "component_received_events_total",
        "component_sent_events_total",
        "sqs_message_received_messages_total",
        "sqs_message_delete_succeeded_total",
    ] {
        assert!(condition.contains(counter), "{counter}");
    }
    assert!(condition.contains(&format!("\"{}\"", pull::BRONZE_SINK)));
    // NAN-3381: the pull Worker's scrape marker (liveness on an idle tenant).
    assert!(condition.contains(&format!(
        "component == \"{}\" && .name == \"component_sent_events_total\"",
        pull::PULL_LOSS_SOURCE
    )));
    let exporter = &table["sinks"][pull::PULL_LOSS_EXPORTER];
    assert_eq!(exporter["type"].as_str(), Some("prometheus_exporter"));
    assert_eq!(
        exporter["address"].as_str(),
        Some(pull::PULL_LOSS_EXPORTER_ADDRESS)
    );
    assert!(file.contains(pull::LOSS_FENCE_CONTRACT));
    assert_eq!(file.matches("[sinks.").count(), 1);
}

/// P0-4: `host_metrics` (its `process` collector) is never in a pull bundle,
/// and the Bronze sink's retry backoff cap must be high enough that a stalled
/// edge log is not re-sent every few seconds (retries are metered egress).
#[test]
fn host_metrics_is_pruned_and_a_low_bronze_backoff_cap_is_refused() {
    let mut with_host = base();
    with_host.put(
        "95-host-metrics.toml",
        b"[sources.host_telemetry]\ntype = \"host_metrics\"\ncollectors = [\"process\", \"cpu\"]\n\n\
[transforms.host_telemetry_tag]\ntype = \"remap\"\ninputs = [\"host_telemetry\"]\nsource = '.tags.x = \"y\"'\n\n\
[sinks.host_telemetry_exporter]\ntype = \"prometheus_exporter\"\ninputs = [\"host_telemetry_tag\"]\naddress = \"0.0.0.0:9600\"\n"
            .to_vec(),
    );
    let filtered = pull::pull_base(&with_host, &pulls(), Uuid::from_u128(TENANT_UUID), false).unwrap();
    let everything = all_text(&filtered);
    assert!(!everything.contains("host_metrics") && !everything.contains("host_telemetry"));
    assert!(filtered.file("95-host-metrics.toml").is_none());

    let sink = text(&base(), overlay::LAKE_SINK_FILE).to_string();
    assert!(sink.contains("retry_max_duration_secs = 300\n"));
    let mut low = base();
    low.put(
        overlay::LAKE_SINK_FILE,
        sink.replace(
            "retry_max_duration_secs = 300\n",
            "retry_max_duration_secs = 8\n",
        )
        .into_bytes(),
    );
    let error = pull::pull_base(&low, &pulls(), Uuid::from_u128(TENANT_UUID), false).unwrap_err();
    assert!(
        error.to_string().contains("retry_max_duration_secs"),
        "{error}"
    );
}

/// D-L: the GCP token contract is recorded where the source renders.
#[test]
fn gcp_pubsub_records_the_one_hour_token_contract() {
    assert_eq!(pull::GCP_PUBSUB_TOKEN_LIFETIME_SECS, 3600);
    let gcp = pull_source(3, "apache_access", PullSourceKind::GcpPubsub);
    let outcome = generate(tenant_sources(), Some(vec![gcp]));
    let file = text(&pull_tree(&outcome), pull::PULL_SOURCES_FILE).to_string();
    assert!(file.contains("3600 s tokens (D-L)"), "{file}");
}

/// NAN-3604 (DESIGN §5/§9): an Event Hubs source renders the fork's native
/// AMQP source with managed-identity auth (client id from env) for both the
/// source and the customer's blob checkpoint store, acks on, bytes decoding,
/// and nothing that could redirect it or carry a secret.
#[test]
fn an_event_hubs_source_renders_the_native_amqp_source_with_keyless_auth() {
    let hub = pull_source(
        0x00e4_0000_0000_4000_8000_0000_0000_00a2,
        "windows_sysmon",
        PullSourceKind::AzureEventHubs,
    );
    assert_eq!(hub.kind.as_str(), "azure_event_hubs");
    assert_eq!(
        serde_json::to_value(hub.kind).unwrap(),
        serde_json::json!("azure_event_hubs")
    );
    let outcome = generate(tenant_sources(), Some(vec![hub.clone()]));
    let tree = pull_tree(&outcome);
    let file = text(&tree, pull::PULL_SOURCES_FILE);
    let id = pull::source_component(&hub);
    let env = pull::env_prefix(&hub);
    assert_eq!(env, "NANO_PULL_00E400000000400080000000000000A2_");
    let start = file.find(&format!("[sources.{id}]\n")).unwrap();
    let end = file.find(&format!("[transforms.{id}_stamp]")).unwrap();
    let source = &file[start..end];
    let expected = format!(
        "[sources.{id}]\n\
         type = \"azure_event_hubs\"\n\
         # Token: entra.internal managed-identity handler (http://entra.internal/msi/token).\n\
         namespace = \"${{{env}EH_NAMESPACE}}\"\n\
         event_hub_name = \"${{{env}EH_NAME}}\"\n\
         consumer_group = \"${{{env}EH_CONSUMER_GROUP}}\"\n\
         start_position = \"latest\"\n\
         checkpoint_interval_secs = 5\n\
         acknowledgements.enabled = true\n\
         decoding.codec = \"bytes\"\n\
         framing.method = \"bytes\"\n\
         \n\
         [sources.{id}.auth]\n\
         azure_credential_kind = \"managed_identity\"\n\
         user_assigned_managed_identity_id = \"${{{env}AZURE_CLIENT_ID}}\"\n\
         user_assigned_managed_identity_id_type = \"client_id\"\n\
         \n\
         [sources.{id}.checkpoint_store]\n\
         type = \"azure_blob\"\n\
         account_name = \"${{{env}CHECKPOINT_ACCOUNT}}\"\n\
         container_name = \"${{{env}CHECKPOINT_CONTAINER}}\"\n\
         \n\
         [sources.{id}.checkpoint_store.auth]\n\
         azure_credential_kind = \"managed_identity\"\n\
         user_assigned_managed_identity_id = \"${{{env}AZURE_CLIENT_ID}}\"\n\
         user_assigned_managed_identity_id_type = \"client_id\"\n\
         \n"
    );
    assert_eq!(source, expected);
    // It parses as TOML with exactly these tables.
    let parsed: toml::Value = toml::from_str(file).unwrap();
    let rendered = &parsed["sources"][id.as_str()];
    assert_eq!(
        rendered["auth"]["azure_credential_kind"].as_str(),
        Some("managed_identity")
    );
    assert_eq!(
        rendered["checkpoint_store"]["type"].as_str(),
        Some("azure_blob")
    );
    // NAN-3604: point-forward; never the hub's whole retention.
    assert_eq!(rendered["start_position"].as_str(), Some("latest"));
    assert!(!file.contains("earliest"), "{file}");
    // No redirect, no secret, no other Azure auth mode.
    let lower = source.to_ascii_lowercase();
    for forbidden in [
        "custom_endpoint",
        "connection_string",
        "blob_endpoint",
        "secret",
        "sharedaccess",
        "client_assertion",
        "workload_identity",
        "token_file",
        "proxy",
        "servicebus.windows.net",
        "blob.core.windows.net",
        "kafka",
        "oauth.internal",
        "9093",
    ] {
        assert!(!lower.contains(forbidden), "{forbidden}: {source}");
    }
    // The stamp names the kind and unpacks the Azure Monitor envelope.
    assert!(file.contains(".content_format = \"nano_pull_azure_event_hubs\""));
    assert_eq!(pull::envelope(&hub), Some(pull::PullEnvelope::AzureRecords));
    // Env coordinates are exactly the §9 names (placeholders at build time).
    let mut names: Vec<&str> = outcome
        .env
        .iter()
        .map(|(n, _)| n.as_str())
        .filter(|n| n.starts_with("NANO_PULL_"))
        .collect();
    names.sort_unstable();
    let mut want: Vec<String> = [
        "AZURE_CLIENT_ID",
        "CHECKPOINT_ACCOUNT",
        "CHECKPOINT_CONTAINER",
        "EH_CONSUMER_GROUP",
        "EH_NAME",
        "EH_NAMESPACE",
    ]
    .iter()
    .map(|suffix| format!("{env}{suffix}"))
    .collect();
    want.sort_unstable();
    assert_eq!(names, want);
    // SQS tuning on an Event Hubs source is refused.
    let mut tuned = hub;
    tuned.sqs_client_concurrency = Some(2);
    assert!(!build::generate(&inputs(tenant_sources(), Some(vec![tuned]))).ok());
}

/// The bundle's kind is the build.json wire name; `kafka` no longer exists.
#[test]
fn the_kafka_pull_kind_is_gone() {
    assert!(serde_json::from_value::<PullSourceKind>(serde_json::json!("kafka")).is_err());
    assert_eq!(
        serde_json::from_value::<PullSourceKind>(serde_json::json!("azure_event_hubs")).unwrap(),
        PullSourceKind::AzureEventHubs
    );
}

/// Run a stamp's VRL on one source event (legacy namespace), as the remap
/// would: returns the resulting root (an array = that many events) and the
/// metadata the stamp set.
pub(super) fn run_stamp(vrl: &str, event: serde_json::Value) -> (serde_json::Value, serde_json::Value) {
    use vrl::compiler::runtime::Runtime;
    use vrl::compiler::state::RuntimeState;
    use vrl::compiler::{TargetValue, TimeZone};
    use vrl::value::{Secrets, Value};
    let program = vrl::compiler::compile(vrl, &vrl::stdlib::all())
        .unwrap_or_else(|e| panic!("{e:?}"))
        .program;
    let mut target = TargetValue {
        value: Value::from(event),
        metadata: Value::Object(Default::default()),
        secrets: Secrets::new(),
    };
    Runtime::new(RuntimeState::default())
        .resolve(&mut target, &program, &TimeZone::Local)
        .unwrap();
    let json = |v: Value| serde_json::to_value(v).unwrap();
    (json(target.value), json(target.metadata))
}

/// NAN-3604 (parsers lane, absorbs #6184): Event Hubs delivers Diagnostic
/// Settings exports as one `{"records": [...]}` batch per message (a bare
/// JSON array is a batch too) and the lane takes one record per `.message`,
/// so the stamp of every Event Hubs source explodes the batch after the
/// identity lines. A hub routinely mixes categories (Activity Log + Entra ID
/// sign-in/audit); each record keeps its own body for the lane to dispatch
/// on. Other top-level keys beside `records` are dropped. Nothing that is not
/// a batch is altered, and nothing can abort.
#[test]
fn the_event_hubs_stamp_explodes_azure_monitor_records() {
    let hub = pull_source(0xe4, "azure_monitor", PullSourceKind::AzureEventHubs);
    let signin = pull_source(0xe5, "azure_signin", PullSourceKind::AzureEventHubs);
    let s3_other = pull_source(0xe6, "apache_access", PullSourceKind::AwsS3);
    assert_eq!(pull::envelope(&s3_other), None);
    let mut sources = tenant_sources();
    for slug in ["azure_monitor", "azure_signin"] {
        sources.push(source(slug, OCSF_VRL));
    }
    let outcome = generate(sources, Some(vec![hub.clone(), signin.clone()]));
    assert_eq!(
        outcome.report.pull_bundle.as_ref().unwrap().lane_sources,
        vec!["azure_monitor", "azure_signin"]
    );
    let file = text(&pull_tree(&outcome), pull::PULL_SOURCES_FILE).to_string();
    let vrl = stamp_vrl(&file, &hub);
    // Every Event Hubs lane gets the envelope, whatever its slug.
    assert!(stamp_vrl(&file, &signin).contains("map_values(nano_pull_records)"));
    let identity = vrl.find("%nano_credential_id").unwrap();
    assert!(identity < vrl.find("map_values(nano_pull_records)").unwrap());
    assert!(
        !vrl.contains("abort") && !vrl.contains("!("),
        "no abort or raising call"
    );

    let message = |body: &str| {
        serde_json::json!({
            "message": body, "event_hub_name": "insights-activity", "partition_id": "3",
            "offset": "4294967296", "sequence_number": 17, "enqueued_time": "2026-10-11T22:00:00Z",
            "source_type": "azure_event_hubs"
        })
    };
    let source_fields = [
        "event_hub_name",
        "partition_id",
        "offset",
        "sequence_number",
        "enqueued_time",
    ];
    let check_stamped = |event: &serde_json::Value| {
        for field in source_fields {
            assert_eq!(event[field], message("")[field], "{field}");
        }
        assert_eq!(event["source_type"], "azure_monitor");
        assert_eq!(event["metadata"]["forwarded_via"], "pull");
        assert_eq!(event["content_format"], "nano_pull_azure_event_hubs");
    };
    let events_of = |root: serde_json::Value| -> Vec<serde_json::Value> {
        root.as_array()
            .expect("an array root = one event per record")
            .clone()
    };

    // #6184's mixed batch: Activity Log + Entra sign-in + Entra audit.
    let activity = serde_json::json!({"time": "2026-10-11T14:02:31.3810679Z", "category": "Administrative",
        "operationName": "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/WRITE", "resultType": "Success",
        "resourceId": "/SUBSCRIPTIONS/BBBB1B1B-CC2C-DD3D-EE4E-FFFFFF5F5F5F/RESOURCEGROUPS/RG/PROVIDERS/MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/NSG"});
    let signin_record = serde_json::json!({"time": "2026-10-11T15:00:00Z", "category": "SignInLogs", "resultType": "50126",
        "properties": {"userPrincipalName": "alice@contoso.com", "ipAddress": "198.51.100.66", "status": {"errorCode": 50126}}});
    let audit = serde_json::json!({"time": "2026-10-11T16:10:00Z", "category": "AuditLogs",
        "properties": {"activityDisplayName": "Add member to group", "category": "GroupManagement"}});
    let records = vec![activity.clone(), signin_record.clone(), audit.clone()];
    let (root, metadata) = run_stamp(
        &vrl,
        message(&serde_json::json!({ "records": records }).to_string()),
    );
    let events = events_of(root);
    assert_eq!(events.len(), 3);
    for (event, record) in events.iter().zip(&records) {
        let body: serde_json::Value =
            serde_json::from_str(event["message"].as_str().unwrap()).unwrap();
        assert_eq!(&body, record);
        check_stamped(event);
    }
    assert_eq!(
        metadata["nano_credential_id"],
        format!("pull:{}", hub.source_id.hyphenated())
    );
    assert_eq!(metadata["source_type"], "azure_monitor");

    // Any element: a string is kept as is, anything else is its JSON.
    let (root, _) = run_stamp(
        &vrl,
        message(r#"{"records":[{"operationName":"B"},"raw",7]}"#),
    );
    let bodies: Vec<String> = events_of(root)
        .iter()
        .map(|e| e["message"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(bodies, vec![r#"{"operationName":"B"}"#, "raw", "7"]);

    // A bare JSON array is a batch too.
    let bare = serde_json::json!([activity, "plain text record"]).to_string();
    let (root, _) = run_stamp(&vrl, message(&bare));
    let events = events_of(root);
    assert_eq!(events.len(), 2);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(events[0]["message"].as_str().unwrap()).unwrap(),
        activity
    );
    assert_eq!(events[1]["message"], "plain text record");
    events.iter().for_each(check_stamped);

    // Extra top-level keys beside `records`: the records split, the extra
    // keys are dropped (they are not events).
    let extra = serde_json::json!({ "records": [audit], "operationName": "x", "tenantId": "t" });
    let (root, _) = run_stamp(&vrl, message(&extra.to_string()));
    let events = events_of(root);
    assert_eq!(events.len(), 1);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(events[0]["message"].as_str().unwrap()).unwrap(),
        audit
    );
    assert!(events[0].get("operationName").is_none() && events[0].get("tenantId").is_none());
    check_stamped(&events[0]);

    // An empty batch (envelope or bare array): zero events, acked not lost.
    for body in [r#"{"records":[]}"#, "[]"] {
        let (root, _) = run_stamp(&vrl, message(body));
        assert_eq!(root, serde_json::json!([]), "{body}");
    }

    // Not a batch: one event each, the body untouched (the lane decides).
    let single = signin_record.to_string();
    for body in [
        single.as_str(),
        r#"{"records":"not-an-array"}"#,
        "{\"records\": [ truncated mid-batch",
        "not json {",
        "",
        "7",
    ] {
        let (root, metadata) = run_stamp(&vrl, message(body));
        assert!(root.is_object(), "{body}: {root}");
        assert_eq!(root["message"], body);
        check_stamped(&root);
        assert_eq!(
            metadata["nano_credential_id"],
            format!("pull:{}", hub.source_id.hyphenated())
        );
    }
}

/// NAN-3604 follow-up: one Event Hubs message fans out to at most
/// `AZURE_RECORDS_CAP` record events plus one truncation event, and the
/// message's application `properties` (unbounded, customer-set) are not
/// copied into every record.
#[test]
fn the_event_hubs_stamp_caps_records_and_does_not_copy_properties() {
    let hub = pull_source(0xe7, "azure_monitor", PullSourceKind::AzureEventHubs);
    let mut sources = tenant_sources();
    sources.push(source("azure_monitor", OCSF_VRL));
    let outcome = generate(sources, Some(vec![hub.clone()]));
    let file = text(&pull_tree(&outcome), pull::PULL_SOURCES_FILE).to_string();
    let vrl = stamp_vrl(&file, &hub);
    let cap = pull::AZURE_RECORDS_CAP;
    assert_eq!(cap, 10_000);
    assert!(vrl.contains(&format!("nano_pull_total > {cap}\n")), "{vrl}");
    assert!(
        !vrl.contains("abort") && !vrl.contains("!("),
        "no abort or raising call"
    );

    let message = |body: String| {
        serde_json::json!({
            "message": body, "event_hub_name": "insights-activity", "partition_id": "3",
            "offset": "4294967296", "sequence_number": 17, "enqueued_time": "2026-10-11T22:00:00Z",
            "partition_key": "pk", "source_type": "azure_event_hubs",
            "properties": { "big": "x".repeat(4096), "n": 1 }
        })
    };
    let batch = |n: usize| {
        let records: Vec<serde_json::Value> =
            (0..n).map(|i| serde_json::json!({ "i": i })).collect();
        serde_json::json!({ "records": records }).to_string()
    };
    let check_record = |event: &serde_json::Value, i: usize| {
        assert_eq!(event["message"], format!("{{\"i\":{i}}}"));
        assert!(event.get("properties").is_none(), "properties copied: {i}");
        assert!(event.get("nano_pull_error").is_none());
        assert_eq!(event["partition_key"], "pk");
        assert_eq!(event["sequence_number"], 17);
        assert_eq!(event["source_type"], "azure_monitor");
    };

    // Exactly at the cap: every record, no truncation event.
    let (root, _) = run_stamp(&vrl, message(batch(cap)));
    let events = root.as_array().unwrap();
    assert_eq!(events.len(), cap);
    for (i, event) in events.iter().enumerate() {
        check_record(event, i);
    }

    // Over the cap: the first `cap` records, then ONE truncation event that
    // carries the stamp and the original count.
    let (root, metadata) = run_stamp(&vrl, message(batch(cap + 7)));
    let events = root.as_array().unwrap();
    assert_eq!(events.len(), cap + 1);
    for (i, event) in events[..cap].iter().enumerate() {
        check_record(event, i);
    }
    let marker = &events[cap];
    assert_eq!(marker["nano_pull_error"], "azure_records_truncated");
    assert_eq!(marker["nano_pull_records_total"], cap + 7);
    assert_eq!(marker["nano_pull_records_cap"], cap);
    assert!(marker.get("properties").is_none());
    assert_eq!(marker["event_hub_name"], "insights-activity");
    assert_eq!(marker["metadata"]["forwarded_via"], "pull");
    let body: serde_json::Value =
        serde_json::from_str(marker["message"].as_str().unwrap()).unwrap();
    assert_eq!(
        body,
        serde_json::json!({ "nano_pull_error": "azure_records_truncated",
            "records_total": cap + 7, "records_kept": cap })
    );
    assert_eq!(
        metadata["nano_credential_id"],
        format!("pull:{}", hub.source_id.hyphenated())
    );

    // A bare array over the cap is capped the same way.
    let bare: Vec<serde_json::Value> = (0..cap + 1)
        .map(|i| serde_json::json!({ "i": i }))
        .collect();
    let (root, _) = run_stamp(&vrl, message(serde_json::json!(bare).to_string()));
    let events = root.as_array().unwrap();
    assert_eq!(events.len(), cap + 1);
    assert_eq!(events[cap]["nano_pull_records_total"], cap + 1);

    // Not a batch: one event, properties kept (they are not duplicated).
    let (root, _) = run_stamp(&vrl, message("{\"category\":\"x\"}".into()));
    assert!(root.is_object());
    assert_eq!(root["properties"]["n"], 1);
}

/// NAN-3653: with the origin stamp (which `build::generate` always applies),
/// every pulled row carries the pull delivery it came through as an OCSF
/// `metadata.loggers` entry that passes the lake's strict OCSF 1.9 check;
/// without it the bundle is byte-identical to before (what an older builder
/// emitted, and what the verifier rederives for a report without
/// `pull_origin`).
#[test]
fn pull_origin_stamps_metadata_loggers_and_is_off_by_default() {
    use super::overlay::LAKE_SINK_FILE;
    let uuid = Uuid::from_u128(TENANT_UUID);
    let mut pulls = pulls();
    pulls.push(pull_source(0xa3, "aws_cloudtrail", PullSourceKind::GcpPubsub));
    let (rendered, _) = pull::plan(&tenant_sources(), &pulls);
    let off = pull::build_pull_bundle(&base(), &tenant_sources(), &rendered, uuid, false).unwrap();
    let off_with =
        pull::build_pull_bundle_with(&base(), &tenant_sources(), &rendered, uuid, false, false).unwrap();
    assert_eq!(archive::pack(&off.candidate).unwrap(), archive::pack(&off_with.candidate).unwrap());
    assert!(!text(&off.candidate, LAKE_SINK_FILE).contains(pull::PULL_ORIGIN_MARKER));

    let on = pull::build_pull_bundle_with(&base(), &tenant_sources(), &rendered, uuid, false, true).unwrap();
    assert_eq!(text(&on.candidate, LAKE_SINK_FILE).matches(pull::PULL_ORIGIN_MARKER).count(), 1);
    // Only the lake sink file differs, and the bundle still verifies.
    for (path, bytes) in &off.candidate.files {
        if path != LAKE_SINK_FILE {
            assert_eq!(on.candidate.file(path).unwrap(), bytes.as_slice(), "{path}");
        }
    }
    overlay::verify_against_base_with(&on.base, &on.candidate, OverlayProfile::Pull).unwrap();
    // Stamping twice is refused.
    assert!(pull::stamp_pull_origin(text(&on.candidate, LAKE_SINK_FILE), &rendered).is_err());

    let storage = super::platform_audit_lane::storage_prepare_vrl(&on.candidate).unwrap();
    let event = serde_json::json!({
        "class_uid": 6003, "category_uid": 6, "activity_id": 99, "type_uid": 600399, "severity_id": 1,
        "time": 1_700_000_000_000i64, "message": "m", "api": {"operation": "Unknown"},
        "cloud": {"provider": "AWS"}, "actor": {"user": {"name": "unknown"}}, "src_endpoint": {"ip": "0.0.0.0"},
        "metadata": {"version": "1.9.0", "profiles": ["cloud"], "product": {"name": "AWS CloudTrail", "vendor_name": "Amazon"},
                     "loggers": [{"name": "lane logger"}]},
    });
    let tenant = uuid.hyphenated().to_string();
    let run = |credential: &str| -> serde_json::Value {
        let meta = [("tenant_id", tenant.as_str()), ("source_type", "aws_cloudtrail"), ("nano_credential_id", credential)];
        let row = super::bronze_row_contract::run_vrl(&storage, vrl::value::Value::from(event.clone()), &meta).unwrap();
        let row = serde_json::to_value(&row).unwrap();
        let mut decoded: serde_json::Value = match row.get(crate::parsers::lake_bronze_row::BRONZE_EVENT_COLUMN) {
            Some(serde_json::Value::String(encoded)) => serde_json::from_str(encoded).unwrap(),
            _ => row.clone(),
        };
        decoded["time"] = serde_json::json!(1_700_000_000_000i64);
        // The S3 key helper is stripped by the sink before encoding.
        if let Some(object) = decoded.as_object_mut() {
            object.remove("_nano_bronze_partition");
        }
        decoded
    };
    let gcp = Uuid::from_u128(0xa3).hyphenated().to_string();
    let row = run(&format!("pull:{gcp}"));
    assert_eq!(
        row["metadata"]["loggers"],
        serde_json::json!([
            {"name": "lane logger"},
            {"name": "GCP Pub/Sub", "uid": gcp, "log_provider": "gcp_pubsub",
             "product": {"name": "nano pull", "vendor_name": "nano"}}
        ])
    );
    let validation = crate::parsers::validate_ocsf_event(&row);
    assert!(validation.valid, "{:?}", validation.errors);
    let s3 = Uuid::from_u128(0xa1).hyphenated().to_string();
    assert_eq!(run(&format!("pull:{s3}"))["metadata"]["loggers"][1]["log_provider"], "aws_s3_sqs");
    // No pull identity, or one this bundle does not render: untouched.
    assert_eq!(run("")["metadata"]["loggers"], serde_json::json!([{"name": "lane logger"}]));
    let stranger = Uuid::from_u128(0xff).hyphenated().to_string();
    assert_eq!(run(&format!("pull:{stranger}"))["metadata"]["loggers"], serde_json::json!([{"name": "lane logger"}]));
}

/// Evaluate a filter `condition` (legacy namespace) on one event. Vector
/// sets `.timestamp` (and the fork's `aws_s3` `.s3_event_time`) as a
/// timestamp, not a string, so those keys are typed here.
fn run_condition(vrl: &str, event: serde_json::Value) -> bool {
    run_condition_typed(vrl, event, &["timestamp", pull::S3_EVENT_TIME_FIELD])
}

/// [`run_condition`], typing only the RFC 3339 strings under `typed` as
/// timestamps (any other key stays a string, as object user metadata would).
fn run_condition_typed(vrl: &str, event: serde_json::Value, typed: &[&str]) -> bool {
    use vrl::compiler::runtime::Runtime;
    use vrl::compiler::state::RuntimeState;
    use vrl::compiler::{TargetValue, TimeZone};
    use vrl::value::{Secrets, Value};
    let program = vrl::compiler::compile(vrl, &vrl::stdlib::all())
        .unwrap_or_else(|e| panic!("{e:?}"))
        .program;
    let mut value = Value::from(event);
    if let Value::Object(map) = &mut value {
        for key in typed {
            if let Some(Value::Bytes(raw)) = map.get(*key).cloned() {
                let parsed =
                    chrono::DateTime::parse_from_rfc3339(std::str::from_utf8(&raw).unwrap())
                        .unwrap()
                        .with_timezone(&chrono::Utc);
                map.insert((*key).into(), Value::Timestamp(parsed));
            }
        }
    }
    let mut target = TargetValue {
        value,
        metadata: Value::Object(Default::default()),
        secrets: Secrets::new(),
    };
    match Runtime::new(RuntimeState::default())
        .resolve(&mut target, &program, &TimeZone::Local)
        .unwrap()
    {
        Value::Boolean(keep) => keep,
        other => panic!("condition returned {other:?}"),
    }
}

/// 2026-10-12T00:00:00Z: the source row's `created_at` in the tests below.
const CREATED_MS: u64 = 1_791_763_200_000;

/// NAN-3604: a queue/subscription source with a cutoff renders the
/// skipped-backlog filter
/// between the source and its stamp. It drops (acks, never ingests) only an
/// event older than the cutoff minus the grace, passes every newer event and
/// any event it cannot date, and its drops are intentional discards on their
/// own `nano_pull_<id>_skipped_backlog` component, which the loss exporter
/// exports and the loss fence never counts.
#[test]
fn queue_sources_skip_pre_existing_backlog_and_still_ingest_new_messages() {
    let mut s3 = pull_source(0xa1, "aws_cloudtrail", PullSourceKind::AwsS3);
    s3.backlog_cutoff_unix_ms = Some(CREATED_MS);
    let mut sqs = pull_source(0xa2, "apache_access", PullSourceKind::AwsSqs);
    sqs.backlog_cutoff_unix_ms = Some(CREATED_MS);
    let mut gcp = pull_source(0xa3, "windows_sysmon", PullSourceKind::GcpPubsub);
    gcp.backlog_cutoff_unix_ms = Some(CREATED_MS);
    let outcome = generate(
        tenant_sources(),
        Some(vec![s3.clone(), sqs.clone(), gcp.clone()]),
    );
    let file = text(&pull_tree(&outcome), pull::PULL_SOURCES_FILE).to_string();
    let neutral: toml::Table = file.replace("${", "_{").parse().unwrap();
    for source in [&s3, &sqs, &gcp] {
        let id = pull::source_component(source);
        let filter_id = pull::backlog_component(source).unwrap();
        assert_eq!(filter_id, format!("{id}_skipped_backlog"));
        let filter = neutral["transforms"][&filter_id].as_table().unwrap();
        assert_eq!(filter["type"].as_str(), Some("filter"));
        assert_eq!(
            filter["inputs"].as_array().unwrap(),
            &vec![toml::Value::from(id.clone())]
        );
        // The stamp reads the filter, so nothing reaches a lane unfiltered.
        let stamp = neutral["transforms"][&pull::stamp_component(source)]
            .as_table()
            .unwrap();
        assert_eq!(
            stamp["inputs"].as_array().unwrap(),
            &vec![toml::Value::from(filter_id.clone())]
        );
        let condition = filter["condition"].as_str().unwrap();
        let at = |ts: &str| serde_json::json!({"message": "m", "timestamp": ts});
        // Days-old backlog: skipped.
        assert!(!run_condition(condition, at("2026-10-05T00:00:00Z")));
        // Older than the cutoff by more than the 5 min grace: skipped.
        assert!(!run_condition(condition, at("2026-10-11T23:54:59.999Z")));
        // Inside the grace (clock skew) and after creation: ingested.
        assert!(run_condition(condition, at("2026-10-11T23:55:00Z")));
        assert!(run_condition(condition, at("2026-10-12T00:00:01Z")));
        assert!(run_condition(condition, at("2026-10-13T08:00:00Z")));
        // No usable timestamp: never skipped.
        assert!(run_condition(
            condition,
            serde_json::json!({"message": "m"})
        ));
        assert!(run_condition(
            condition,
            serde_json::json!({"message": "m", "timestamp": 5})
        ));
    }
    // The loss exporter keeps every discard counter (the skipped-backlog
    // count included), and the filter is not a loss-probe component.
    assert!(file.contains(".name == \"component_discarded_events_total\" ||"));
    assert!(!pull::backlog_component(&s3)
        .unwrap()
        .starts_with("nano_pull_loss_"));

    // Without a cutoff (rows before NAN-3604) there is no filter and the
    // request and the file are byte-identical to before.
    let plain = generate(tenant_sources(), Some(pulls()));
    let plain_tree = pull_tree(&plain);
    let plain_file = text(&plain_tree, pull::PULL_SOURCES_FILE);
    assert!(!plain_file.contains("skipped_backlog"));
    let request: serde_json::Value =
        serde_json::from_slice(&inputs(tenant_sources(), Some(pulls())).build_json).unwrap();
    assert!(request["pull_sources"][0]
        .get("backlog_cutoff_unix_ms")
        .is_none());
}

/// NAN-3604 (S3 cutoff source): an `aws_s3` event is dated by the S3
/// notification's `eventTime` (the nano Vector fork's `.s3_event_time`), not
/// by `.timestamp` (the object's `LastModified`), so a restore or copy that
/// keeps an old `LastModified` still ingests. A Vector without the field
/// falls back to `.timestamp`; a string of that name (object user metadata on
/// such a Vector) is never trusted. The stamp deletes the field, so the
/// lane's parsers see exactly the event they saw before. `aws_sqs` and
/// `gcp_pubsub` ignore the field.
#[test]
fn aws_s3_backlog_is_dated_by_the_notification_event_time() {
    let mut s3 = pull_source(0xa1, "aws_cloudtrail", PullSourceKind::AwsS3);
    s3.backlog_cutoff_unix_ms = Some(CREATED_MS);
    let mut sqs = pull_source(0xa2, "apache_access", PullSourceKind::AwsSqs);
    sqs.backlog_cutoff_unix_ms = Some(CREATED_MS);
    let mut gcp = pull_source(0xa3, "windows_sysmon", PullSourceKind::GcpPubsub);
    gcp.backlog_cutoff_unix_ms = Some(CREATED_MS);
    let outcome = generate(
        tenant_sources(),
        Some(vec![s3.clone(), sqs.clone(), gcp.clone()]),
    );
    let file = text(&pull_tree(&outcome), pull::PULL_SOURCES_FILE).to_string();
    let neutral: toml::Table = file.replace("${", "_{").parse().unwrap();
    let condition = |source: &PullSource| {
        neutral["transforms"][&pull::backlog_component(source).unwrap()]["condition"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let s3_condition = condition(&s3);
    let event = |event_time: Option<&str>, last_modified: Option<&str>| {
        let mut event = serde_json::json!({"message": "m", "bucket": "b", "object": "k"});
        if let Some(at) = event_time {
            event[pull::S3_EVENT_TIME_FIELD] = at.into();
        }
        if let Some(at) = last_modified {
            event["timestamp"] = at.into();
        }
        event
    };
    let old = "2021-01-01T00:00:00Z";
    let new = "2026-10-12T08:00:00Z";
    // A restore/copy: old LastModified, new eventTime: ingested.
    assert!(run_condition(&s3_condition, event(Some(new), Some(old))));
    // Pre-existing backlog: an old notification is skipped whatever the object says.
    assert!(!run_condition(&s3_condition, event(Some(old), Some(new))));
    assert!(!run_condition(&s3_condition, event(Some(old), Some(old))));
    // The grace applies to eventTime.
    assert!(!run_condition(&s3_condition, event(Some("2026-10-11T23:54:59.999Z"), Some(new))));
    assert!(run_condition(&s3_condition, event(Some("2026-10-11T23:55:00Z"), Some(old))));
    // A Vector without the field: LastModified decides (the earlier behaviour).
    assert!(!run_condition(&s3_condition, event(None, Some(old))));
    assert!(run_condition(&s3_condition, event(None, Some(new))));
    // Undatable: never skipped.
    assert!(run_condition(&s3_condition, event(None, None)));
    // A user-metadata string of the same name is not a timestamp: LastModified decides.
    let untyped = |event_time: &str, last_modified: &str| {
        run_condition_typed(&s3_condition, event(Some(event_time), Some(last_modified)), &["timestamp"])
    };
    assert!(untyped(old, new));
    assert!(!untyped(new, old));
    // aws_sqs / gcp_pubsub date by `.timestamp` only (SentTimestamp / publish_time).
    for source in [&sqs, &gcp] {
        let condition = condition(source);
        assert!(!condition.contains(pull::S3_EVENT_TIME_FIELD), "{condition}");
        assert!(!run_condition(&condition, event(Some(new), Some(old))));
        assert!(run_condition(&condition, event(Some(old), Some(new))));
        assert!(!stamp_vrl(&file, source).contains(pull::S3_EVENT_TIME_FIELD));
    }

    // The stamp drops the field before anything else; the lane input is unchanged.
    let stamp = stamp_vrl(&file, &s3);
    assert!(stamp.starts_with(&format!("del(.{})\n", pull::S3_EVENT_TIME_FIELD)), "{stamp}");
    let stamped = |event: serde_json::Value| {
        let (mut out, _) = run_stamp(&stamp, event);
        // `now()`: differs between two runs.
        out.as_object_mut().unwrap().remove("routing_timestamp");
        out
    };
    let with_field = stamped(event(Some(new), Some(new)));
    assert!(with_field.get(pull::S3_EVENT_TIME_FIELD).is_none(), "{with_field}");
    assert_eq!(with_field, stamped(event(None, Some(new))));
    // Without a cutoff nothing changes: no filter, no del.
    let plain = pull_source(0xa1, "aws_cloudtrail", PullSourceKind::AwsS3);
    let plain_file = text(
        &pull_tree(&generate(tenant_sources(), Some(vec![plain.clone()]))),
        pull::PULL_SOURCES_FILE,
    )
    .to_string();
    assert!(!plain_file.contains(pull::S3_EVENT_TIME_FIELD));
}

#[test]
fn a_backlog_cutoff_on_event_hubs_or_out_of_range_is_refused() {
    let refused = |pull: PullSource| {
        let outcome = build::generate(&inputs(tenant_sources(), Some(vec![pull.clone()])));
        assert!(!outcome.ok(), "{pull:?}");
        let message = outcome.report.failure.unwrap().message;
        assert!(message.contains("backlog_cutoff_unix_ms"), "{message}");
        assert!(pull::pull_base(&base(), &[pull], Uuid::from_u128(TENANT_UUID), false).is_err());
    };
    let mut hub = pull_source(0xa1, "aws_cloudtrail", PullSourceKind::AzureEventHubs);
    hub.backlog_cutoff_unix_ms = Some(CREATED_MS);
    refused(hub);
    for bad in [0, 1_791_763_200, MAX_BACKLOG_CUTOFF_UNIX_MS + 1] {
        let mut p = pull_source(0xa1, "aws_cloudtrail", PullSourceKind::AwsS3);
        p.backlog_cutoff_unix_ms = Some(bad);
        refused(p);
    }
    let mut ok = pull_source(0xa1, "aws_cloudtrail", PullSourceKind::AwsSqs);
    ok.backlog_cutoff_unix_ms = Some(MIN_BACKLOG_CUTOFF_UNIX_MS);
    generate(tenant_sources(), Some(vec![ok]));
}

/// NAN-3604: nano never moves a Pub/Sub subscription's cursor back: the
/// source table is exactly these keys (no seek, snapshot, retained-acked
/// replay or a second subscription), so a new key fails here first. (A
/// backlog the subscription already held is skipped by the backlog filter,
/// covered above.)
#[test]
fn gcp_pubsub_never_seeks_the_subscription_back() {
    let gcp = pull_source(3, "apache_access", PullSourceKind::GcpPubsub);
    let outcome = generate(tenant_sources(), Some(vec![gcp.clone()]));
    let file = text(&pull_tree(&outcome), pull::PULL_SOURCES_FILE).to_string();
    let neutral: toml::Table = file.replace("${", "_{").parse().unwrap();
    let table = neutral["sources"][&pull::source_component(&gcp)]
        .as_table()
        .unwrap();
    let keys: BTreeSet<&str> = table.keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        BTreeSet::from([
            "type",
            "project",
            "subscription",
            "ack_deadline_secs",
            "acknowledgements",
        ])
    );
    let lower = file.to_ascii_lowercase();
    for forbidden in ["seek", "snapshot", "retain_acked", "earliest"] {
        assert!(!lower.contains(forbidden), "{forbidden}");
    }
    // With a cutoff only the filter is added; the source table is unchanged.
    let mut cut = gcp.clone();
    cut.backlog_cutoff_unix_ms = Some(CREATED_MS);
    let outcome = generate(tenant_sources(), Some(vec![cut.clone()]));
    let file = text(&pull_tree(&outcome), pull::PULL_SOURCES_FILE).to_string();
    let neutral: toml::Table = file.replace("${", "_{").parse().unwrap();
    assert_eq!(
        neutral["sources"][&pull::source_component(&cut)]
            .as_table()
            .unwrap(),
        table
    );
    assert!(!file.to_ascii_lowercase().contains("seek"));
}
