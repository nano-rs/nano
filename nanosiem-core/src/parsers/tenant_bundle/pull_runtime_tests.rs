// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3712: the runtime-config pull bundle (`pull_lanes`) and the runtime
//! source templates the pull runtime renders its sources with.

use std::collections::BTreeMap;

use regex::Regex;
use uuid::Uuid;

use super::archive;
use super::build;
use super::model::*;
use super::overlay::{self, OverlayProfile, LAKE_SINK_FILE, ROUTER_FILE};
use super::pull::{self, RuntimeVariant};
use super::pull_tests::*;

fn lanes(slugs: &[&str]) -> Vec<String> {
    slugs.iter().map(|s| s.to_string()).collect()
}

fn runtime_inputs(pull_lanes: Vec<String>, capture: bool) -> build::BuildInputs {
    let mut inputs = inputs_with(tenant_sources(), None, capture);
    let mut json: serde_json::Value = serde_json::from_slice(&inputs.build_json).unwrap();
    json["pull_lanes"] = serde_json::json!(pull_lanes);
    inputs.build_json = serde_json::to_vec(&json).unwrap();
    inputs
}

fn generate_runtime(pull_lanes: Vec<String>, capture: bool) -> build::GenerateOutcome {
    let outcome = build::generate(&runtime_inputs(pull_lanes, capture));
    assert!(outcome.ok(), "{:?}", outcome.report.failure);
    outcome
}

fn inputs_line(text: &str, kind: &str, id: &str) -> String {
    let section = &text[text.find(&format!("[{kind}.{id}]\n")).unwrap()..];
    section
        .lines()
        .find(|l| l.starts_with("inputs = ["))
        .unwrap()
        .to_string()
}

/// Vector's `${NAME}` interpolation with `$$` = `$` (no default/required
/// modifiers: the runtime render never uses them), on a text whose values
/// are already in place: the reference the substitution must equal.
fn interpolate(text: &str, env: &BTreeMap<String, String>) -> String {
    let re = Regex::new(r"\$\{([A-Z0-9_]+)\}").unwrap();
    re.replace_all(text, |c: &regex::Captures<'_>| env[&c[1]].replace('$', "$$"))
        .into_owned()
}

fn env_for(source: &PullSource, consumer_group: &str) -> BTreeMap<String, String> {
    let prefix = pull::env_prefix(source);
    [
        ("REGION", "eu-west-2"),
        ("QUEUE_URL", "https://sqs.eu-west-2.amazonaws.com/210987654321/q-1"),
        ("GCP_PROJECT", "acme-prod"),
        ("GCP_SUBSCRIPTION", "acme-logs"),
        ("EH_NAMESPACE", "acme.servicebus.windows.net"),
        ("EH_NAME", "insights-logs"),
        ("EH_CONSUMER_GROUP", consumer_group),
        ("AZURE_CLIENT_ID", "11111111-2222-4333-8444-555555555555"),
        ("CHECKPOINT_ACCOUNT", "acmecheckpoints"),
        ("CHECKPOINT_CONTAINER", "nano"),
    ]
    .into_iter()
    .map(|(name, value)| (format!("{prefix}{name}"), value.to_string()))
    .collect()
}

fn runtime_source(id: u128, slug: &str, kind: PullSourceKind, cutoff: Option<u64>) -> PullSource {
    let mut source = pull_source(id, slug, kind);
    source.backlog_cutoff_unix_ms = cutoff;
    source
}

/// One source per variant plus edge ids/slugs/cutoffs.
fn matrix() -> Vec<PullSource> {
    vec![
        runtime_source(0xa1, "aws_cloudtrail", PullSourceKind::AwsS3, Some(1_791_763_200_000)),
        runtime_source(0xa2, "apache_access", PullSourceKind::AwsS3, Some(1_577_836_800_000)),
        runtime_source(u128::MAX, "alb-logs_v2", PullSourceKind::AwsSqs, Some(4_102_444_800_000)),
        runtime_source(0x0123_4567_89ab_4cde_8f01_2345_6789_abcd, "aws_cloudtrail", PullSourceKind::AwsSqs, Some(1_700_000_000_000)),
        runtime_source(0xdead_beef, "gcp_audit", PullSourceKind::GcpPubsub, Some(1_760_000_000_123)),
        runtime_source(0xa4, "azure_monitor", PullSourceKind::AzureEventHubs, None),
        runtime_source(0xa5, "aws_cloudtrail", PullSourceKind::AzureEventHubs, None),
    ]
}

// -- the runtime bundle ------------------------------------------------------------

/// The runtime bundle is code only: the lanes, the router over the stamp
/// glob, the source-agnostic origin stamp and a `05-pull-sources.toml` with
/// the contract marker and the loss probe, and no pull source at all.
#[test]
fn the_runtime_bundle_carries_the_lanes_and_no_pull_source() {
    let outcome = generate_runtime(lanes(&["apache_access", "aws_cloudtrail"]), false);
    let out = outcome.report.pull_bundle.as_ref().unwrap();
    assert_eq!(out.pull_runtime_contract.as_deref(), Some(pull::PULL_RUNTIME_CONTRACT));
    assert!(out.pull_origin);
    assert!(out.pull_sources.is_empty());
    assert_eq!(out.lane_sources, vec!["apache_access", "aws_cloudtrail"]);
    assert!(outcome.report.pull_pending.is_empty() && outcome.report.pull_pending_lanes.is_empty());

    let tree = pull_tree(&outcome);
    let file = text(&tree, pull::PULL_SOURCES_FILE);
    assert!(file.starts_with(&format!("# {}:", pull::PULL_RUNTIME_CONTRACT)));
    assert_eq!(pull::runtime_contract(file), Some(pull::PULL_RUNTIME_CONTRACT));
    let all = all_text(&tree);
    let declared = Regex::new(r"(?m)^\[(sources|transforms)\.nano_pull_([a-z0-9_]+)\]").unwrap();
    let ids: Vec<String> = declared.captures_iter(&all).map(|c| c[2].to_string()).collect();
    assert_eq!(ids, vec!["loss_metrics", "loss_select"], "no pull source in the bundle");
    assert!(!all.contains("NANO_PULL_"), "no source env in the bundle");
    assert_eq!(
        inputs_line(text(&tree, ROUTER_FILE), "transforms", "source_router"),
        format!("inputs = [\"{}\"]", pull::PULL_STAMP_GLOB)
    );
    // The loss probe also exports Vector's reload counters.
    assert!(file.contains("\"reloaded_total\"") && file.contains("[\"reload\", \"config_load\"]"));
    // The origin stamp reads the provider, never a source id.
    let lake = text(&tree, LAKE_SINK_FILE);
    assert_eq!(lake.matches(pull::PULL_ORIGIN_MARKER).count(), 1);
    assert!(lake.contains("%nano_pull_provider"));
    // The lanes are the full bundle's lanes, and the bundle verifies.
    let built = pull::build_pull_runtime_bundle(
        &base(),
        &tenant_sources(),
        &lanes(&["apache_access", "aws_cloudtrail"]),
        false,
    )
    .unwrap();
    assert_eq!(archive::pack(&built.candidate).unwrap(), outcome.pull_bundle.clone().unwrap());
    overlay::verify_against_base_with(&built.base, &built.candidate, OverlayProfile::Pull).unwrap();
    assert_eq!(
        out.base_sha256,
        sha(&archive::pack(&pull::pull_runtime_base(&base(), false).unwrap()).unwrap())
    );
    // The Vector stage gets the sample beside it; a legacy build gets none.
    assert_eq!(
        outcome.pull_runtime_sample.as_deref(),
        Some(pull::render_runtime_sample(uuid::Uuid::from_u128(TENANT_UUID)).as_str())
    );
    assert!(generate(tenant_sources(), Some(pulls())).pull_runtime_sample.is_none());
}

/// The runtime bundle depends only on the lanes: no source, cutoff or
/// coordinate moves its bytes, so a source change needs no build.
#[test]
fn the_runtime_bundle_depends_only_on_the_lanes() {
    let a = generate_runtime(lanes(&["aws_cloudtrail"]), false);
    let b = generate_runtime(lanes(&["aws_cloudtrail"]), false);
    assert_eq!(a.pull_bundle, b.pull_bundle);
    let c = generate_runtime(lanes(&["apache_access", "aws_cloudtrail"]), false);
    assert_ne!(a.pull_bundle, c.pull_bundle);
}

#[test]
fn runtime_lanes_without_a_tenant_lane_stay_pending() {
    let outcome = generate_runtime(lanes(&["aws_cloudtrail", "gcp_audit"]), false);
    assert_eq!(outcome.report.pull_pending_lanes, vec!["gcp_audit"]);
    assert_eq!(
        outcome.report.pull_bundle.as_ref().unwrap().lane_sources,
        vec!["aws_cloudtrail"]
    );
    let none = generate_runtime(lanes(&["gcp_audit"]), false);
    assert!(none.pull_bundle.is_none() && none.report.pull_bundle.is_none());
    assert_eq!(none.report.pull_pending_lanes, vec!["gcp_audit"]);
}

#[test]
fn pull_lanes_requests_are_validated() {
    let bad = |inputs: build::BuildInputs| {
        let outcome = build::generate(&inputs);
        assert!(!outcome.ok());
        outcome.report.failure.unwrap().message
    };
    assert!(bad(runtime_inputs(vec![], false)).contains("pull_lanes"));
    assert!(bad(runtime_inputs(lanes(&["b", "a"]), false)).contains("sorted"));
    assert!(bad(runtime_inputs(lanes(&["a", "a"]), false)).contains("unique"));
    assert!(bad(runtime_inputs(lanes(&["Bad Slug"]), false)).contains("pull_lanes"));
    let many: Vec<String> = (0..=MAX_PULL_LANES).map(|i| format!("lane{i:03}")).collect();
    assert!(bad(runtime_inputs(many, false)).contains("pull_lanes"));
    let mut both = runtime_inputs(lanes(&["aws_cloudtrail"]), false);
    let mut json: serde_json::Value = serde_json::from_slice(&both.build_json).unwrap();
    json["pull_sources"] = serde_json::to_value(pulls()).unwrap();
    both.build_json = serde_json::to_vec(&json).unwrap();
    assert!(bad(both).contains("exclusive"));
    // Capture needs one of them; with lanes it is fine.
    assert!(bad(inputs_with(tenant_sources(), None, true)).contains("pull_capture"));
    generate_runtime(lanes(&["aws_cloudtrail"]), true);
}

/// A request without `pull_lanes` serializes exactly as before.
#[test]
fn a_request_without_pull_lanes_serializes_as_before() {
    let inputs = inputs(tenant_sources(), Some(pulls()));
    let json = String::from_utf8(inputs.build_json).unwrap();
    assert!(!json.contains("pull_lanes"), "{json}");
    let report = serde_json::to_string(&generate(tenant_sources(), Some(pulls())).report).unwrap();
    assert!(!report.contains("pull_runtime_contract") && !report.contains("pull_pending_lanes"));
}

#[test]
fn the_runtime_capture_tap_reads_every_stamp_by_glob() {
    let outcome = generate_runtime(lanes(&["aws_cloudtrail"]), true);
    let tree = pull_tree(&outcome);
    let file = text(&tree, pull::PULL_SOURCES_FILE);
    assert_eq!(
        inputs_line(file, "transforms", "nano_pipe_capture_select"),
        format!("inputs = [\"{}\"]", pull::PULL_STAMP_GLOB)
    );
    // The capture tap is still kept out of the loss exporter.
    assert!(file.contains("tap = starts_with(component, \"nano_pipe_capture_\")"));
    // Without capture: no tap.
    let plain = pull_tree(&generate_runtime(lanes(&["aws_cloudtrail"]), false));
    assert!(!all_text(&plain).contains("nano_pipe_capture_"));
}

/// The stamp glob matches every runtime stamp and nothing else the bundle
/// or a runtime config declares.
#[test]
fn the_stamp_glob_matches_only_stamps() {
    let glob = Regex::new(&format!(
        "^{}$",
        regex::escape(pull::PULL_STAMP_GLOB).replace(r"\*", ".*")
    ))
    .unwrap();
    let tenant = Uuid::from_u128(TENANT_UUID);
    let sample = pull::render_runtime_sample(tenant);
    let bundle = all_text(&pull_tree(&generate_runtime(lanes(&["aws_cloudtrail"]), true)));
    let declared = Regex::new(r"(?m)^\[(?:sources|transforms|sinks|enrichment_tables)\.([A-Za-z0-9_-]+)\]").unwrap();
    let mut stamps = Vec::new();
    for text in [&sample, &bundle] {
        for c in declared.captures_iter(text) {
            if glob.is_match(&c[1]) {
                stamps.push(c[1].to_string());
            }
        }
    }
    assert_eq!(stamps.len(), RuntimeVariant::ALL.len(), "{stamps:?}");
    assert!(stamps.iter().all(|s| s.ends_with("_stamp") && s.starts_with(pull::PULL_COMPONENT_PREFIX)));
}

// -- templates ----------------------------------------------------------------------

/// The substituted template IS the one renderer's output (plus the provider
/// line), interpolated: for every variant, edge ids, slugs, cutoffs and a
/// `$Default` consumer group.
#[test]
fn a_substituted_template_equals_the_render_of_the_source() {
    let tenant = Uuid::from_u128(TENANT_UUID);
    for source in matrix() {
        let variant = RuntimeVariant::of(source.kind, &source.slug);
        let env = env_for(&source, "$Default");
        let template = pull::runtime_template(variant, tenant);
        let substituted =
            pull::substitute_runtime_template(&template, variant, &source, &env).unwrap();
        // The legacy render of the same source, with the runtime stamp's
        // provider line added after the credential line.
        let legacy = pull::render_pull_sources(tenant, std::slice::from_ref(&source), false);
        let start = legacy.find("# Pull source").unwrap();
        let end = legacy.find("\n# NAN-3371/NAN-3372 loss accounting").unwrap();
        let credential = format!("%nano_credential_id = \"{}\"\n", pull::credential_id(&source));
        let provider = format!(
            "%nano_pull_provider = \"{}\"\n",
            pull::pull_origin_provider(source.kind).0
        );
        let expected = format!("\n{}", &legacy[start..end])
            .replacen(&credential, &format!("{credential}{provider}"), 1);
        assert_eq!(substituted, interpolate(&expected, &env), "{source:?}");
        assert_eq!(pull::render_runtime_source(&source, tenant, &env).unwrap(), substituted);
        // `$` is escaped for Vector's interpolation; nothing is left to fill.
        if source.kind == PullSourceKind::AzureEventHubs {
            assert!(substituted.contains("consumer_group = \"$$Default\""));
        }
        assert!(!substituted.contains("${") && !substituted.contains("@@"));
        // It parses, declares exactly this source's components, and its stamp compiles.
        let table: toml::Table = substituted.parse().unwrap();
        assert!(table["sources"].get(&pull::source_component(&source)).is_some());
        let stamp = table["transforms"][&pull::stamp_component(&source)]["source"]
            .as_str()
            .unwrap();
        vrl::compiler::compile(stamp, &vrl::stdlib::all()).unwrap_or_else(|e| panic!("{e:?}"));
        assert!(stamp.contains(&provider));
        assert_eq!(
            table.get("transforms").and_then(|t| t.as_table()).map(|t| t.len()),
            Some(if variant.has_cutoff() { 2 } else { 1 })
        );
    }
}

/// A template carries the tenant (its own) and tokens, never a trace of the
/// sentinel it was rendered from.
#[test]
fn templates_carry_only_known_tokens() {
    let tenant = Uuid::from_u128(TENANT_UUID);
    let templates = pull::runtime_templates(tenant);
    assert_eq!(
        templates.keys().copied().collect::<Vec<_>>(),
        vec!["aws_s3", "aws_s3_cloudtrail", "aws_sqs", "azure_event_hubs", "gcp_pubsub"]
    );
    let token = Regex::new(r"@@[A-Z_]+@@").unwrap();
    for (name, template) in &templates {
        for t in token.find_iter(template) {
            assert!(
                [
                    pull::TOKEN_SOURCE_ID,
                    pull::TOKEN_SOURCE_HEX,
                    pull::TOKEN_SOURCE_HEX_UPPER,
                    pull::TOKEN_SLUG,
                    pull::TOKEN_CUTOFF_MS,
                    pull::TOKEN_CUTOFF_THRESHOLD_MS,
                ]
                .contains(&t.as_str()),
                "{name}: {}",
                t.as_str()
            );
        }
        for trace in ["fedcba98", "FEDCBA98", "3333333", "nano-runtime-template-slug"] {
            assert!(!template.contains(trace), "{name} keeps {trace}");
        }
        assert!(template.contains(&tenant.hyphenated().to_string()));
        assert!(template.contains(pull::TOKEN_SOURCE_HEX) && template.contains(pull::TOKEN_SOURCE_ID));
        let cutoff = template.contains(pull::TOKEN_CUTOFF_MS);
        assert_eq!(cutoff, *name != "azure_event_hubs", "{name}");
        assert_eq!(template.contains(pull::TOKEN_SLUG), *name != "aws_s3_cloudtrail", "{name}");
    }
    // Another tenant's templates differ only by the tenant.
    let other = Uuid::from_u128(0x0bad);
    for (name, template) in pull::runtime_templates(other) {
        assert_eq!(
            template.replace(&other.hyphenated().to_string(), &tenant.hyphenated().to_string()),
            templates[name]
        );
    }
}

#[test]
fn substitution_refuses_what_the_template_cannot_carry() {
    let tenant = Uuid::from_u128(TENANT_UUID);
    let queue = runtime_source(0xa2, "apache_access", PullSourceKind::AwsSqs, Some(1_791_763_200_000));
    let env = env_for(&queue, "$Default");
    let render = |source: &PullSource, env: &BTreeMap<String, String>| {
        pull::render_runtime_source(source, tenant, env)
    };
    assert!(render(&queue, &env).is_ok());
    // A value that would break out of the TOML string.
    for value in ["a\"b", "a\\b", "a\nb", ""] {
        let mut bad = env.clone();
        bad.insert(format!("{}REGION", pull::env_prefix(&queue)), value.into());
        assert!(render(&queue, &bad).is_err(), "{value:?}");
    }
    // A missing coordinate.
    let mut missing = env.clone();
    missing.remove(&format!("{}QUEUE_URL", pull::env_prefix(&queue)));
    assert!(render(&queue, &missing).unwrap_err().contains("QUEUE_URL"));
    // Cutoff exactly on queue/subscription kinds, in range.
    let mut no_cutoff = queue.clone();
    no_cutoff.backlog_cutoff_unix_ms = None;
    assert!(render(&no_cutoff, &env).is_err());
    let mut seconds = queue.clone();
    seconds.backlog_cutoff_unix_ms = Some(1_791_763_200);
    assert!(render(&seconds, &env).is_err());
    let hub = runtime_source(0xa4, "azure_monitor", PullSourceKind::AzureEventHubs, Some(1_791_763_200_000));
    assert!(render(&hub, &env_for(&hub, "$Default")).is_err());
    // No SQS tuning, a valid slug and id, and the matching variant.
    let mut tuned = runtime_source(0xa1, "aws_cloudtrail", PullSourceKind::AwsS3, Some(1_791_763_200_000));
    tuned.sqs_client_concurrency = Some(2);
    assert!(render(&tuned, &env_for(&tuned, "x")).is_err());
    let mut slug = queue.clone();
    slug.slug = "Bad\"".into();
    assert!(render(&slug, &env).is_err());
    let nil = runtime_source(0, "apache_access", PullSourceKind::AwsSqs, Some(1_791_763_200_000));
    assert!(render(&nil, &env_for(&nil, "x")).is_err());
    let template = pull::runtime_template(RuntimeVariant::AwsS3, tenant);
    assert!(pull::substitute_runtime_template(&template, RuntimeVariant::AwsS3, &queue, &env).is_err());
    let s3 = runtime_source(0xa1, "aws_cloudtrail", PullSourceKind::AwsS3, Some(1_791_763_200_000));
    assert!(pull::substitute_runtime_template(&template, RuntimeVariant::AwsS3, &s3, &env_for(&s3, "x")).is_err());
    // An unknown token is refused.
    let sqs = pull::runtime_template(RuntimeVariant::AwsSqs, tenant);
    assert!(pull::substitute_runtime_template(&format!("{sqs}@@REGION@@"), RuntimeVariant::AwsSqs, &queue, &env).is_err());
}

// -- the runtime origin stamp ------------------------------------------------------

/// The runtime origin stamp appends the same Logger as the per-source stamp,
/// from the provider the source stamp set; without a pull identity or with an
/// unknown provider the event is untouched.
#[test]
fn the_runtime_origin_stamp_reads_the_provider() {
    let built = pull::build_pull_runtime_bundle(&base(), &tenant_sources(), &lanes(&["aws_cloudtrail"]), false).unwrap();
    let storage = super::platform_audit_lane::storage_prepare_vrl(&built.candidate).unwrap();
    let event = serde_json::json!({
        "class_uid": 6003, "category_uid": 6, "activity_id": 99, "type_uid": 600399, "severity_id": 1,
        "time": 1_700_000_000_000i64, "message": "m", "api": {"operation": "Unknown"},
        "cloud": {"provider": "AWS"}, "actor": {"user": {"name": "unknown"}}, "src_endpoint": {"ip": "0.0.0.0"},
        "metadata": {"version": "1.9.0", "profiles": ["cloud"], "product": {"name": "AWS CloudTrail", "vendor_name": "Amazon"},
                     "loggers": [{"name": "lane logger"}]},
    });
    let tenant = Uuid::from_u128(TENANT_UUID).hyphenated().to_string();
    let run = |credential: &str, provider: &str| -> serde_json::Value {
        let mut meta = vec![("tenant_id", tenant.as_str()), ("source_type", "aws_cloudtrail"), ("nano_credential_id", credential)];
        if !provider.is_empty() {
            meta.push(("nano_pull_provider", provider));
        }
        let row = super::bronze_row_contract::run_vrl(&storage, vrl::value::Value::from(event.clone()), &meta).unwrap();
        let row = serde_json::to_value(&row).unwrap();
        match row.get(crate::parsers::lake_bronze_row::BRONZE_EVENT_COLUMN) {
            Some(serde_json::Value::String(encoded)) => serde_json::from_str(encoded).unwrap(),
            _ => row.clone(),
        }
    };
    let id = Uuid::from_u128(0xa3).hyphenated().to_string();
    for kind in [
        PullSourceKind::AwsS3,
        PullSourceKind::AwsSqs,
        PullSourceKind::GcpPubsub,
        PullSourceKind::AzureEventHubs,
    ] {
        let (provider, name) = pull::pull_origin_provider(kind);
        assert_eq!(
            run(&format!("pull:{id}"), provider)["metadata"]["loggers"],
            serde_json::json!([
                {"name": "lane logger"},
                {"name": name, "uid": id, "log_provider": provider,
                 "product": {"name": "nano pull", "vendor_name": "nano"}}
            ])
        );
    }
    let untouched = serde_json::json!([{"name": "lane logger"}]);
    assert_eq!(run(&format!("pull:{id}"), "")["metadata"]["loggers"], untouched);
    assert_eq!(run(&format!("pull:{id}"), "kafka")["metadata"]["loggers"], untouched);
    assert_eq!(run("", "aws_sqs")["metadata"]["loggers"], untouched);
    assert_eq!(run("hec:token", "aws_sqs")["metadata"]["loggers"], untouched);
}
