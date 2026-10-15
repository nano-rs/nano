// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3623: Nano Pipe live capture of pull events (the opt-in capture tap in
//! the pull bundle).
//!
//! The golden files under `testdata/` are blessed one at a time with
//! `NANO_BLESS_PULL_GOLDEN=<file name> cargo test -p nanosiem-core pull_capture_tests`.
//! `pull-bundle-no-capture.golden` was blessed on origin/main (361d1ad8e)
//! BEFORE the capture tap existed, with only this test added: a pull bundle
//! without capture must keep every byte. Never re-bless it to make a change pass.
//! NAN-3604 re-blessed it once, for the deliberate Event Hubs
//! `start_position = "latest"`: with `AZURE_START_POSITION = "earliest"` the
//! old golden still passed, so that line is the only change.

use std::fmt::Write as _;

use super::model::*;
use super::pull_tests::*;

const NO_CAPTURE_GOLDEN: &str = "src/parsers/tenant_bundle/testdata/pull-bundle-no-capture.golden";

/// Every pull kind, two of them sharing a lane.
fn every_kind() -> Vec<PullSource> {
    let mut all = pulls();
    all.push(pull_source(0xa3, "windows_sysmon", PullSourceKind::GcpPubsub));
    all.push(pull_source(0xa4, "windows_sysmon", PullSourceKind::AzureEventHubs));
    all
}

/// A reviewable digest of a pull build without capture: the packed bundle, the
/// report's pull facts and every file of the pull tree.
/// NAN-3653: `build::generate` always adds the pull origin stamp now, so the
/// pre-capture render is rebuilt with the stamp off (the bytes an older
/// builder emits); the stamp itself is covered in `pull_tests`.
fn digest_of(sources: Vec<PullSource>) -> String {
    let (rendered, _) = super::pull::plan(&tenant_sources(), &sources);
    let tenant = uuid::Uuid::from_u128(TENANT_UUID);
    let built = super::pull::build_pull_bundle(&base(), &tenant_sources(), &rendered, tenant, false).unwrap();
    let packed = super::archive::pack(&built.candidate).unwrap();
    let mut out = String::new();
    writeln!(out, "pull_bundle_sha256 {}", sha(&packed)).unwrap();
    writeln!(out, "base_sha256 {}", sha(&super::archive::pack(&built.base).unwrap())).unwrap();
    writeln!(out, "gzip_bytes {}", packed.len()).unwrap();
    let tree = built.candidate;
    for (path, data) in &tree.files {
        writeln!(out, "file {} {}", sha(data), path).unwrap();
    }
    for dir in &tree.dirs {
        writeln!(out, "dir {dir}").unwrap();
    }
    out
}

fn golden(path: &str, actual: &str) {
    let full = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(path);
    if std::env::var("NANO_BLESS_PULL_GOLDEN").is_ok_and(|name| !name.is_empty() && path.ends_with(&name)) {
        std::fs::write(&full, actual).unwrap();
        return;
    }
    let expected = std::fs::read_to_string(&full)
        .unwrap_or_else(|e| panic!("{path}: {e} (bless with NANO_BLESS_PULL_GOLDEN=1)"));
    assert_eq!(expected, actual, "{path} differs");
}

/// Acceptance (NAN-3623): a tenant without capture renders exactly the pull
/// bundle it rendered before the capture tap existed.
#[test]
fn a_pull_bundle_without_capture_is_byte_identical_to_the_pre_capture_render() {
    golden(NO_CAPTURE_GOLDEN, &digest_of(every_kind()));
}

// -- the capture tap --------------------------------------------------------------

const CAPTURE_GOLDEN: &str = "src/parsers/tenant_bundle/testdata/pull-capture-sources.golden.toml";

fn generate_capture(pull_sources: Vec<PullSource>) -> super::build::GenerateOutcome {
    let outcome = super::build::generate(&inputs_with(tenant_sources(), Some(pull_sources), true));
    assert!(outcome.ok(), "{:?}", outcome.report.failure);
    outcome
}

/// `05-pull-sources.toml` parsed (interpolations neutralized, as pull.rs reads it).
fn pull_sources_table(tree: &super::archive::BundleTree) -> toml::Table {
    let text = text(tree, super::pull::PULL_SOURCES_FILE);
    regex::Regex::new(r"\$\{[^}]*\}").unwrap().replace_all(text, "0").parse().unwrap()
}

fn component<'a>(table: &'a toml::Table, kind: &str, id: &str) -> &'a toml::Table {
    table[kind][id].as_table().unwrap_or_else(|| panic!("{kind}.{id}"))
}

fn inputs_list(table: &toml::Table) -> Vec<String> {
    table["inputs"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect()
}

/// The rendered tap, golden (the platform `pull-bundle.ts` mirrors it byte for
/// byte from this file) and wired as designed.
#[test]
fn the_capture_tap_reads_every_stamp_and_reaches_the_worker_only_through_its_buffer() {
    let sources = every_kind();
    let outcome = generate_capture(sources.clone());
    let tree = pull_tree(&outcome);
    golden(CAPTURE_GOLDEN, text(&tree, super::pull::PULL_SOURCES_FILE));
    // For `vector validate` of the whole tree in the fork image (manual check).
    if let Ok(path) = std::env::var("NANO_DUMP_PULL_CAPTURE_BUNDLE") {
        std::fs::write(path, outcome.pull_bundle.as_deref().unwrap()).unwrap();
    }
    let table = pull_sources_table(&tree);
    let p = super::pull::CAPTURE_COMPONENT_PREFIX;

    let mut sorted = sources.clone();
    sorted.sort();
    let stamps: Vec<String> = sorted.iter().map(super::pull::stamp_component).collect();
    assert_eq!(inputs_list(component(&table, "transforms", &format!("{p}select"))), stamps);
    assert_eq!(
        component(&table, "sources", &format!("{p}status"))["endpoint"].as_str(),
        Some(super::pull::CAPTURE_STATUS_URI)
    );
    let sink = component(&table, "sinks", &format!("{p}observe"));
    assert_eq!(sink["uri"].as_str(), Some(super::pull::CAPTURE_OBSERVE_URI));
    // Ack decoupling: the sink reads the buffer's export source, never a transform.
    assert_eq!(inputs_list(sink), vec![format!("{p}export")]);
    assert_eq!(sink["request"]["retry_attempts"].as_integer(), Some(0));
    assert_eq!(sink["buffer"]["when_full"].as_str(), Some("drop_newest"));
    let buffer = component(&table, "enrichment_tables", &format!("{p}buffer"));
    assert_eq!(buffer["type"].as_str(), Some("memory"));
    assert_eq!(inputs_list(buffer), vec![format!("{p}shape")]);
    assert_eq!(buffer["source_config"]["source_key"].as_str(), Some(format!("{p}export").as_str()));
    assert_eq!(buffer["source_config"]["remove_after_export"].as_bool(), Some(true));
    assert!(buffer["max_byte_size"].as_integer().is_some());
    // Nothing of the tap is a pull component, and nothing of it is the lane.
    for kind in ["sources", "transforms", "sinks", "enrichment_tables"] {
        for id in table.get(kind).and_then(toml::Value::as_table).into_iter().flat_map(|t| t.keys()) {
            assert!(!(id.starts_with(p) && id.starts_with(super::pull::PULL_COMPONENT_PREFIX)), "{id}");
        }
    }
    let router = &text(&tree, super::overlay::ROUTER_FILE);
    assert!(!router.contains(p), "the lane never reads the tap");
    // The loss fence never sees the tap's discards.
    let select = component(&table, "transforms", super::pull::PULL_LOSS_SELECT)["condition"].as_str().unwrap();
    assert!(
        select.contains(&format!("tap = starts_with(component, \"{p}\")\n(!tap && .name == \"component_discarded_events_total\") ||\n")),
        "{select}"
    );

    // The full (ingest) bundle does not change with capture.
    let plain = generate(tenant_sources(), Some(sources));
    assert_eq!(plain.bundle, outcome.bundle);
    assert_ne!(
        plain.report.pull_bundle.unwrap().pull_bundle_sha256,
        outcome.report.pull_bundle.unwrap().pull_bundle_sha256
    );
}

#[test]
fn without_capture_the_pull_bundle_names_no_capture_component_or_host() {
    let tree = pull_tree(&generate(tenant_sources(), Some(every_kind())));
    let all = all_text(&tree);
    assert!(!all.contains(super::pull::CAPTURE_COMPONENT_PREFIX));
    assert!(!all.contains(super::pull::PIPE_CAPTURE_HOST));
}

#[test]
fn pull_capture_is_opt_in_and_needs_pull_sources() {
    let request: serde_json::Value =
        serde_json::from_slice(&inputs(tenant_sources(), Some(pulls())).build_json).unwrap();
    assert!(request.get("pull_capture").is_none(), "false must not serialize");
    let on: serde_json::Value =
        serde_json::from_slice(&inputs_with(tenant_sources(), Some(pulls()), true).build_json).unwrap();
    assert_eq!(on["pull_capture"], serde_json::json!(true));
    let refused = super::build::generate(&inputs_with(tenant_sources(), None, true));
    assert!(!refused.ok());
    let message = format!("{:?}", refused.report.failure);
    assert!(message.contains("pull_capture requires pull_sources"), "{message}");
}

#[test]
fn a_base_already_using_the_capture_prefix_is_refused_only_for_capture() {
    use super::pull;
    let mut tree = base();
    let path = super::overlay::LAKE_SINK_FILE;
    let mut text = tree.text(path).unwrap().to_string();
    text.push_str("\n[enrichment_tables.nano_pipe_capture_sessions]\ntype = \"memory\"\n");
    tree.put(path, text.into_bytes());
    let uuid = uuid::Uuid::from_u128(TENANT_UUID);
    assert!(pull::pull_base(&tree, &pulls(), uuid, false).is_ok());
    let error = pull::pull_base(&tree, &pulls(), uuid, true).unwrap_err();
    assert!(format!("{error}").contains("already declares nano_pipe_capture_sessions"), "{error}");
}

fn vrl_of(table: &toml::Table, kind: &str, id: &str, field: &str) -> String {
    component(table, kind, id)[field].as_str().unwrap().to_string()
}

#[test]
fn the_tap_vrl_keeps_only_message_and_lane_and_bounds_the_message() {
    let tree = pull_tree(&generate_capture(pulls()));
    let table = pull_sources_table(&tree);
    let p = super::pull::CAPTURE_COMPONENT_PREFIX;
    let shape = vrl_of(&table, "transforms", &format!("{p}shape"), "source");
    let one = |event: serde_json::Value| {
        let (out, _) = run_stamp(&shape, event);
        let map = out.as_object().unwrap().clone();
        assert_eq!(map.len(), 1, "one uniquely keyed buffer entry");
        let (key, value) = map.into_iter().next().unwrap();
        assert!(uuid::Uuid::parse_str(&key).is_ok(), "{key}");
        value
    };
    assert_eq!(
        one(serde_json::json!({"message": "m", "source_type": "aws_cloudtrail", "object": "AWSLogs/k",
            "metadata": {"forwarded_via": "pull"}, "auth_status": "authenticated"})),
        serde_json::json!({"message": "m", "source_type": "aws_cloudtrail"})
    );
    assert_eq!(
        one(serde_json::json!({"message": {"a": 1}, "source_type": "x"})),
        serde_json::json!({"message": "{\"a\":1}", "source_type": "x"})
    );
    let long = "y".repeat(super::pull::CAPTURE_MAX_MESSAGE_BYTES as usize + 1);
    assert_eq!(
        one(serde_json::json!({"message": long, "source_type": "x"})),
        serde_json::json!({"message": "", "source_type": "x", "truncated": true})
    );

    let active = vrl_of(&table, "transforms", &format!("{p}active"), "source");
    let (out, _) = run_stamp(&active, serde_json::json!({
        "active": {"aws_cloudtrail": 1, "Bad Slug": 1, "apache_access": 0, "x": "1"},
        "source_type": "http_client", "timestamp": "2026-10-11T00:00:00Z"
    }));
    assert_eq!(out, serde_json::json!({"aws_cloudtrail": 1}), "only well-formed active slugs become table keys");
    let (out, _) = run_stamp(&active, serde_json::json!({"error": "nope"}));
    assert_eq!(out, serde_json::json!({}));
}
