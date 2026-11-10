// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4902 regression: on a fresh install the Splunk HEC source config is
//! disabled, so `sources/configs/splunk_hec.toml` (the only place
//! `splunk_hec_route` is defined) does not exist. Deploying an HEC parser used
//! to render a parser filter and a `splunk_hec_route_unclaimed` filter that
//! named the missing transform, and a cold-started Vector refused the whole
//! config and crash-looped.
//!
//! `splunk_hec_route` is now permanent (passthrough when the HEC source config
//! is not deployed or has no rules). These render real bundles with
//! `VectorConfigManager` and run `vector validate --no-environment` on the
//! pinned image in a throwaway container, for the fresh install and for the
//! enabled→disabled and disabled→enabled transitions — with an HEC parser
//! deployed (and deliberately NOT re-rendered across the transition, the
//! codex P1 case) and with no parser deployed. "Disabled" uses the exact
//! helper the source-config undeploy calls. Needs docker:
//!
//! ```text
//! NANOSIEM_TEST_VECTOR_IMAGE=ghcr.io/nano-rs/vector:0.61.0-nano.8-debian \
//!   cargo test -p nanosiem-core --test fresh_install_hec_parser_vector_validate -- --ignored --test-threads=1
//! ```

use std::path::Path;

use chrono::Utc;
use nanosiem_core::parsers::vector_hec_route::{write_passthrough_route, SPLUNK_HEC_ROUTE_FILE};
use nanosiem_core::parsers::{Parser, VectorConfigManager};
use uuid::Uuid;

fn hec_parser() -> Parser {
    Parser {
        id: Uuid::new_v4(),
        name: "Windows Sysmon HEC".to_string(),
        description: None,
        source_type: "splunk_hec".to_string(),
        parser_vrl: ".parsed = true".to_string(),
        output_fields: None,
        feed_id: None,
        dispatch_source_config_id: None,
        dispatch_route_name: None,
        enabled: true,
        validated: true,
        validation_error: None,
        category: None,
        vendor: None,
        product: None,
        kind: "log".to_string(),
        enrich_kind: None,
        enrich_source: None,
        target_table: None,
        normalize_vrl: None,
        namespace: "default".to_string(),
        timezone: "UTC".to_string(),
        match_values: Some(vec!["windows_sysmon".to_string()]),
        sampling_ratio: None,
        sampling_exclude_condition: None,
        extension_vrl: None,
        extension_enabled: false,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

/// Every static top-level `config/vector/*.toml` the product ships.
fn copy_static(repo: &Path, dest: &Path) {
    std::fs::create_dir_all(dest).unwrap();
    for entry in std::fs::read_dir(repo.join("config/vector")).unwrap().flatten() {
        let path = entry.path();
        if path.is_file() && path.extension().is_some_and(|e| e == "toml") {
            std::fs::copy(&path, dest.join(entry.file_name())).unwrap();
        }
    }
}

fn walk(dir: &Path, out: &mut String) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "toml") {
                out.push_str(&std::fs::read_to_string(&path).unwrap_or_default());
            }
        }
    }
}

/// The routing transform the source config writes when deployed with rules.
const RULES_FILE: &str = "# Auto-generated routing rules for system-level source: Splunk HEC\n\
[transforms.splunk_hec_route]\n\
inputs = [\"hec_normalize\"]\n\
source = \"\"\"\nif .source_type == \"xmlwineventlog\" {\n    .source_type = \"windows_event\"\n}\n# else: passthrough — keep existing .source_type\n\"\"\"\n\
type = \"remap\"\n";

struct Bundle {
    _work: tempfile::TempDir,
    static_dir: std::path::PathBuf,
    dynamic: std::path::PathBuf,
    vector: VectorConfigManager,
}

fn bundle() -> Bundle {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let work = tempfile::tempdir().unwrap();
    let static_dir = work.path().join("config");
    let dynamic = work.path().join("dynamic");
    copy_static(&repo, &static_dir);
    std::fs::create_dir_all(static_dir.join("dynamic")).unwrap();
    // Fresh install: no source-config routing file is deployed.
    std::fs::create_dir_all(dynamic.join("sources/configs")).unwrap();
    std::fs::create_dir_all(dynamic.join("sources/parsers")).unwrap();
    std::fs::create_dir_all(dynamic.join("ingest-tokens")).unwrap();
    let vector = VectorConfigManager::new(&dynamic);
    Bundle { _work: work, static_dir, dynamic, vector }
}

impl Bundle {
    fn configs(&self) -> std::path::PathBuf {
        self.dynamic.join("sources/configs")
    }
    fn enable_with_rules(&self) {
        std::fs::write(self.configs().join(SPLUNK_HEC_ROUTE_FILE), RULES_FILE).unwrap();
    }
    fn disable(&self) {
        // Exactly what SourceConfigService::undeploy does for splunk_hec.
        write_passthrough_route(&self.configs()).unwrap();
    }
    fn validate(&self, label: &str) {
        let image = std::env::var("NANOSIEM_TEST_VECTOR_IMAGE")
            .expect("NANOSIEM_TEST_VECTOR_IMAGE must name the pinned Vector image");
        let output = std::process::Command::new("docker")
            .args(["run", "--rm"])
            .args(["-e", "VECTOR_AUTH_TOKEN=validate-only"])
            .args(["-e", "CLICKHOUSE_URL=http://clickhouse:8123"])
            .args(["-e", "CLICKHOUSE_USER=nanosiem", "-e", "CLICKHOUSE_PASSWORD=nanosiem"])
            .args(["-e", "VECTOR_BATCH_TIMEOUT_SECS=1"])
            .arg("-v")
            .arg(format!("{}:/etc/vector:ro", self.static_dir.display()))
            .arg("-v")
            .arg(format!("{}:/etc/vector/dynamic:ro", self.dynamic.display()))
            .args([
                image.as_str(),
                // Production starts Vector with this flag (docker-compose), and
                // the shipped configs use `${VAR:-default}` values that need it.
                "--dangerously-allow-env-var-interpolation",
                "validate",
                "--no-environment",
                "--config-dir",
                "/etc/vector",
                "--config-dir",
                "/etc/vector/dynamic/sources/parsers",
                "--config-dir",
                "/etc/vector/dynamic/sources/configs",
            ])
            .output()
            .expect("docker must be runnable");
        let mut rendered = String::new();
        walk(&self.dynamic, &mut rendered);
        assert!(
            output.status.success(),
            "[{label}] bundle failed vector validate:\n{}{}\n--- rendered ---\n{rendered}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if rendered.contains("splunk_hec_route") {
            assert!(
                rendered.contains("[transforms.splunk_hec_route]"),
                "[{label}] names splunk_hec_route without declaring it:\n{rendered}"
            );
        }
    }
}

#[tokio::test]
#[ignore = "requires docker and NANOSIEM_TEST_VECTOR_IMAGE (the pinned Vector image)"]
async fn fresh_install_hec_parser_bundle_passes_vector_validate() {
    let b = bundle();
    b.vector.deploy_parsers(&[hec_parser()]).await.expect("deploy");
    b.validate("fresh install, HEC parser deployed");
}

#[tokio::test]
#[ignore = "requires docker and NANOSIEM_TEST_VECTOR_IMAGE (the pinned Vector image)"]
async fn enabled_to_disabled_with_a_deployed_parser_not_rerendered() {
    let b = bundle();
    b.enable_with_rules();
    b.vector.deploy_parsers(&[hec_parser()]).await.expect("deploy");
    b.validate("enabled, HEC parser deployed");
    b.disable(); // the parser files are NOT regenerated
    b.validate("enabled -> disabled, parser not re-rendered");
}

#[tokio::test]
#[ignore = "requires docker and NANOSIEM_TEST_VECTOR_IMAGE (the pinned Vector image)"]
async fn disabled_to_enabled_with_a_deployed_parser_not_rerendered() {
    let b = bundle();
    b.disable();
    b.vector.deploy_parsers(&[hec_parser()]).await.expect("deploy");
    b.validate("disabled, HEC parser deployed");
    b.enable_with_rules(); // the parser files are NOT regenerated
    b.validate("disabled -> enabled, parser not re-rendered");
}

#[tokio::test]
#[ignore = "requires docker and NANOSIEM_TEST_VECTOR_IMAGE (the pinned Vector image)"]
async fn transitions_with_no_parser_deployed() {
    let b = bundle();
    b.vector.deploy_parsers(&[]).await.expect("render router + pipeline");
    b.validate("fresh install, no parser");
    b.enable_with_rules();
    b.validate("fresh -> enabled, no parser");
    b.disable();
    b.validate("enabled -> disabled, no parser");
    b.enable_with_rules();
    b.validate("disabled -> enabled, no parser");
}

#[tokio::test]
#[ignore = "requires docker and NANOSIEM_TEST_VECTOR_IMAGE (the pinned Vector image)"]
async fn undeploying_the_hec_parser_keeps_a_valid_bundle() {
    let b = bundle();
    b.vector.deploy_parsers(&[hec_parser()]).await.expect("deploy");
    b.validate("HEC parser deployed");
    b.vector.deploy_parsers(&[]).await.expect("undeploy the parser");
    b.validate("HEC parser undeployed, route kept");
    b.disable();
    b.validate("HEC parser undeployed, source config disabled");
}
