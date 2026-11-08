// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4902: `splunk_hec_route` is permanent. A deployed HEC parser always
//! names it, so whenever an HEC parser is rendered the route must exist; the
//! passthrough is written when nothing declares it, and an existing
//! declaration (the source config's routing rules) is never overwritten.

use chrono::Utc;
use uuid::Uuid;

use super::hec_route::{
    ensure_hec_route, hec_route_declared, passthrough_route_toml, write_passthrough_route,
    SPLUNK_HEC_ROUTE_FILE,
};
use super::router::{file_declares_route_transform, route_transform_upstream};
use super::VectorConfigManager;
use crate::parsers::types::Parser;

fn hec_parser() -> Parser {
    Parser {
        id: Uuid::new_v4(),
        name: "Windows Sysmon (HEC)".to_string(),
        description: None,
        source_type: "splunk_hec".to_string(),
        parser_vrl: String::new(),
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

const RULES_FILE: &str = "[transforms.splunk_hec_route]\n\
inputs = [\"hec_normalize\"]\n\
source = \"\"\"\nif .source_type == \"xmlwineventlog\" { .source_type = \"windows_event\" }\n\"\"\"\n\
type = \"remap\"\n";

fn configs(dir: &tempfile::TempDir) -> std::path::PathBuf {
    dir.path().join("sources").join("configs")
}

#[test]
fn the_passthrough_declares_the_route_over_hec_normalize() {
    let toml = passthrough_route_toml();
    assert!(file_declares_route_transform(&toml, "splunk_hec_route"), "{toml}");
    assert_eq!(route_transform_upstream(&toml, "splunk_hec_route").as_deref(), Some("[\"hec_normalize\"]"));
    // The parser writer's coverage scan keys on this exact line.
    assert!(toml.lines().any(|l| l == "inputs = [\"hec_normalize\"]"), "{toml}");
    toml::from_str::<toml::Value>(&toml).expect("valid TOML");
}

#[test]
fn rendering_an_hec_parser_on_a_fresh_install_writes_the_passthrough() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(configs(&dir)).unwrap();
    let mgr = VectorConfigManager::new(dir.path());
    let (config, _) = mgr.generate_source_config(&hec_parser());
    assert!(config.contains("inputs = [\"splunk_hec_route\"]"), "{config}");
    let written = std::fs::read_to_string(configs(&dir).join(SPLUNK_HEC_ROUTE_FILE)).unwrap();
    assert_eq!(written, passthrough_route_toml());
}

#[test]
fn ensure_never_overwrites_the_source_configs_routing_rules() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(configs(&dir)).unwrap();
    std::fs::write(configs(&dir).join(SPLUNK_HEC_ROUTE_FILE), RULES_FILE).unwrap();
    assert!(!ensure_hec_route(&configs(&dir)).unwrap());
    assert_eq!(std::fs::read_to_string(configs(&dir).join(SPLUNK_HEC_ROUTE_FILE)).unwrap(), RULES_FILE);
    let mgr = VectorConfigManager::new(dir.path());
    let (config, _) = mgr.generate_source_config(&hec_parser());
    assert!(config.contains("inputs = [\"splunk_hec_route\"]"), "{config}");
    assert_eq!(std::fs::read_to_string(configs(&dir).join(SPLUNK_HEC_ROUTE_FILE)).unwrap(), RULES_FILE);
}

#[test]
fn undeploy_replaces_rules_with_the_passthrough_and_never_removes_the_route() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(configs(&dir)).unwrap();
    std::fs::write(configs(&dir).join(SPLUNK_HEC_ROUTE_FILE), RULES_FILE).unwrap();
    write_passthrough_route(&configs(&dir)).unwrap();
    assert!(hec_route_declared(&configs(&dir)));
    assert_eq!(
        std::fs::read_to_string(configs(&dir).join(SPLUNK_HEC_ROUTE_FILE)).unwrap(),
        passthrough_route_toml()
    );
    // No temp file left behind for Vector's watcher to see.
    let leftovers: Vec<_> = std::fs::read_dir(configs(&dir))
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
        .collect();
    assert!(leftovers.is_empty());
}
