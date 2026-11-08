// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4956: the render never names a source-config route that is not on disk.
//!
//! A fetch parser bound to `<config>_route` used to keep its `_filter` and its
//! `<route>_unclaimed` claim after the config's file was removed (delete or
//! undeploy), and Vector refused every reload. The render now leaves such a
//! parser out until its route exists again.

use super::*;

use std::collections::BTreeSet;
use tempfile::TempDir;

fn kafka_parser(name: &str, route: Option<&str>) -> Parser {
    Parser {
        id: uuid::Uuid::new_v4(),
        name: name.to_string(),
        description: None,
        source_type: "kafka".to_string(),
        parser_vrl: ".parsed = true".to_string(),
        output_fields: None,
        feed_id: None,
        dispatch_source_config_id: route.map(|_| uuid::Uuid::new_v4()),
        dispatch_route_name: route.map(str::to_string),
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
        match_values: Some(vec![format!("{name}_key")]),
        sampling_ratio: None,
        sampling_exclude_condition: None,
        extension_vrl: None,
        extension_enabled: false,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

/// The routing file a deployed source config writes (`<stem>_route`).
fn deploy_config(dir: &std::path::Path, stem: &str) {
    let configs = dir.join("sources").join("configs");
    std::fs::create_dir_all(&configs).unwrap();
    std::fs::write(
        configs.join(format!("{stem}.toml")),
        format!(
            "# nano-env-escaped: v1\n[sources.{stem}_source]\ntype = \"demo_logs\"\nformat = \"shuffle\"\n\n\
             [transforms.{stem}_route]\ntype = \"remap\"\ninputs = [\"{stem}_source\"]\nsource = \".a = 1\"\n"
        ),
    )
    .unwrap();
}

fn undeploy_config(dir: &std::path::Path, stem: &str) {
    std::fs::remove_file(dir.join("sources").join("configs").join(format!("{stem}.toml"))).unwrap();
}

/// Every component any rendered parser-tree file names as an input.
fn named_inputs(parsers_dir: &std::path::Path) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for entry in std::fs::read_dir(parsers_dir).unwrap().flatten() {
        if !entry.file_name().to_string_lossy().ends_with(".toml") {
            continue;
        }
        let raw = std::fs::read_to_string(entry.path()).unwrap();
        let Ok(doc) = toml::from_str::<toml::Table>(&crate::vector_env::substitute_like_vector(&raw)) else {
            continue; // _pipeline.toml etc. carry unquoted interpolation; not parser inputs.
        };
        for section in ["transforms", "sinks"] {
            for (_, c) in doc.get(section).and_then(|t| t.as_table()).into_iter().flatten() {
                for i in c.get("inputs").and_then(|i| i.as_array()).into_iter().flatten() {
                    if let Some(s) = i.as_str() {
                        out.insert(s.to_string());
                    }
                }
            }
        }
    }
    out
}

#[tokio::test]
async fn a_bound_parser_is_left_out_while_its_route_is_not_deployed() {
    let dir = TempDir::new().unwrap();
    let mgr = VectorConfigManager::new(dir.path());
    let parser = kafka_parser("orders", Some("kafka_orders_route"));

    // Config deployed: the parser is rendered with its filter and claim.
    deploy_config(dir.path(), "kafka_orders");
    mgr.deploy_parsers(&[parser.clone()]).await.unwrap();
    assert!(mgr.parsers_dir().join("orders.toml").exists());
    let inputs = named_inputs(mgr.parsers_dir());
    assert!(inputs.contains("kafka_orders_route"), "{inputs:?}");

    // Config undeployed/deleted, parser row still bound: nothing names the route.
    undeploy_config(dir.path(), "kafka_orders");
    mgr.deploy_parsers(&[parser.clone()]).await.unwrap();
    assert!(!mgr.parsers_dir().join("orders.toml").exists(), "parser file must be pruned");
    let inputs = named_inputs(mgr.parsers_dir());
    assert!(
        !inputs.iter().any(|i| i.starts_with("kafka_orders_route")),
        "a removed route is still named: {inputs:?}"
    );

    // Deployed again: back in.
    deploy_config(dir.path(), "kafka_orders");
    mgr.deploy_parsers(&[parser]).await.unwrap();
    assert!(mgr.parsers_dir().join("orders.toml").exists());
}

#[tokio::test]
async fn the_staged_tree_prunes_the_same_way() {
    let dir = TempDir::new().unwrap();
    let mgr = VectorConfigManager::new(dir.path());
    let parser = kafka_parser("orders", Some("kafka_orders_route"));
    mgr.stage_parsers(&[parser]).await.unwrap();
    let staged = mgr.staging_dir().join("sources").join("parsers");
    assert!(!staged.join("orders.toml").exists());
    let inputs = named_inputs(&staged);
    assert!(!inputs.iter().any(|i| i.starts_with("kafka_orders_route")), "{inputs:?}");
}

#[tokio::test]
async fn an_unbound_fetch_parser_is_never_rendered() {
    let dir = TempDir::new().unwrap();
    let mgr = VectorConfigManager::new(dir.path());
    mgr.deploy_parsers(&[kafka_parser("loose", None)]).await.unwrap();
    assert!(!mgr.parsers_dir().join("loose.toml").exists());
    let inputs = named_inputs(mgr.parsers_dir());
    assert!(!inputs.contains("source_router.loose"), "{inputs:?}");
}
