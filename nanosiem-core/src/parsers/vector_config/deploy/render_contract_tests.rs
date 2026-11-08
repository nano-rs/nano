// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4952 / NAN-4953: the contracts between what the deploy writes and what
//! Vector loads.
//!
//! * NAN-4952: every parser file that reads `source_router.<name>` has a
//!   `<name>` route in `_router.toml`, and no route exists without its file —
//!   for every `source_type` spelling the API accepts, across draft (disabled)
//!   and published (enabled) states, in both the active and the staged writer.
//! * NAN-4953: every file carrying tenant text is escaped against Vector's env
//!   interpolation; substituting it the way Vector does yields the tenant's
//!   text, never an environment value.

use super::*;

use std::collections::BTreeSet;
use tempfile::TempDir;

fn parser(name: &str, source_type: &str, enabled: bool) -> Parser {
    Parser {
        id: uuid::Uuid::new_v4(),
        name: name.to_string(),
        description: None,
        source_type: source_type.to_string(),
        parser_vrl: ".parsed = true".to_string(),
        output_fields: None,
        feed_id: None,
        dispatch_source_config_id: None,
        dispatch_route_name: None,
        enabled,
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

/// Parse a rendered file the way Vector will: substitute env interpolation
/// (escaped `$$` back to `$`) with an empty environment, then TOML.
fn load(path: &std::path::Path) -> toml::Table {
    let raw = std::fs::read_to_string(path).unwrap();
    toml::from_str(&crate::vector_env::substitute_like_vector(&raw))
        .unwrap_or_else(|e| panic!("{} is not valid TOML after substitution: {e}\n{raw}", path.display()))
}

/// Route names in `[transforms.source_router.route]`.
fn router_routes(parsers_dir: &std::path::Path) -> BTreeSet<String> {
    let doc = load(&parsers_dir.join("_router.toml"));
    doc["transforms"]["source_router"]["route"]
        .as_table()
        .unwrap()
        .keys()
        .filter(|k| k.as_str() != "generic")
        .cloned()
        .collect()
}

/// Every `source_router.<route>` named as an input by a per-parser file.
fn parser_router_inputs(parsers_dir: &std::path::Path) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for entry in std::fs::read_dir(parsers_dir).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(".toml") || matches!(name.as_str(), "_router.toml" | "_combiner.toml" | "_pipeline.toml" | "_enrichment.toml" | "_ocsf_sink.toml") {
            continue;
        }
        let doc = load(&entry.path());
        for (_, transform) in doc.get("transforms").and_then(|t| t.as_table()).into_iter().flatten() {
            for input in transform.get("inputs").and_then(|i| i.as_array()).into_iter().flatten() {
                if let Some(route) = input.as_str().and_then(|s| s.strip_prefix("source_router.")) {
                    out.insert(route.to_string());
                }
            }
        }
    }
    out
}

/// The spellings that reach `source_router` (`http` passes
/// `SourceType::from_str`; unrecognized labels default to the router) plus the
/// canonical ones.
const ROUTED_SPELLINGS: &[&str] = &["routed", "http", "vector", "acme_vpn_label"];

#[tokio::test]
async fn every_router_input_has_its_route_for_every_accepted_spelling() {
    let dir = TempDir::new().unwrap();
    let mgr = VectorConfigManager::new(dir.path());
    let parsers: Vec<Parser> = ROUTED_SPELLINGS
        .iter()
        .enumerate()
        .map(|(i, st)| parser(&format!("src_{i}"), st, true))
        .collect();
    mgr.deploy_parsers(&parsers).await.unwrap();

    let inputs = parser_router_inputs(mgr.parsers_dir());
    let routes = router_routes(mgr.parsers_dir());
    assert_eq!(inputs.len(), ROUTED_SPELLINGS.len(), "every spelling renders a router-fed parser: {inputs:?}");
    assert_eq!(inputs, routes, "parser inputs and router routes must be the same set");
}

/// The NAN-4952 sequence on the renderer: a draft (disabled) source is in
/// neither half; publishing it (enabled) puts it in both; another source and a
/// later re-publish keep both halves equal. Active AND staged writers.
#[tokio::test]
async fn draft_to_published_transitions_keep_router_and_parser_files_in_lockstep() {
    for spelling in ROUTED_SPELLINGS {
        let dir = TempDir::new().unwrap();
        let mgr = VectorConfigManager::new(dir.path());
        let mut draft = parser("draft_src", spelling, false);
        let normal = parser("normal_src", "routed", true);

        let steps: Vec<(&str, Vec<Parser>)> = vec![
            ("draft only", vec![draft.clone()]),
            ("draft + normal", vec![draft.clone(), normal.clone()]),
            ("draft published", {
                draft.enabled = true;
                vec![draft.clone(), normal.clone()]
            }),
            ("draft unpublished", {
                draft.enabled = false;
                vec![draft.clone(), normal.clone()]
            }),
        ];
        for (label, set) in steps {
            mgr.deploy_parsers(&set).await.unwrap();
            let inputs = parser_router_inputs(mgr.parsers_dir());
            let routes = router_routes(mgr.parsers_dir());
            assert_eq!(inputs, routes, "[{spelling} / {label}] active tree diverged");
            let expected: BTreeSet<String> = set
                .iter()
                .filter(|p| p.enabled)
                .map(|p| VectorConfigManager::safe_name(&p.name))
                .collect();
            assert_eq!(routes, expected, "[{spelling} / {label}] route set");

            mgr.stage_parsers(&set).await.unwrap();
            let staged = mgr.staging_dir().join("sources").join("parsers");
            assert_eq!(
                parser_router_inputs(&staged),
                router_routes(&staged),
                "[{spelling} / {label}] staged tree diverged"
            );
            mgr.cleanup_staging().await.unwrap();
        }
    }
}

/// Fetch transports never read `source_router`, so they never get a route,
/// enabled or not.
#[tokio::test]
async fn fetch_and_hec_parsers_get_no_source_router_route() {
    let dir = TempDir::new().unwrap();
    let mgr = VectorConfigManager::new(dir.path());
    let mut kafka = parser("kafka_src", "kafka", true);
    kafka.dispatch_route_name = Some("my_kafka_route".to_string());
    let hec = parser("hec_src", "splunk_hec", true);
    let routed = parser("routed_src", "routed", true);
    let set = vec![kafka.clone(), hec.clone(), routed.clone()];
    let routed_set: Vec<&str> = mgr
        .source_router_parsers(&set)
        .into_iter()
        .map(|p| p.name.as_str())
        .collect();
    assert_eq!(routed_set, vec!["routed_src"]);
}

const LEAK: &str = ".leak = \"${CLICKHOUSE_PASSWORD}\" + \"$VECTOR_AUTH_TOKEN\"\n.capture = replace(\"ab\", r'(a)', \"$1\")";

/// NAN-4953: a parser's VRL reaches the live config only escaped. Vector's
/// substitution of the written file gives back the tenant's text exactly.
#[tokio::test]
async fn parser_and_router_files_are_env_escaped() {
    let dir = TempDir::new().unwrap();
    let mgr = VectorConfigManager::new(dir.path());
    let mut p = parser("leaky", "routed", true);
    p.parser_vrl = LEAK.to_string();
    p.match_values = Some(vec!["k'ey$HOME\"x".to_string()]);
    p.extension_enabled = true;
    p.extension_vrl = Some(".ext = \"${CLICKHOUSE_USER}\"".to_string());
    p.sampling_ratio = Some(0.5);
    p.sampling_exclude_condition = Some(".x == \"$HOME\"".to_string());
    mgr.deploy_parsers(&[p]).await.unwrap();

    for file in ["leaky.toml", "_router.toml"] {
        let raw = std::fs::read_to_string(mgr.parsers_dir().join(file)).unwrap();
        assert!(raw.starts_with(crate::vector_env::ENV_ESCAPED_HEADER), "{file}:\n{raw}");
        assert!(
            !crate::vector_env::contains_env_interpolation(&raw),
            "{file} still holds live interpolation syntax:\n{raw}"
        );
    }
    let parser_doc = load(&mgr.parsers_dir().join("leaky.toml"));
    let source = parser_doc["transforms"]["leaky_parse"]["source"].as_str().unwrap();
    assert!(source.contains(LEAK), "parse VRL must survive substitution byte for byte:\n{source}");
    let ext = parser_doc["transforms"]["leaky_extension"]["source"].as_str().unwrap();
    assert!(ext.contains(".ext = \"${CLICKHOUSE_USER}\""), "{ext}");

    // The router condition carries the tenant match value literally (quotes
    // escaped, `$` intact after substitution) and is valid TOML.
    let router = load(&mgr.parsers_dir().join("_router.toml"));
    let cond = router["transforms"]["source_router"]["route"]["leaky"].as_str().unwrap();
    assert_eq!(cond, ".source_type == \"k'ey$HOME\\\"x\"");
}

/// The staged writer escapes exactly like the active one (promotion copies the
/// staged files over the active tree).
#[tokio::test]
async fn staged_parser_files_are_env_escaped() {
    let dir = TempDir::new().unwrap();
    let mgr = VectorConfigManager::new(dir.path());
    let mut p = parser("leaky", "routed", true);
    p.parser_vrl = LEAK.to_string();
    mgr.stage_parsers(&[p]).await.unwrap();
    let staged = mgr.staging_dir().join("sources").join("parsers");
    for file in ["leaky.toml", "_router.toml"] {
        let raw = std::fs::read_to_string(staged.join(file)).unwrap();
        assert!(raw.starts_with(crate::vector_env::ENV_ESCAPED_HEADER), "{file}:\n{raw}");
        assert!(!crate::vector_env::contains_env_interpolation(&raw), "{file}:\n{raw}");
    }
}

/// `_enrichment.toml` keeps nano's own `${CLICKHOUSE_*}` but an enrichment
/// parser's normalize VRL is escaped where it is embedded.
#[test]
fn enrichment_normalize_vrl_is_escaped_but_nano_sinks_still_interpolate() {
    let mut p = parser("Okta Users", "routed", true);
    p.kind = "enrichment".to_string();
    p.enrich_kind = Some("identity".to_string());
    p.enrich_source = Some("okta".to_string());
    p.target_table = Some("user_registry".to_string());
    p.normalize_vrl = Some(".leak = \"${CLICKHOUSE_PASSWORD}\"".to_string());
    let lane = VectorConfigManager::enrichment_lane_config(&[p]);
    assert!(lane.starts_with(crate::vector_env::ENV_ESCAPED_TENANT_HEADER), "{lane}");
    assert!(lane.contains(".leak = \"$${CLICKHOUSE_PASSWORD}\""), "{lane}");
    assert!(lane.contains("auth.password = \"${CLICKHOUSE_PASSWORD:-nanosiem}\""), "{lane}");
    let after = crate::vector_env::substitute_like_vector(&lane);
    assert!(after.contains(".leak = \"${CLICKHOUSE_PASSWORD}\""), "{after}");
    assert!(after.contains("auth.password = \"nanosiem\""), "{after}");
}
