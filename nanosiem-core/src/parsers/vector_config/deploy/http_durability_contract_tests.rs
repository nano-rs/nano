// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5004: pin the HTTP/OTLP durable-success contract at render time.
//!
//! The nano Vector 0.61 fork waits on a source batch notifier. Disk-buffer
//! writers finalize after accepting a complete record, while transforms and
//! buffers that discard an event report `Dropped`; the batch aggregator treats
//! `Dropped` as delivered. Consequently the durable protocol paths must avoid
//! silent-drop transforms and must block, not drop, at buffer capacity.

use super::*;

const HTTP_BASE: &str = include_str!("../../../../../config/vector/00-base.toml");
const OTLP: &str = include_str!("../../../../../config/vector/03-otlp-source.toml");
const ENRICH_SOURCE: &str = include_str!("../../../../../config/vector/04-enrichment-source.toml");
const SEED_PIPELINE: &str =
    include_str!("../../../../../config/vector/sources/parsers/_pipeline.toml");

fn repo_file(path: &str) -> Option<String> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("nanosiem-core has a repository parent")
        .join(path);
    if !path.exists() {
        // The open-core mirror intentionally strips deploy/, including the
        // enterprise Helm chart. Keep those paths out of include_str! so the
        // public Rust tree still compiles; parity is asserted in private trees.
        return None;
    }
    Some(std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display())))
}

fn load(raw: &str) -> toml::Table {
    toml::from_str(&crate::vector_env::substitute_like_vector(raw))
        .unwrap_or_else(|e| panic!("not valid TOML after substitution: {e}\n{raw}"))
}

fn enabled(table: &toml::Table, section: &str, name: &str) -> Option<bool> {
    table
        .get(section)
        .and_then(|v| v.get(name))
        .and_then(|v| v.get("acknowledgements"))
        .and_then(|v| v.get("enabled"))
        .and_then(toml::Value::as_bool)
}

fn when_full<'a>(table: &'a toml::Table, sink: &str) -> Option<&'a str> {
    table
        .get("sinks")
        .and_then(|v| v.get(sink))
        .and_then(|v| v.get("buffer"))
        .and_then(|v| v.get("when_full"))
        .and_then(toml::Value::as_str)
}

fn buffer_type<'a>(table: &'a toml::Table, sink: &str) -> Option<&'a str> {
    table
        .get("sinks")
        .and_then(|v| v.get(sink))
        .and_then(|v| v.get("buffer"))
        .and_then(|v| v.get("type"))
        .and_then(toml::Value::as_str)
}

fn assert_disk_buffers_meet_vector_minimum(label: &str, raw: &str) {
    let doc = load(raw);
    let sinks = doc
        .get("sinks")
        .and_then(toml::Value::as_table)
        .unwrap_or_else(|| panic!("{label}: rendered config has no sinks"));
    let mut disk_buffers = 0;

    for (sink, def) in sinks {
        let Some(buffer) = def.get("buffer").and_then(toml::Value::as_table) else {
            continue;
        };
        if buffer.get("type").and_then(toml::Value::as_str) != Some("disk") {
            continue;
        }
        disk_buffers += 1;
        let max_size = buffer
            .get("max_size")
            .and_then(toml::Value::as_integer)
            .unwrap_or_else(|| panic!("{label}: {sink} disk buffer has no integer max_size"));
        assert!(
            max_size >= VECTOR_DISK_BUFFER_MIN_BYTES,
            "{label}: {sink} disk buffer max_size {max_size} is below Vector's {VECTOR_DISK_BUFFER_MIN_BYTES}-byte minimum"
        );
    }

    assert!(
        disk_buffers > 0,
        "{label}: no rendered disk buffers inspected"
    );
}

fn input_bases(def: &toml::Value) -> Vec<String> {
    def.get("inputs")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(toml::Value::as_str)
        .map(|input| input.split('.').next().unwrap_or(input).to_string())
        .collect()
}

fn assert_enrichment_terminals(label: &str, router_raw: &str, lane_raw: &str) {
    use std::collections::{HashMap, HashSet};

    let source = load(ENRICH_SOURCE);
    let router = load(router_raw);
    let lane = load(lane_raw);
    assert_eq!(enabled(&source, "sources", "enrichment_ingest"), Some(true));
    assert_eq!(
        router["transforms"]["enrichment_router"]["inputs"]
            .as_array()
            .and_then(|inputs| inputs.first())
            .and_then(toml::Value::as_str),
        Some("enrichment_ingest_prepare"),
        "{label}: enrichment must not share a log-source backpressure domain"
    );

    let mut components: HashMap<String, (&str, &toml::Value)> = HashMap::new();
    for doc in [&source, &router, &lane] {
        for section in ["sources", "transforms", "sinks"] {
            if let Some(entries) = doc.get(section).and_then(toml::Value::as_table) {
                for (name, def) in entries {
                    components.insert(name.clone(), (section, def));
                }
            }
        }
    }

    let mut downstream: HashMap<String, Vec<String>> = HashMap::new();
    for (name, (_, def)) in &components {
        for input in input_bases(def) {
            downstream.entry(input).or_default().push(name.clone());
        }
    }

    let mut seen = HashSet::new();
    let mut stack = vec!["enrichment_ingest".to_string()];
    let mut sinks = Vec::new();
    while let Some(component) = stack.pop() {
        if !seen.insert(component.clone()) {
            continue;
        }
        let (section, _) = components
            .get(&component)
            .unwrap_or_else(|| panic!("{label}: unresolved component {component}"));
        if *section == "sinks" {
            sinks.push(component);
            continue;
        }
        let next = downstream.get(&component).cloned().unwrap_or_default();
        assert!(
            !next.is_empty(),
            "{label}: reachable {component} has no terminal path"
        );
        stack.extend(next);
    }

    sinks.sort();
    sinks.dedup();
    assert!(
        sinks.iter().any(|name| name.starts_with("clickhouse_")),
        "{label}: no success sink"
    );
    assert!(
        sinks.iter().any(|name| name == "enrichment_dead_letter"),
        "{label}: no dead-letter sink"
    );
    for sink in sinks {
        assert_eq!(buffer_type(&lane, &sink), Some("disk"), "{label}: {sink}");
        assert_eq!(when_full(&lane, &sink), Some("block"), "{label}: {sink}");
        assert_eq!(
            enabled(&lane, "sinks", &sink),
            Some(false),
            "{label}: {sink}"
        );
    }
    assert_eq!(
        lane["sinks"]["enrichment_dead_letter"]["type"].as_str(),
        Some("clickhouse")
    );
    assert_eq!(
        lane["sinks"]["enrichment_dead_letter"]["table"].as_str(),
        Some("ingestion_errors")
    );
}

#[test]
fn http_success_waits_for_downstream_finalizers_without_a_throttle_drop() {
    let doc = load(HTTP_BASE);
    assert_eq!(enabled(&doc, "sources", "http_ingest"), Some(true));

    let transforms = doc["transforms"].as_table().expect("transforms");
    assert!(
        !transforms.contains_key("rate_limit"),
        "Vector throttle silently finalizes discarded events as Delivered"
    );
    assert_eq!(
        transforms["parse_content"]["inputs"]
            .as_array()
            .and_then(|inputs| inputs.first())
            .and_then(toml::Value::as_str),
        Some("rate_limit_prep")
    );
    assert!(
        transforms["parse_content"]["source"]
            .as_str()
            .is_some_and(|source| source.contains("%nano_durable_ingest = true")),
        "HTTP must stamp the protected sampling-bypass marker"
    );
}

#[test]
fn durable_protocols_bypass_dedupe_and_event_buffers_never_drop_newest() {
    for (label, raw) in [
        ("seed", SEED_PIPELINE),
        ("generated", VectorConfigManager::pipeline_config_content()),
    ] {
        let doc = load(raw);
        let route = &doc["transforms"]["durable_delivery_route"]["route"];
        assert!(
            route["durable"]
                .as_str()
                .is_some_and(|v| v.contains("http") && v.contains("otlp")),
            "{label}: durable protocol route is missing"
        );
        assert_eq!(when_full(&doc, "clickhouse_logs"), Some("block"), "{label}");
        assert_eq!(
            when_full(&doc, "clickhouse_parser_health"),
            Some("block"),
            "{label}"
        );
    }
}

#[test]
fn otlp_success_is_explicit_and_capacity_backpressures() {
    let doc = load(OTLP);
    assert_eq!(enabled(&doc, "sources", "otlp_ingest"), Some(true));
    assert!(
        doc["transforms"]["otlp_logs_prep"]["source"]
            .as_str()
            .is_some_and(|source| source.contains("%nano_durable_ingest = true")),
        "OTLP logs must stamp the protected sampling-bypass marker"
    );
    for sink in ["clickhouse_otel_spans", "clickhouse_otel_metrics"] {
        assert_eq!(buffer_type(&doc, sink), Some("disk"), "{sink}");
        assert_eq!(when_full(&doc, sink), Some("block"), "{sink}");
        assert_eq!(enabled(&doc, "sinks", sink), Some(false), "{sink}");
    }
}

#[test]
fn enrichment_source_isolated_and_all_rendered_terminals_are_durable() {
    let static_router = super::super::router::enrichment_router_block(
        &[],
        super::super::router::ENRICHMENT_ROUTER_INPUT,
    );
    let static_lane = VectorConfigManager::static_enrichment_lane();
    assert_enrichment_terminals("static", &static_router, &static_lane);

    let parser = super::super::router::builtin_identity_parser(
        &crate::identity::normalizers::BUILTIN_IDENTITY_NORMALIZERS[0],
    );
    let generated_router = super::super::router::enrichment_router_block(
        &[&parser],
        super::super::router::ENRICHMENT_ROUTER_INPUT,
    );
    let generated_lane = VectorConfigManager::generate_enrichment_lane(&[&parser]);
    assert_enrichment_terminals("generated", &generated_router, &generated_lane);
}

#[test]
fn every_rendered_disk_buffer_meets_vector_runtime_minimum() {
    let parser = super::super::router::builtin_identity_parser(
        &crate::identity::normalizers::BUILTIN_IDENTITY_NORMALIZERS[0],
    );
    let rendered = [
        ("compose pipeline seed", SEED_PIPELINE.to_string()),
        (
            "generated pipeline",
            VectorConfigManager::pipeline_config_content().to_string(),
        ),
        ("compose OTLP", OTLP.to_string()),
        (
            "static enrichment lane",
            VectorConfigManager::static_enrichment_lane(),
        ),
        (
            "generated enrichment lane",
            VectorConfigManager::generate_enrichment_lane(&[&parser]),
        ),
    ];

    for (label, raw) in rendered {
        assert_disk_buffers_meet_vector_minimum(label, &raw);
    }
}

#[test]
fn helm_vector_seeds_match_compose_seeds() {
    let Some(http) = repo_file("deploy/helm/nano/files/vector/00-base.toml") else {
        return;
    };
    let otlp = repo_file("deploy/helm/nano/files/vector/03-otlp-source.toml")
        .expect("Helm seed set is complete");
    let enrich = repo_file("deploy/helm/nano/files/vector/04-enrichment-source.toml")
        .expect("Helm seed set is complete");
    assert_eq!(http, HTTP_BASE, "Helm HTTP seed drifted");
    assert_eq!(otlp, OTLP, "Helm OTLP seed drifted");
    assert_eq!(enrich, ENRICH_SOURCE, "Helm enrichment source drifted");
}

/// NAN-5285: the durable-2xx contract depends on the Vector image (the
/// fsync-before-ack disk buffer is nano-rs/vector 0.61.0-nano.10+). Every
/// shipped pin must name the same image and digest, so a bump can't leave one
/// install path (compose, open core, the image locks) on an older buffer.
#[test]
fn every_shipped_vector_pin_names_one_image() {
    fn pins(text: &str) -> Vec<String> {
        text.lines()
            .filter_map(|line| {
                let at = line.find("ghcr.io/nano-rs/vector:")?;
                let rest = &line[at..];
                // `image@sha256:…` (compose) or `image sha256:…` (locks).
                let pin: String = rest
                    .split_whitespace()
                    .take(2)
                    .collect::<Vec<_>>()
                    .join(" ")
                    .replace(" sha256:", "@sha256:");
                Some(pin.split_whitespace().next().unwrap_or_default().to_string())
            })
            .collect()
    }
    let mut seen: Vec<(String, String)> = Vec::new();
    for path in [
        "docker-compose.yml",
        "docker-compose.opensource.yml",
        "images.lock",
        "deploy/release/images.enterprise.lock",
        "deploy/k8s/vector/vector.yaml",
        "deploy/k8s/rackspace/vector.yaml",
        "deploy/templates/vector-s3-sync.docker-compose.yml",
    ] {
        let Some(text) = repo_file(path) else { continue };
        for pin in pins(&text) {
            seen.push((path.to_string(), pin));
        }
    }
    // The Helm chart pins Vector in `nano.imagePins` as separate tag/digest
    // lines (NAN-5280); `nano.shippedImagePins` (older refs) is skipped.
    let helm_pins = "deploy/helm/nano/templates/_image_pins.tpl";
    if let Some(text) = repo_file(helm_pins) {
        let block = text
            .split("{{- define \"nano.imagePins\" -}}")
            .nth(1)
            .and_then(|rest| rest.split("{{- end -}}").next())
            .expect("nano.imagePins block");
        let mut lines = block.lines().skip_while(|l| l.trim() != "vector:").skip(1);
        let mut field = |name: &str| -> String {
            lines
                .next()
                .and_then(|l| l.trim().strip_prefix(&format!("{name}: ")).map(str::to_string))
                .unwrap_or_else(|| panic!("{helm_pins}: vector {name} line"))
        };
        let (repo, tag, digest) = (field("repository"), field("tag"), field("digest"));
        seen.push((helm_pins.to_string(), format!("{repo}:{tag}@{digest}")));
    }
    assert!(!seen.is_empty(), "no Vector image pins found");
    let first = &seen[0].1;
    assert!(first.contains("@sha256:"), "{}: pin without a digest: {first}", seen[0].0);
    for (path, pin) in &seen {
        assert_eq!(pin, first, "{path} pins a different Vector image than {}", seen[0].0);
    }
}
