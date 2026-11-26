// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5810: no Vector TOML nano ships or renders may use a bare `${...}` as a
//! whole value (`max_bytes = ${VECTOR_BATCH_MAX_BYTES:-52428800}`).
//!
//! Vector 0.62 (vectordotdev/vector#26475) parses the config file BEFORE it
//! interpolates environment variables, then substitutes only inside string
//! values and coerces the result to the field's type. A bare placeholder is
//! therefore a TOML parse error and Vector refuses the WHOLE config (every
//! ingest lane down). Quote it: `max_bytes = "${VECTOR_BATCH_MAX_BYTES:-52428800}"`.
//!
//! NAN-5899: the STATIC bundle (`config/vector`, Helm `files/vector`) must also
//! load in the previous release's Vector (0.61 substitutes in the raw text, then
//! parses, and rejects a quoted number). So no static TOML carries a numeric
//! placeholder at all: those sinks are YAML with the placeholder BARE
//! (`03-otlp-sinks.yaml`, `92-metrics-sinks.yaml`), which this TOML-only scan
//! does not read; `scripts/tests/test_vector_static_config_dual_version.py`
//! guards the static bundle. The quoting rule here is for everything nano
//! renders (read only by its own Vector) and for static TOML string values.

use super::*;

use crate::vector_env::bare_placeholder_lines;

const WHY: &str = "Vector 0.62 parses the TOML before it interpolates env vars, so a bare \
                   `key = ${VAR}` is a parse error and Vector refuses the whole config. \
                   Quote it: `key = \"${VAR:-default}\"` (Vector coerces the string to the \
                   field's type).";

fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("nanosiem-core has a repository parent")
        .to_path_buf()
}

/// Every committed Vector TOML (`*.toml`, `*.toml.disabled`) under `dirs`,
/// from git when it is available (so runtime files a dev stack wrote are not
/// read), else from the filesystem. `config/vector/backup/` is a runtime dir.
fn committed_vector_tomls(dirs: &[&str]) -> Vec<std::path::PathBuf> {
    let root = repo_root();
    let is_toml = |p: &str| p.ends_with(".toml") || p.ends_with(".toml.disabled");
    let skip = |p: &str| p.starts_with("config/vector/backup/");
    let listed = std::process::Command::new("git")
        .arg("-C")
        .arg(&root)
        .args(["ls-files", "-z", "--"])
        .args(dirs)
        .output()
        .ok()
        .filter(|o| o.status.success() && !o.stdout.is_empty());
    if let Some(out) = listed {
        return String::from_utf8_lossy(&out.stdout)
            .split('\0')
            .filter(|p| is_toml(p) && !skip(p))
            .map(|p| root.join(p))
            .filter(|p| p.exists())
            .collect();
    }
    let mut found = Vec::new();
    let mut stack: Vec<std::path::PathBuf> = dirs.iter().map(|d| root.join(d)).collect();
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let path = entry.path();
            let rel = path.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/");
            if skip(&format!("{rel}/")) || skip(&rel) || rel.starts_with("config/vector/dynamic") {
                continue;
            }
            if path.is_dir() {
                stack.push(path);
            } else if is_toml(&rel) {
                found.push(path);
            }
        }
    }
    found
}

fn violations(label: &str, content: &str) -> Vec<String> {
    bare_placeholder_lines(content)
        .into_iter()
        .map(|(line, text)| format!("{label}:{line}: {text}"))
        .collect()
}

fn assert_none(found: Vec<String>) {
    assert!(found.is_empty(), "{WHY}\n{}", found.join("\n"));
}

#[test]
fn committed_vector_tomls_quote_every_placeholder() {
    let files = committed_vector_tomls(&["config/vector", "deploy/helm/nano/files/vector"]);
    assert!(
        files.iter().any(|f| f.ends_with("config/vector/03-otlp-source.toml")),
        "the scan must see the static bundle: {files:?}"
    );
    let mut found = Vec::new();
    for file in &files {
        let content = std::fs::read_to_string(file).unwrap();
        let label = file.strip_prefix(repo_root()).unwrap().display().to_string();
        found.extend(violations(&label, &content));
    }
    assert_none(found);
}

/// Every generator output, sharded and not, both schema profiles.
#[test]
fn generated_vector_tomls_quote_every_placeholder() {
    let endpoints = vec![
        "http://clickhouse-shard-0:8123".to_string(),
        "http://clickhouse-shard-1:8123".to_string(),
    ];
    let enrichment_parser = Parser {
        kind: "enrichment".into(),
        enrich_kind: Some("asset".into()),
        enrich_source: Some("asset".into()),
        target_table: Some("asset_registry".into()),
        normalize_vrl: Some(".x = 1".into()),
        source_type: "nano_enrich".into(),
        ..render_parser("asset_enrich")
    };
    let mut pipeline_ocsf = VectorConfigManager::pipeline_config_content_for(true);
    pipeline_ocsf.push_str(VectorConfigManager::GENERIC_OCSF_PREPARE_BLOCK);
    let renders = [
        ("pipeline_config_content", VectorConfigManager::pipeline_config_content().to_string()),
        ("pipeline_config_content_for(udm)", VectorConfigManager::pipeline_config_content_for(false)),
        ("pipeline_config_content_for(ocsf)", pipeline_ocsf.clone()),
        ("ocsf_sink_content", VectorConfigManager::ocsf_sink_content(&["\"ocsf_prepare\"".to_string()])),
        ("enrichment_lane_content", VectorConfigManager::enrichment_lane_content().to_string()),
        ("static_enrichment_lane", VectorConfigManager::static_enrichment_lane()),
        (
            "generate_enrichment_lane",
            VectorConfigManager::generate_enrichment_lane(&[&enrichment_parser]),
        ),
        (
            "sharded pipeline",
            VectorConfigManager::shard_route_clickhouse_sinks(pipeline_ocsf, &endpoints),
        ),
        (
            "sharded ocsf sink",
            VectorConfigManager::shard_route_clickhouse_sinks(
                VectorConfigManager::ocsf_sink_content(&["\"ocsf_prepare\"".to_string()]),
                &endpoints,
            ),
        ),
        (
            "sharded enrichment lane",
            VectorConfigManager::shard_route_clickhouse_sinks(
                VectorConfigManager::static_enrichment_lane(),
                &endpoints,
            ),
        ),
    ];
    let mut found = Vec::new();
    for (label, content) in &renders {
        assert!(content.contains("${"), "{label}: expected nano's own placeholders");
        found.extend(violations(label, content));
    }
    assert_none(found);
}

/// A whole tree as `deploy_parsers` writes it (parser files, router, sinks).
#[tokio::test]
async fn a_deployed_tree_quotes_every_placeholder() {
    let tmp = tempfile::TempDir::new().unwrap();
    let manager = VectorConfigManager::new(tmp.path());
    let enrichment_parser = Parser {
        kind: "enrichment".into(),
        enrich_kind: Some("asset".into()),
        enrich_source: Some("asset".into()),
        target_table: Some("asset_registry".into()),
        normalize_vrl: Some(".x = 1".into()),
        source_type: "nano_enrich".into(),
        ..render_parser("asset_enrich")
    };
    manager
        .deploy_parsers(&[render_parser("acme_json"), enrichment_parser])
        .await
        .expect("render");
    let mut found = Vec::new();
    let mut seen = 0;
    let mut stack = vec![tmp.path().to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "toml") {
                seen += 1;
                let content = std::fs::read_to_string(&path).unwrap();
                found.extend(violations(&path.display().to_string(), &content));
            }
        }
    }
    assert!(seen >= 3, "the render wrote {seen} TOML files");
    assert_none(found);
}

fn render_parser(name: &str) -> Parser {
    Parser {
        activation_parked: false,
        id: uuid::Uuid::new_v4(),
        name: name.to_string(),
        description: None,
        source_type: name.to_string(),
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
        match_values: Some(vec![format!("{name}_key")]),
        sampling_ratio: None,
        sampling_exclude_condition: None,
        extension_vrl: None,
        extension_enabled: false,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

/// The guard itself: the form the static bundle used before NAN-5810 is caught.
#[test]
fn the_guard_catches_the_pre_0_62_form() {
    let old = "[sinks.x.batch]\nmax_bytes = ${VECTOR_BATCH_MAX_BYTES:-52428800}\n";
    assert_eq!(violations("old", old).len(), 1);
    assert!(violations("new", &crate::vector_env::quote_bare_placeholders(old)).is_empty());
}
