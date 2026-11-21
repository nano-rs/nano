// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5678 profiling harness: render the real config for a set of shipped
//! OCSF parsers into a directory, through the same `deploy_parsers` the API
//! runs, so `vector validate` and a reload can be timed against it.
//!
//! Ignored; driven by env:
//!   NAN5678_PARSERS_DIR  directory holding `<source>/parser.yaml`
//!   NAN5678_OUT          config dir to render into (gets `sources/parsers/`)
//!   NAN5678_LIMIT        optional: number of parsers (default all)
//!   NAN5678_SKIP         optional: parser names to leave out (a deletion)
//!   NAN5678_OUT_AFTER    optional: render all into OUT and the set without SKIP here
//!   VECTOR_FANIN_SLOTS   optional: render with stable fan-in slots
//!   NANO_SCHEMA_PROFILE=ocsf
//!
//!   cargo test -p nanosiem-core --lib reload_scaling_render -- --ignored --nocapture

use super::*;

use crate::parser_repository::parse_parser_yaml;

fn parser_from_yaml(content: &str, index: i64) -> Option<Parser> {
    let y = parse_parser_yaml(content).ok()?;
    if y.kind.as_deref().is_some_and(|k| k != "log") {
        return None;
    }
    let vrl = y.parser_vrl?;
    Some(Parser {
        activation_parked: false,
        // Stable across renders: fan-in slot assignment orders by (created_at, id).
        id: uuid::Uuid::from_u128(index as u128 + 1),
        name: y.name.clone(),
        description: None,
        source_type: "routed".to_string(),
        parser_vrl: vrl,
        output_fields: None,
        feed_id: None,
        dispatch_source_config_id: None,
        dispatch_route_name: None,
        enabled: true,
        validated: true,
        validation_error: None,
        category: y.category,
        vendor: y.vendor,
        product: y.product,
        kind: "log".to_string(),
        enrich_kind: None,
        enrich_source: None,
        target_table: None,
        normalize_vrl: None,
        namespace: "default".to_string(),
        timezone: "UTC".to_string(),
        match_values: y.match_values.or_else(|| Some(vec![y.name.clone()])),
        sampling_ratio: None,
        sampling_exclude_condition: None,
        extension_vrl: None,
        extension_enabled: false,
        created_at: chrono::DateTime::from_timestamp(1_700_000_000 + index, 0).expect("timestamp"),
        updated_at: chrono::DateTime::from_timestamp(1_700_000_000 + index, 0).expect("timestamp"),
    })
}

#[tokio::test]
#[ignore = "NAN-5678 profiling harness; needs NAN5678_PARSERS_DIR and NAN5678_OUT"]
async fn reload_scaling_render_shipped_ocsf_parsers() {
    let src = std::path::PathBuf::from(std::env::var("NAN5678_PARSERS_DIR").expect("NAN5678_PARSERS_DIR"));
    let out = std::path::PathBuf::from(std::env::var("NAN5678_OUT").expect("NAN5678_OUT"));
    let limit: usize = std::env::var("NAN5678_LIMIT").ok().and_then(|v| v.parse().ok()).unwrap_or(usize::MAX);
    // NAN5678_SKIP: comma-separated parser names left out (a deleted source).
    let skip: Vec<String> = std::env::var("NAN5678_SKIP")
        .map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
        .unwrap_or_default();

    let mut dirs: Vec<_> = std::fs::read_dir(&src).expect("read parsers dir").flatten().map(|e| e.path()).collect();
    dirs.sort();
    let mut parsers = Vec::new();
    for dir in dirs {
        let Ok(content) = std::fs::read_to_string(dir.join("parser.yaml")) else { continue };
        if let Some(p) = parser_from_yaml(&content, parsers.len() as i64) {
            parsers.push(p);
        }
        if parsers.len() >= limit {
            break;
        }
    }
    let render = |out: std::path::PathBuf, parsers: Vec<Parser>| async move {
        let mgr = VectorConfigManager::new(&out);
        let started = std::time::Instant::now();
        mgr.deploy_parsers(&parsers).await.expect("render");
        eprintln!(
            "rendered {} parsers into {} in {:?} ({} bytes loaded)",
            parsers.len(),
            out.display(),
            started.elapsed(),
            loaded_config_bytes(&out)
        );
    };
    // NAN5678_OUT_AFTER: also render the set without the NAN5678_SKIP
    // sources there (the tree after deleting them); NAN5678_OUT then gets all.
    match std::env::var("NAN5678_OUT_AFTER") {
        Ok(after) => {
            render(out, parsers.clone()).await;
            parsers.retain(|p| !skip.contains(&p.name));
            render(std::path::PathBuf::from(after), parsers).await;
        }
        Err(_) => {
            parsers.retain(|p| !skip.contains(&p.name));
            render(out, parsers).await;
        }
    }
}
