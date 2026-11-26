// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5874: the parser trees `scripts/tests/reload-acked-loss.live.sh` hot
//! reloads a real Vector between, rendered by the real `deploy_parsers` and
//! committed under `scripts/tests/fixtures/reload-acked-loss/` (that gate runs
//! where there is no Rust toolchain). Regenerate them after a render change
//! the gate trips on:
//!
//! ```sh
//! NANO_RELOAD_TREES_OUT=scripts/tests/fixtures/reload-acked-loss \
//!   cargo test -p nanosiem-core --lib reload_acked_loss_fixtures -- --exact \
//!   parsers::vector_config::reload_acked_loss_fixtures::write_the_live_reload_fixtures
//! ```
//!
//! * `rc1`: `base` without `<parser>_source_tz` (`_parse` reads the stage in
//!   front of it), the tree v2.0.34 and v2.0.35 RC1 render. `rc1 -> base` is
//!   the reload RC2's upgrade lost acknowledged events on.
//! * `base`: one JSON parser.
//! * `vrl_edit`: the same parser with new VRL (an ordinary publish).
//! * `repointed`: the parser extension turned on, which inserts a stage
//!   after `_parse`.

use chrono::Utc;
use uuid::Uuid;

use super::VectorConfigManager;
use crate::parsers::types::Parser;

fn parser(name: &str, vrl: &str) -> Parser {
    Parser {
        activation_parked: false,
        id: Uuid::from_u128(name.len() as u128 + 1),
        name: name.into(),
        description: None,
        source_type: name.into(),
        parser_vrl: vrl.into(),
        output_fields: None,
        feed_id: None,
        dispatch_source_config_id: None,
        dispatch_route_name: None,
        namespace: "default".into(),
        enabled: true,
        validated: true,
        validation_error: None,
        timezone: "UTC".into(),
        match_values: Some(vec![name.into()]),
        sampling_ratio: None,
        sampling_exclude_condition: None,
        extension_vrl: None,
        extension_enabled: false,
        category: None,
        vendor: None,
        product: None,
        kind: "log".into(),
        enrich_kind: None,
        enrich_source: None,
        target_table: None,
        normalize_vrl: None,
        created_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap_or_else(Utc::now),
        updated_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap_or_else(Utc::now),
    }
}

const JSON_OCSF: &str = r#"e = object!(parse_json!(string!(.message)))
. = { "class_uid": 0, "category_uid": 0, "metadata": { "version": "1.9.0" }, "unmapped": e }"#;

const PARSER: &str = "acme_json";

/// `base` as v2.0.34 rendered it: drop `<parser>_source_tz` and feed `_parse`
/// from what fed it.
fn without_source_tz(dir: &std::path::Path) {
    let tz = format!("{PARSER}_source_tz");
    let parse = format!("{PARSER}_parse");
    let mut found = false;
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "toml") {
            continue;
        }
        // Only the stage's file is parsed (and re-serialized); every other
        // file is copied as rendered.
        let text = std::fs::read_to_string(&path).unwrap();
        if !text.contains(&format!("[transforms.{tz}]")) {
            continue;
        }
        let mut doc: toml::Table = text.parse().expect("the source_tz file is plain TOML");
        let Some(transforms) = doc.get_mut("transforms").and_then(toml::Value::as_table_mut) else {
            continue;
        };
        let Some(stage) = transforms.remove(&tz) else { continue };
        let inputs = stage.get("inputs").cloned().expect("the source_tz stage has inputs");
        let parse = transforms
            .get_mut(&parse)
            .and_then(toml::Value::as_table_mut)
            .expect("_parse is in the same file as _source_tz");
        parse.insert("inputs".into(), inputs);
        std::fs::write(&path, toml::to_string(&doc).unwrap()).unwrap();
        found = true;
    }
    assert!(found, "no {tz} stage in {}", dir.display());
}

/// A no-op without `NANO_RELOAD_TREES_OUT`.
#[tokio::test]
async fn write_the_live_reload_fixtures() {
    let Ok(out) = std::env::var("NANO_RELOAD_TREES_OUT") else { return };
    std::env::set_var("NANO_SCHEMA_PROFILE", "ocsf");
    let out = std::path::PathBuf::from(out);
    let base = parser(PARSER, JSON_OCSF);
    let mut edited = base.clone();
    edited.parser_vrl = JSON_OCSF.replace("1.9.0", "1.9.1");
    let mut extended = base.clone();
    extended.extension_enabled = true;
    extended.extension_vrl = Some(".unmapped.ext = true".into());
    for (name, p) in [("rc1", &base), ("base", &base), ("vrl_edit", &edited), ("repointed", &extended)] {
        let render = tempfile::TempDir::new().unwrap();
        VectorConfigManager::new(render.path())
            .deploy_parsers(std::slice::from_ref(p))
            .await
            .expect("render");
        let parsers = render.path().join("sources").join("parsers");
        if name == "rc1" {
            without_source_tz(&parsers);
        }
        let dir = out.join(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut files: Vec<_> = std::fs::read_dir(&parsers).unwrap().map(|e| e.unwrap().path()).collect();
        files.sort();
        for file in files.into_iter().filter(|f| f.extension().is_some_and(|e| e == "toml")) {
            std::fs::copy(&file, dir.join(file.file_name().unwrap())).unwrap();
        }
    }
}
