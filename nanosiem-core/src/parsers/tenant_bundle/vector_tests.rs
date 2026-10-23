// SPDX-License-Identifier: AGPL-3.0-or-later

//! `vector test` cases for the tenant's saved samples.
//!
//! Each sample is inserted at the source's first tenant transform and must
//! come out of `<name>_ocsf_prepare` as an OCSF row: an object `event` with a
//! `class_uid`, and a string `timestamp`. A sample the parser cannot parse is
//! rerouted to `_output` as a parse failure and never reaches
//! `_ocsf_prepare`, so Vector reports the case as failed.
//!
//! The file is separate from the bundle (the artifact carries no tests) and
//! is loaded with `--config-toml` beside the bundle's config dirs.

use super::overlay::GeneratedSource;
use super::scan::escape_interpolation;

/// The OCSF-prepare shape check.
pub const OCSF_SHAPE_CONDITION: &str = "assert!(is_object(.event), \"no OCSF event object\")\n\
assert!(exists(.event.class_uid), \"parser output has no OCSF class_uid\")\n\
assert!(is_string(.timestamp), \"no row timestamp\")\n";

/// Test-case name for one sample; the report maps results back by it.
pub fn case_name(slug: &str, index: usize) -> String {
    format!("tenant {slug} sample {}", index + 1)
}

/// Render the test file, or `None` when no source has samples to run.
pub fn render(cases: &[(&GeneratedSource, &[String])]) -> Option<String> {
    let mut tests = Vec::new();
    for (source, samples) in cases {
        for (index, sample) in samples.iter().enumerate() {
            let mut log_fields = toml::Table::new();
            log_fields.insert("message".into(), sample.clone().into());
            log_fields.insert("source_type".into(), source.tenant.slug.clone().into());
            let mut input = toml::Table::new();
            input.insert("insert_at".into(), source.entry_component.clone().into());
            input.insert("type".into(), "log".into());
            input.insert("log_fields".into(), log_fields.into());
            let mut condition = toml::Table::new();
            condition.insert("type".into(), "vrl".into());
            condition.insert("source".into(), OCSF_SHAPE_CONDITION.into());
            let mut output = toml::Table::new();
            output.insert(
                "extract_from".into(),
                format!("{}_ocsf_prepare", source.tenant.name).into(),
            );
            output.insert(
                "conditions".into(),
                toml::Value::Array(vec![condition.into()]),
            );
            let mut test = toml::Table::new();
            test.insert("name".into(), case_name(&source.tenant.slug, index).into());
            test.insert("inputs".into(), toml::Value::Array(vec![input.into()]));
            if let Some(plan) = source
                .processing_plan
                .as_ref()
                .filter(|plan| plan.has_native())
            {
                // Stateful transforms must see the frozen sequence, with fresh
                // state in each named test. Keep one named case per saved
                // sample so existing release-report attestation stays intact.
                let inputs = samples
                    .iter()
                    .map(|sample| {
                        let mut fields = toml::Table::new();
                        fields.insert("message".into(), sample.clone().into());
                        fields.insert("source_type".into(), source.tenant.slug.clone().into());
                        let mut input = toml::Table::new();
                        input.insert("insert_at".into(), source.entry_component.clone().into());
                        input.insert("type".into(), "log".into());
                        input.insert("log_fields".into(), fields.into());
                        toml::Value::Table(input)
                    })
                    .collect();
                test.insert("inputs".into(), toml::Value::Array(inputs));
                let events:Vec<_>=samples.iter().map(|message|serde_json::json!({"message":message,"source_type":source.tenant.slug})).collect();
                let empty = crate::parsers::pipe::batch::run(plan, &events, None)
                    .ok()
                    .is_some_and(|rows| {
                        rows.iter()
                            .all(|row| row.error.is_none() && row.outputs.is_empty())
                    });
                let mut no_outputs: Vec<toml::Value> = source
                    .processing_failures
                    .iter()
                    .cloned()
                    .map(toml::Value::String)
                    .collect();
                if empty {
                    no_outputs.extend([
                        format!("{}_ocsf_prepare", source.tenant.name).into(),
                        format!("{}_output", source.tenant.name).into(),
                    ]);
                } else {
                    test.insert("outputs".into(), toml::Value::Array(vec![output.into()]));
                }
                // Mixed batches must not hide bad rows behind a successful
                // aggregate from another input. Every remap failure rejects
                // release verification, including the source extension.
                test.insert("no_outputs_from".into(), toml::Value::Array(no_outputs));
                tests.push(toml::Value::Table(test));
                continue;
            }
            let intentionally_empty = source
                .processing_plan
                .as_ref()
                .and_then(|plan| {
                    crate::parsers::pipe::evaluate(
                        plan,
                        &serde_json::json!({"message":sample,"source_type":source.tenant.slug}),
                    )
                    .ok()
                })
                .is_some_and(|value| value.as_array().is_some_and(Vec::is_empty));
            if intentionally_empty {
                // A policy drop must not reappear as a parser failure. Check
                // both successful and error-restoration paths explicitly.
                test.insert(
                    "no_outputs_from".into(),
                    toml::Value::Array(vec![
                        format!("{}_ocsf_prepare", source.tenant.name).into(),
                        format!("{}_output", source.tenant.name).into(),
                    ]),
                );
            } else {
                test.insert("outputs".into(), toml::Value::Array(vec![output.into()]));
            }
            tests.push(toml::Value::Table(test));
        }
    }
    if tests.is_empty() {
        return None;
    }
    let mut root = toml::Table::new();
    root.insert("tests".into(), toml::Value::Array(tests));
    // Samples are raw tenant data: escape `$` so Vector's interpolation hands
    // the literal text to the test instead of expanding it.
    Some(escape_interpolation(
        &toml::to_string(&root).expect("a table of strings always serializes"),
    ))
}

/// Keep each source's exact transforms and their upstream dependencies. Tests
/// inject at the same entry point and assert at the same outputs as the combined
/// config. Downstream consumers cannot affect these assertions. The combined
/// validate and platform tests still exercise the complete wiring.
pub fn source_configs(
    tree: &super::archive::BundleTree,
    cases: &[(&GeneratedSource, &[String])],
) -> Result<Vec<String>, super::TenantBundleError> {
    use std::collections::BTreeSet;
    if cases.iter().all(|(_, samples)| samples.is_empty()) {
        return Ok(Vec::new());
    }
    let error = |message: String| super::TenantBundleError::Input(message);
    let mut config = toml::Table::new();
    let mut interpolations = Vec::new();
    let interpolation = regex::Regex::new(r"\$\$|\$\{[^}\n]+\}|\$[A-Za-z_][A-Za-z0-9_]*").unwrap();
    let bare =
        regex::Regex::new(r"(?m)(=\s*)(NANO_SHARD_INTERPOLATION_[0-9]+_)(\s*(?:#.*)?$)").unwrap();
    for (path, bytes) in &tree.files {
        // Match the runtime's three config dirs, without loading backups or
        // both copies of the source configs.
        let parent = path.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
        if !matches!(parent, "" | "sources/parsers" | "sources/configs") {
            continue;
        }
        if [".json", ".yaml", ".yml"]
            .iter()
            .any(|ext| path.ends_with(ext))
        {
            return Err(error(format!("unsupported shard config format: {path}")));
        }
        if !path.ends_with(".toml") {
            continue;
        }
        let text = std::str::from_utf8(bytes).map_err(|e| error(e.to_string()))?;
        // Preserve Vector's pre-TOML interpolation, including typed unquoted
        // values. Never evaluate environment variables inside the builder.
        if text.contains("NANO_SHARD_INTERPOLATION_") {
            return Err(error(
                "reserved shard interpolation marker in config".into(),
            ));
        }
        let masked = interpolation.replace_all(text, |caps: &regex::Captures<'_>| {
            if &caps[0] == "$$" {
                return "$$".to_string();
            }
            let token = format!("NANO_SHARD_INTERPOLATION_{}_", interpolations.len());
            interpolations.push((token.clone(), caps[0].to_string()));
            token
        });
        let masked = bare.replace_all(&masked, "${1}\"${2}RAW\"${3}");
        let parsed: toml::Table =
            toml::from_str(&masked).map_err(|e| error(format!("{path}: {e}")))?;
        for (key, value) in parsed {
            if key == "tests" || key == "sinks" {
                continue;
            }
            if let Some(existing) = config.get_mut(&key) {
                let dest = existing
                    .as_table_mut()
                    .ok_or_else(|| error(format!("duplicate {key}")))?;
                let items = value
                    .as_table()
                    .ok_or_else(|| error(format!("duplicate {key}")))?;
                for (name, item) in items {
                    if dest.insert(name.clone(), item.clone()).is_some() {
                        return Err(error(format!("duplicate {key}.{name}")));
                    }
                }
            } else {
                config.insert(key, value);
            }
        }
    }
    let transforms = config
        .get("transforms")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| error("missing transforms".into()))?;
    let mut configs = Vec::new();
    for (source, samples) in cases {
        let Some(tests) = render(&[(source, samples)]) else {
            continue;
        };
        let mut keep: BTreeSet<String> = source.components.iter().cloned().collect();
        let mut pending: Vec<String> = keep.iter().cloned().collect();
        while let Some(name) = pending.pop() {
            let transform = transforms
                .get(&name)
                .ok_or_else(|| error(format!("missing transform {name}")))?;
            if let Some(inputs) = transform.get("inputs").and_then(toml::Value::as_array) {
                for input in inputs.iter().filter_map(toml::Value::as_str) {
                    let upstream = input.split('.').next().unwrap_or(input);
                    // Wildcard wiring needs explicit dependency expansion before
                    // it can be safely sharded. Refuse rather than omit a gate.
                    if upstream.contains(['*', '?', '[']) {
                        return Err(error(format!("cannot shard wildcard input {input}")));
                    }
                    if transforms.contains_key(upstream) && keep.insert(upstream.into()) {
                        pending.push(upstream.into());
                    }
                }
            }
        }
        let mut shard = config.clone();
        shard
            .get_mut("transforms")
            .unwrap()
            .as_table_mut()
            .unwrap()
            .retain(|name, _| keep.contains(name));
        let mut rendered = toml::to_string(&shard).map_err(|e| error(e.to_string()))?;
        for (token, original) in &interpolations {
            // Bare typed values were quoted only to let the TOML parser read
            // them; string interpolation stays inside its original quotes.
            rendered = rendered.replace(&format!("\\\"{token}RAW\\\""), original);
            rendered = rendered.replace(&format!("\"{token}RAW\""), original);
            rendered = rendered.replace(token, original);
        }
        rendered.push_str("\n");
        rendered.push_str(&tests);
        configs.push(rendered);
    }
    Ok(configs)
}
