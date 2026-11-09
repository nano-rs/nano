// SPDX-License-Identifier: AGPL-3.0-or-later
//! Deploy-time guard over one generated parser document (NAN-4919).
//!
//! The renderer is the only author of a parser TOML, but its input
//! (`parser_vrl`, `extension_vrl`) is tenant-controlled and may be hand-edited
//! through the API. This guard re-reads what was actually rendered and refuses
//! the deploy when the document contains anything the pipeline compiler would
//! not have produced (port of main's `tenant_bundle/overlay.rs` checks, minus
//! the lake-only bundle parts):
//!
//! - only `[transforms.*]`: no sources, sinks, enrichment tables, secrets or API;
//! - every pipeline transform type is one the deployment's Vector image ships;
//! - `_pipe_` components exist only for a stored processing plan, under the
//!   source's own prefix, with compiler-owned suffixes;
//! - `dedupe` / `reduce` / `lua` only as the fixed, bounded pipeline shapes, and
//!   `reduce` / `lua` only inside a fully trusted combine envelope;
//! - no remap calls an enrichment-table function (pipeline lookups are inline);
//! - every pipeline-owned remap (and a plan's `_parse`) compiles with `%`
//!   metadata read-only, except the exact fixed combine restore whose
//!   complete data path is verified.

use super::native::{self, metadata};
use super::*;
use std::collections::BTreeSet;

fn refuse(message: impl Into<String>) -> Result<(), String> {
    Err(message.into())
}

/// Check one rendered parser document. `prefix` is the source's safe name,
/// `parser_vrl` its stored parser (plan or plain VRL), `runtime` the transform
/// types its Vector runs.
pub fn check_document(
    prefix: &str,
    parser_vrl: &str,
    document: &str,
    runtime: &BTreeSet<String>,
) -> Result<(), String> {
    let plan = if parser_vrl.starts_with(HEADER) {
        let plan = stored_plan(parser_vrl)?.ok_or("Processing plan marker without a plan")?;
        native::deployable_with(&plan, runtime)?;
        Some(plan)
    } else {
        None
    };
    let doc: toml::Table = document
        .parse()
        .map_err(|e| format!("Generated parser config is not valid TOML: {e}"))?;
    if let Some(key) = doc.keys().find(|key| key.as_str() != "transforms") {
        return refuse(format!(
            "A parser config may only declare transforms (found `{key}`)"
        ));
    }
    let Some(transforms) = doc.get("transforms") else {
        return Ok(());
    };
    let transforms = transforms
        .as_table()
        .ok_or("Generated transforms must be a table")?;
    for (name, body) in transforms {
        let body = body
            .as_table()
            .ok_or_else(|| format!("Transform {name} must be a table"))?;
        let kind = body
            .get("type")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| format!("Transform {name} has no type"))?;
        let owned = name
            .strip_prefix(prefix)
            .is_some_and(|tail| tail.starts_with("_pipe_"));
        // Scoped to pipeline components: the pre-existing parser shapes are
        // unchanged by this guard.
        if owned && !runtime.contains(kind) {
            return refuse(format!(
                "Transform {name} needs Vector's `{kind}` transform, which this deployment's Vector image does not include"
            ));
        }
        if owned && (plan.is_none() || !native::owns_component(prefix, name)) {
            return refuse(format!(
                "Transform {name} is outside the source's generated pipeline namespace"
            ));
        }
        match kind {
            "dedupe" | "reduce" | "lua" => {
                if !owned {
                    return refuse(format!(
                        "`{kind}` is only allowed as a generated pipeline step ({name})"
                    ));
                }
                native::guard_transform(kind, body)?;
                if kind != "dedupe" {
                    let index = name
                        .strip_prefix(&format!("{prefix}_pipe_"))
                        .and_then(|tail| tail.split_once('_'))
                        .map(|(index, _)| index)
                        .ok_or("Combine component index is missing")?;
                    let restore = format!("{prefix}_pipe_{index}_restore");
                    if !metadata::trusted_restore(prefix, &restore, transforms) {
                        return refuse(format!(
                            "{name} is not part of a trusted combine envelope"
                        ));
                    }
                }
            }
            "remap" => {
                let source = body
                    .get("source")
                    .and_then(toml::Value::as_str)
                    .unwrap_or_default();
                if source.contains("enrichment_table") {
                    return refuse(format!(
                        "{name} calls an enrichment-table function; pipeline lookups are compiled inline"
                    ));
                }
                // Every pipeline-owned remap, and the `_parse` remap a plan
                // compiles into, must compile with event metadata read-only
                // (VRL's own analysis: every assignment form and `del`). Only
                // the exact trusted combine restore may write it.
                let plan_parse = plan.is_some() && name == &format!("{prefix}_parse");
                if (owned || plan_parse)
                    && !(name.ends_with("_restore")
                        && metadata::trusted_restore(prefix, name, transforms))
                    && compile_plan_program(source).is_err()
                {
                    return refuse(format!(
                        "{name} must compile with event metadata read-only (it writes metadata or is not valid pipeline VRL)"
                    ));
                }
                // NAN-5057: the tenant-authored remaps of a plain parser
                // (`_parse`, `_extension`) run in Vector with its full
                // stdlib, so they must compile against the parser allowlist
                // here too, not only in the write paths that may or may not
                // have run for this row.
                let tenant_remap = name == &format!("{prefix}_parse")
                    || name == &format!("{prefix}_extension");
                if tenant_remap && !plan_parse {
                    // Memoized: every publication re-renders every source, and
                    // the verdict is a pure function of the source text and
                    // the allowlist (see vrl_verdict_memo).
                    let verdict = crate::parsers::vrl_verdict_memo::verdict(
                        "guard-tenant-remap",
                        source,
                        || {
                            crate::parsers::vrl_guard::compile(
                                source,
                                &crate::parsers::vrl_functions::parser_vrl_functions(),
                            )
                            .map(|_| ())
                            .map_err(|error| error.render(source).trim_end().to_string())
                        },
                    );
                    if let Err(rendered) = verdict {
                        return refuse(format!(
                            "{name} does not compile against the parser function allowlist: {rendered}"
                        ));
                    }
                }
            }
            // NAN-5012: conditions run with Vector's full stdlib too. Every
            // condition in a parser document (the sampling exclude, the
            // generated dispatch filters, a plan's gates and route branches)
            // must be a read-only predicate over the parser allowlist.
            "sample" => check_conditions(name, body.get("exclude"))?,
            "filter" => check_conditions(name, body.get("condition"))?,
            "route" => {
                if let Some(routes) = body.get("route").and_then(toml::Value::as_table) {
                    for value in routes.values() {
                        check_conditions(name, Some(value))?;
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// A condition value is either VRL shorthand (a string) or a table carrying
/// `source`. Each must compile read-only against the parser allowlist.
fn check_conditions(name: &str, value: Option<&toml::Value>) -> Result<(), String> {
    let source = match value {
        None => return Ok(()),
        Some(toml::Value::String(source)) => source.as_str(),
        Some(toml::Value::Table(table)) => match table.get("source").and_then(toml::Value::as_str) {
            Some(source) => source,
            None => return Ok(()),
        },
        Some(_) => return refuse(format!("{name} has a condition that is not VRL")),
    };
    crate::parsers::vrl_verdict_memo::verdict("guard-condition", source, || {
        crate::parsers::vrl_guard::compile_read_only(
            source,
            &crate::parsers::vrl_functions::parser_vrl_functions(),
        )
        .map(|_| ())
        .map_err(|error| error.render(source).trim_end().to_string())
    })
    .map_err(|rendered| {
        format!(
            "{name} has a condition that is not a read-only predicate over the parser function allowlist: {rendered}"
        )
    })
}

#[cfg(test)]
#[path = "guard_tests.rs"]
mod tests;
