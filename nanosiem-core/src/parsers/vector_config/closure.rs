// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3765: input closure of a rendered Vector configuration.
//!
//! Vector refuses a whole configuration when any component names an input that
//! no component declares (`Input "x" for transform "y" doesn't match any
//! components`). A running Vector keeps its previous config on that reload; a
//! restarting one does not boot at all, i.e. no ingest. CT 106 hit this twice:
//! a router referencing a HEC route nothing declared (publication 25), and a
//! parser filter reading a source configuration's route one publication before
//! that route existed (publication 28).
//!
//! The generators are supposed to make that impossible (the HEC fallback route,
//! [`crate::parsers::WaitingParser`]); this check is the backstop that keeps a
//! future generator bug from ever being published. A candidate tree that does
//! not close is refused before it gets a generation, so the committed one keeps
//! serving.

use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};

/// The static base config that ships beside the dynamic tree
/// (`config/vector/*.toml`, mounted next to `dynamic/`). Each entry is gated by
/// the same presence switches the generators honor, so a deployment without
/// that file never counts its components as declared.
fn static_base_documents() -> Vec<(&'static str, &'static str)> {
    let mut docs = vec![
        (
            "00-base.toml",
            include_str!("../../../../config/vector/00-base.toml"),
        ),
        (
            "01-vector-source.toml",
            include_str!("../../../../config/vector/01-vector-source.toml"),
        ),
        (
            "92-metrics.toml",
            include_str!("../../../../config/vector/92-metrics.toml"),
        ),
    ];
    if super::router::hec_normalize_present() {
        docs.push((
            "02-hec-source.toml",
            include_str!("../../../../config/vector/02-hec-source.toml"),
        ));
    }
    if super::router::otlp_source_present() {
        docs.push((
            "03-otlp-source.toml",
            include_str!("../../../../config/vector/03-otlp-source.toml"),
        ));
        docs.push((
            "04-otlp-lake-sink.toml",
            include_str!("../../../../config/vector/04-otlp-lake-sink.toml"),
        ));
    }
    docs
}

/// Vector substitutes `${VAR:-default}` before parsing TOML; mirror it (value
/// after `:-`, else empty) so the raw configs parse.
fn substitute_env(raw: &str) -> String {
    let re = regex::Regex::new(r"\$\{([^}]*)\}").expect("static regex");
    re.replace_all(raw, |caps: &regex::Captures| match caps[1].find(":-") {
        Some(pos) => caps[1][pos + 2..].to_string(),
        None => String::new(),
    })
    .into_owned()
}

/// Components declared and inputs referenced by one TOML document.
#[derive(Default)]
struct Topology {
    declared: HashSet<String>,
    /// (`<kind>.<component>`, input)
    references: Vec<(String, String)>,
}

impl Topology {
    fn add(&mut self, label: &str, raw: &str) -> Result<(), String> {
        let doc: toml::Table = toml::from_str(&substitute_env(raw))
            .map_err(|error| format!("{label} is not valid TOML: {error}"))?;
        for kind in ["sources", "transforms", "sinks"] {
            let Some(table) = doc.get(kind).and_then(|v| v.as_table()) else {
                continue;
            };
            for (name, def) in table {
                self.declared.insert(name.clone());
                let inputs = def
                    .get("inputs")
                    .and_then(|v| v.as_array())
                    .into_iter()
                    .flatten()
                    .filter_map(|v| v.as_str());
                for input in inputs {
                    self.references
                        .push((format!("{kind}.{name}"), input.to_string()));
                }
            }
        }
        Ok(())
    }
}

/// Every `<component> -> <input>` reference in the dynamic tree under
/// `sources_dir` that resolves to neither a component of that tree nor one of
/// the static base config. Route outputs (`source_router.generic`) resolve by
/// their component. Sorted; empty when the tree closes.
pub fn dangling_inputs(sources_dir: &Path) -> Result<Vec<String>, String> {
    let mut files = Vec::new();
    collect_toml_files(sources_dir, &mut files)
        .map_err(|error| format!("cannot read {}: {error}", sources_dir.display()))?;
    files.sort();

    let mut base = Topology::default();
    for (label, raw) in static_base_documents() {
        base.add(label, raw)?;
    }

    let mut dynamic = Topology::default();
    for file in &files {
        let raw = std::fs::read_to_string(file)
            .map_err(|error| format!("cannot read {}: {error}", file.display()))?;
        let label = file
            .strip_prefix(sources_dir)
            .unwrap_or(file)
            .display()
            .to_string();
        dynamic.add(&label, &raw)?;
    }

    let dangling: BTreeSet<String> = dynamic
        .references
        .iter()
        .filter(|(_, input)| {
            let component = input.split('.').next().unwrap_or(input);
            !dynamic.declared.contains(component) && !base.declared.contains(component)
        })
        .map(|(owner, input)| format!("{owner} -> {input}"))
        .collect();
    Ok(dangling.into_iter().collect())
}

fn collect_toml_files(dir: &Path, files: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let path = entry.path();
        if file_type.is_dir() {
            collect_toml_files(&path, files)?;
        } else if file_type.is_file() && path.extension().is_some_and(|e| e == "toml") {
            files.push(path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::TempDir::new().expect("tempdir");
        for (path, content) in files {
            let path = dir.path().join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, content).unwrap();
        }
        dir
    }

    #[test]
    fn closed_tree_has_no_dangling_inputs() {
        let dir = tree(&[
            (
                "configs/hub.toml",
                "[transforms.hub_route]\ntype = \"remap\"\ninputs = [\"vector_merge\"]\nsource = \".\"\n",
            ),
            (
                "parsers/azure.toml",
                "[transforms.azure_filter]\ntype = \"filter\"\ninputs = [\"hub_route\"]\ncondition = \"true\"\n",
            ),
            (
                "parsers/_router.toml",
                "[transforms.source_router]\ntype = \"route\"\ninputs = [\"source_type_extract\"]\nroute.generic = \"true\"\n\
                 [transforms.after]\ntype = \"filter\"\ninputs = [\"source_router.generic\"]\ncondition = \"true\"\n",
            ),
        ]);
        assert_eq!(dangling_inputs(dir.path()).unwrap(), Vec::<String>::new());
    }

    /// CT 106 publication 28: the parser filter read a source configuration's
    /// route that the set did not contain.
    #[test]
    fn parser_filter_on_missing_route_is_dangling() {
        let dir = tree(&[(
            "parsers/nan3764_lab_azure_parser.toml",
            "[transforms.nan3764_lab_azure_parser_filter]\ntype = \"filter\"\n\
             inputs = [\"nan3764_lab_hub_route\"]\ncondition = \"true\"\n",
        )]);
        assert_eq!(
            dangling_inputs(dir.path()).unwrap(),
            vec!["transforms.nan3764_lab_azure_parser_filter -> nan3764_lab_hub_route".to_string()]
        );
    }

    #[test]
    fn unparseable_file_is_an_error() {
        let dir = tree(&[("parsers/bad.toml", "[transforms.x\n")]);
        assert!(dangling_inputs(dir.path()).is_err());
    }

    #[test]
    fn env_interpolation_outside_strings_parses() {
        let dir = tree(&[(
            "parsers/_sink.toml",
            "[sinks.s]\ntype = \"http\"\ninputs = [\"vector_merge\"]\n\
             force_path_style = ${NANO_LAKE_FORCE_PATH_STYLE:-false}\nuri = \"http://x\"\n",
        )]);
        assert_eq!(dangling_inputs(dir.path()).unwrap(), Vec::<String>::new());
    }
}
