// SPDX-License-Identifier: AGPL-3.0-or-later

//! Content gate for the VRL codegen safety layer (NAN-5012 / NAN-5057).
//!
//! The deploy render now compiles every log source's parser and extension VRL
//! against the parser function allowlist and quarantines a source that fails.
//! Before enforcing that, prove the shipped content passes:
//!
//! ```text
//! cargo run -p nanosiem-core --example vrl_content_gate -- \
//!     --parsers <checkout of nano-rs/parsers> [--parsers <another branch>] \
//!     --static-vector <repo>/config/vector
//! ```
//!
//! * `--parsers DIR`: every `**/parser.yaml`. Log parsers' `parser_vrl` go
//!   through exactly the render check (`vrl_safety::check_program`);
//!   enrichment parsers' `normalize_vrl` through the enrichment validator.
//!   Any failure is a gate failure (exit 1).
//! * `--static-vector DIR`: every remap `source` in the platform's static
//!   Vector TOML, compiled against the parser allowlist. These are
//!   platform-owned, never tenant input, and are NOT subject to the render
//!   check; they are reported for information only.

use std::path::{Path, PathBuf};

use nanosiem_core::parser_repository::parse_parser_yaml;
use nanosiem_core::parsers::vrl_functions::parser_vrl_functions;
use nanosiem_core::parsers::{vrl_guard, vrl_safety, VrlValidator};

fn walk(dir: &Path, out: &mut Vec<PathBuf>, keep: &dyn Fn(&Path) -> bool) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = entries.flatten().map(|e| e.path()).collect();
    entries.sort();
    for path in entries {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.starts_with('.') || name == "node_modules" || name == "target" {
            continue;
        }
        if path.is_dir() {
            walk(&path, out, keep);
        } else if keep(&path) {
            out.push(path);
        }
    }
}

fn first_line(message: &str) -> String {
    message
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("")
        .chars()
        .take(160)
        .collect()
}

fn gate_parsers(root: &Path) -> (usize, Vec<String>) {
    let mut files = Vec::new();
    walk(root, &mut files, &|p| {
        p.file_name().and_then(|n| n.to_str()) == Some("parser.yaml")
    });
    let mut failures = Vec::new();
    for file in &files {
        let rel = file.strip_prefix(root).unwrap_or(file).display().to_string();
        let raw = match std::fs::read_to_string(file) {
            Ok(raw) => raw,
            Err(e) => {
                failures.push(format!("{rel}: unreadable: {e}"));
                continue;
            }
        };
        let yaml = match parse_parser_yaml(&raw) {
            Ok(yaml) => yaml,
            Err(e) => {
                failures.push(format!("{rel}: YAML does not parse: {e}"));
                continue;
            }
        };
        let verdict = if yaml.kind.as_deref() == Some("enrichment") {
            let vrl = yaml.normalize_vrl.unwrap_or_default();
            match futures::executor::block_on(VrlValidator::for_enrichment().validate_vrl(&vrl)) {
                Ok(r) if r.valid => Ok(()),
                Ok(r) => Err(r.error.unwrap_or_default()),
                Err(e) => Err(e.to_string()),
            }
        } else {
            let vrl = yaml.parser_vrl.unwrap_or_default();
            if vrl.trim().is_empty() {
                Ok(())
            } else {
                vrl_safety::check_program("parser_vrl", &vrl)
            }
        };
        if let Err(e) = verdict {
            failures.push(format!("{rel}: {}", first_line(&e)));
        }
    }
    (files.len(), failures)
}

fn report_static(root: &Path) -> (usize, Vec<String>) {
    let mut files = Vec::new();
    walk(root, &mut files, &|p| p.extension().and_then(|e| e.to_str()) == Some("toml"));
    let fns = parser_vrl_functions();
    let mut remaps = 0;
    let mut outside = Vec::new();
    for file in &files {
        let rel = file.strip_prefix(root).unwrap_or(file).display().to_string();
        let Ok(raw) = std::fs::read_to_string(file) else { continue };
        let raw = nanosiem_core::vector_env::substitute_like_vector(&raw);
        let Ok(doc) = raw.parse::<toml::Table>() else { continue };
        let Some(transforms) = doc.get("transforms").and_then(toml::Value::as_table) else {
            continue;
        };
        for (name, body) in transforms {
            let Some(body) = body.as_table() else { continue };
            if body.get("type").and_then(toml::Value::as_str) != Some("remap") {
                continue;
            }
            let Some(source) = body.get("source").and_then(toml::Value::as_str) else {
                continue;
            };
            remaps += 1;
            if let Err(e) = vrl_guard::compile(source, &fns) {
                outside.push(format!("{rel} [{name}]: {}", first_line(&e.render(source))));
            }
        }
    }
    (remaps, outside)
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mut parser_roots = Vec::new();
    let mut static_roots = Vec::new();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--parsers" => parser_roots.push(PathBuf::from(args.next().expect("--parsers DIR"))),
            "--static-vector" => {
                static_roots.push(PathBuf::from(args.next().expect("--static-vector DIR")))
            }
            other => panic!("unknown argument {other}"),
        }
    }
    let mut failed = false;
    for root in &parser_roots {
        let (count, failures) = gate_parsers(root);
        println!(
            "parsers {}: {count} parser.yaml, {} pass, {} fail",
            root.display(),
            count - failures.len(),
            failures.len()
        );
        for f in &failures {
            println!("  FAIL {f}");
        }
        failed |= !failures.is_empty();
    }
    for root in &static_roots {
        let (count, outside) = report_static(root);
        println!(
            "static vector {} (platform-owned, informational): {count} remaps, {} use functions outside the parser allowlist",
            root.display(),
            outside.len()
        );
        for o in &outside {
            println!("  INFO {o}");
        }
    }
    if failed {
        std::process::exit(1);
    }
}
