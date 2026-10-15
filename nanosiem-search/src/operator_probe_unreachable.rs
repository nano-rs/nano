// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-3715: the lake cell's operator probes (`/v1/debug/...` on query[T],
//! e.g. `POST /v1/debug/sql-probe`) are reachable only by an operator
//! through `kubectl port-forward` to the cell router. The search service,
//! the API and the Worker must never route to them: every lake-cell request
//! path is a literal in this workspace (`nanosiem_core::search::lake*`), so
//! no source the search path is built from may name the debug prefix.
use std::path::{Path, PathBuf};

/// Built from pieces so this file does not match itself.
fn needles() -> [String; 2] {
    [format!("/v1/{}/", "debug"), format!("{}-probe", "sql")]
}

fn sources(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if !matches!(
                name.as_ref(),
                "node_modules" | "target" | "dist" | "out" | ".wrangler"
            ) {
                sources(&path, out);
            }
        } else if [".rs", ".ts", ".tsx", ".js", ".mjs"]
            .iter()
            .any(|ext| name.ends_with(ext))
        {
            out.push(path);
        }
    }
}

#[test]
fn no_search_api_or_worker_source_routes_to_operator_probes() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root");
    let mut files = Vec::new();
    for root in [
        "nanosiem-search/src",
        "nanosiem-core/src",
        "nanosiem-api/src",
        "nanosiem-api-lib/src",
        "workers",
    ] {
        sources(&workspace.join(root), &mut files);
    }
    assert!(
        files.iter().any(|file| file.ends_with("search/lake.rs")),
        "the lake client source was scanned"
    );
    let this = Path::new(file!())
        .file_name()
        .expect("file name")
        .to_owned();
    let offenders = files
        .iter()
        .filter(|file| file.file_name() != Some(this.as_os_str()))
        .filter(|file| {
            std::fs::read_to_string(file).is_ok_and(|text| {
                needles()
                    .iter()
                    .any(|needle| text.contains(needle.as_str()))
            })
        })
        .collect::<Vec<_>>();
    assert!(
        offenders.is_empty(),
        "operator probe paths must not be routable from search/API/Worker: {offenders:?}"
    );
}
