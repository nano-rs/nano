// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4902: `splunk_hec_route` is a permanent component.
//!
//! Every HEC parser filter reads `splunk_hec_route`, and both router writers
//! (parser deploy and source-config deploy) wire it in front of
//! `source_router`. It used to exist only while the Splunk HEC source config
//! was deployed with routing rules (`sources/configs/splunk_hec.toml`), so a
//! fresh install (config disabled), an undeploy, or a deploy with only default
//! rules left a rendered parser naming a missing component, and a cold-started
//! Vector refused the whole config.
//!
//! The invariant now: whenever the HEC channel exists (`hec_normalize_present`),
//! `sources/configs/splunk_hec.toml` declares `splunk_hec_route`. With routing
//! rules it is the source-config's routing transform; otherwise it is the
//! passthrough below, which keeps `.source_type` unchanged. That is exactly
//! what `hec_normalize` feeding `source_router` directly did before, so it
//! admits nothing new and routes nothing differently. No writer ever deletes
//! the file, so no parser can be left naming a component that is gone.

use std::path::Path;

use super::router::{file_declares_route_transform, hec_normalize_present};

/// The HEC lane every HEC parser and router writer names.
pub const SPLUNK_HEC_ROUTE: &str = "splunk_hec_route";

/// `sources/configs/<stem>.toml` that owns `splunk_hec_route` (the pinned
/// system stem of the singleton Splunk HEC source config).
pub const SPLUNK_HEC_ROUTE_FILE: &str = "splunk_hec.toml";

/// The routing transform with no rules: identical behavior to `hec_normalize`
/// feeding `source_router` directly.
pub fn passthrough_route_toml() -> String {
    "# Splunk HEC routing transform (NAN-4902 passthrough).\n\
     # Written when the Splunk HEC source config is not deployed or has no\n\
     # routing rules. `splunk_hec_route` must always exist: HEC parsers and the\n\
     # router read it. Deploying the source config with rules replaces this.\n\
     # DO NOT EDIT - changes will be overwritten\n\n\
     [transforms.splunk_hec_route]\n\
     type = \"remap\"\n\
     inputs = [\"hec_normalize\"]\n\
     source = \"\"\"\n\
     # passthrough: keep existing .source_type\n\
     \"\"\"\n"
        .to_string()
}

/// Atomically write the passthrough over `sources/configs/splunk_hec.toml`
/// (temp file + rename, so Vector's watcher never reads a half-written file).
pub fn write_passthrough_route(configs_dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(configs_dir)?;
    let target = configs_dir.join(SPLUNK_HEC_ROUTE_FILE);
    // Dotfile: Vector's `--config-dir` ignores it while it exists.
    let tmp = configs_dir.join(format!(".{}.tmp-{}", SPLUNK_HEC_ROUTE_FILE, std::process::id()));
    std::fs::write(&tmp, passthrough_route_toml())?;
    std::fs::rename(&tmp, &target)
}

/// Whether any `*.toml` in `configs_dir` declares `splunk_hec_route`.
pub fn hec_route_declared(configs_dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(configs_dir) else {
        return false;
    };
    entries.flatten().any(|entry| {
        let path = entry.path();
        path.extension().is_some_and(|e| e == "toml")
            && std::fs::read_to_string(&path)
                .map(|content| file_declares_route_transform(&content, SPLUNK_HEC_ROUTE))
                .unwrap_or(false)
    })
}

/// Make the invariant hold: if the HEC channel exists and nothing declares
/// `splunk_hec_route`, write the passthrough. Never touches an existing
/// declaration (the source config's routing rules win). Returns whether it
/// wrote the file.
pub fn ensure_hec_route(configs_dir: &Path) -> std::io::Result<bool> {
    if !hec_normalize_present() || hec_route_declared(configs_dir) {
        return Ok(false);
    }
    write_passthrough_route(configs_dir)?;
    Ok(true)
}
