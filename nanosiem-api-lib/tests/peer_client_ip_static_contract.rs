// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3797: since NAN-3460 `extract_client_ip` trusts proxy headers only for
//! a known socket peer, so `extract_client_ip(headers, None)` is always
//! `None`. A tenant IP policy denies a missing IP: the hosted SSO callback and
//! MFA step-up answered 401 for every user, and audit rows lost the client
//! address. Handlers take `PeerAddr` and call `peer_client_ip`.

use std::path::{Path, PathBuf};

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display())) {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

#[test]
fn no_handler_resolves_a_client_ip_without_its_socket_peer() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let call =
        regex::Regex::new(r"extract_client_ip\(\s*&?\s*[A-Za-z_][A-Za-z0-9_.]*\s*,\s*None\s*\)")
            .unwrap();
    let mut files = Vec::new();
    // The API crates plus the enterprise handler crate when this checkout has it.
    let mut crate_dirs = vec!["nanosiem-api".to_string(), "nanosiem-api-lib".to_string()];
    for entry in std::fs::read_dir(&root).unwrap() {
        let name = entry.unwrap().file_name().to_string_lossy().into_owned();
        if name.starts_with("nanosiem-") && name.ends_with("-enterprise") {
            crate_dirs.push(name);
        }
    }
    for crate_dir in crate_dirs {
        rust_files(&root.join(crate_dir).join("src"), &mut files);
    }
    assert!(files.len() > 50, "the scan must see the handler sources");
    let mut found = Vec::new();
    for file in files {
        if file.ends_with("nanosiem-api-lib/src/headers.rs") {
            continue; // definition and its unit tests
        }
        let source = std::fs::read_to_string(&file).unwrap();
        for m in call.find_iter(&source) {
            let line = source[..m.start()].lines().count() + 1;
            found.push(format!("{}:{line}: {}", file.display(), m.as_str()));
        }
    }
    assert!(
        found.is_empty(),
        "client IP resolved without the socket peer (always None; tenant IP policy denies it). \
         Take `peer: PeerAddr` and call `peer_client_ip(&headers, &peer)`:\n{}",
        found.join("\n")
    );
}
