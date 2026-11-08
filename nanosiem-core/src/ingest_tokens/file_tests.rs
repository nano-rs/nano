// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tests for Vector's hashed tokens file rendering and atomic writes.

use super::*;

fn entry(n: u128, name: &str) -> TokenFileEntry {
    TokenFileEntry {
        sha256: format!("{n:064x}"),
        id: Uuid::from_u128(n),
        route: name.into(),
    }
}

#[test]
fn renders_the_fork_format_sorted() {
    let text = render_tokens_file(&[entry(2, "b"), entry(1, "a")], true);
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(value["version"], 1);
    assert_eq!(value["fallback_enabled"], true);
    let tokens = value["tokens"].as_array().unwrap();
    assert_eq!(tokens.len(), 2);
    assert_eq!(tokens[0]["id"], Uuid::from_u128(1).to_string());
    assert_eq!(tokens[0]["sha256"], format!("{:064x}", 1));
    assert_eq!(tokens[0]["name"], "a");
    assert_eq!(
        text,
        render_tokens_file(&[entry(1, "a"), entry(2, "b")], true),
        "order-independent"
    );
    let disabled: serde_json::Value =
        serde_json::from_str(&render_tokens_file(&[], false)).unwrap();
    assert_eq!(disabled["fallback_enabled"], false);
    assert_eq!(disabled["tokens"], serde_json::json!([]));
}

#[test]
fn writes_atomically_with_0600_and_skips_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ingest-tokens/tokens.json");
    let content = render_tokens_file(&[entry(1, "a")], true);
    assert!(write_tokens_file(&path, &content).unwrap());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), content);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    assert!(!write_tokens_file(&path, &content).unwrap(), "unchanged");
    let next = render_tokens_file(&[], true);
    assert!(write_tokens_file(&path, &next).unwrap());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), next);
    // No temp files left behind.
    let leftovers: Vec<_> = std::fs::read_dir(path.parent().unwrap())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
        .collect();
    assert!(leftovers.is_empty());
}
