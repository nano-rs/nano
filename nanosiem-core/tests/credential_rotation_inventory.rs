// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4933: every secret column a migration creates must be a credential
//! re-wrap target (`crypto::rotation::TARGETS`), or rotation silently leaves
//! its rows on the old key and retirement strands them.
//!
//! Scans every PostgreSQL migration directory present in this tree (the
//! open-core mirror has no enterprise directory, which is fine) for columns
//! whose name says ciphertext (`*_encrypted`, `*ciphertext*`, `*sealed*`) or
//! nonce, and fails on any not covered by TARGETS or the reasoned allowlist.
//! A new secret column fails this test until it is added to TARGETS.

use nanosiem_core::crypto::rotation::{Storage, TARGETS};
use regex::Regex;
use std::collections::BTreeSet;
use std::path::Path;

/// Columns that look like secrets but hold no `EncryptionService` output.
const NOT_REWRAP_TARGETS: &[(&str, &str, &str)] = &[
    (
        "melod_settings",
        "credentials_encrypted",
        "legacy JSONB column from before provider_credentials; no code reads or writes it",
    ),
    (
        "oidc_auth_transactions",
        "nonce",
        "the OIDC protocol nonce of an in-flight login, not an AES-GCM nonce",
    ),
    (
        "sovereign_license_state",
        "pending_recovery_nonce",
        "a 32-byte recovery challenge used for replay protection, not an AES-GCM nonce",
    ),
];

fn is_cipher_column(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.ends_with("_encrypted") || n.contains("ciphertext") || n.contains("sealed")
}

fn is_nonce_column(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n == "nonce" || n.ends_with("_nonce")
}

/// (table, column) of every cipher/nonce-looking column the migrations add.
fn migration_columns() -> BTreeSet<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../migrations");
    let create = Regex::new(r#"(?is)create\s+table\s+(?:if\s+not\s+exists\s+)?(?:public\.)?"?(\w+)"?\s*\((.*)"#).unwrap();
    let column = Regex::new(r#"^\s*"?(\w+)"?\s+\w"#).unwrap();
    let alter = Regex::new(r#"(?is)alter\s+table\s+(?:only\s+)?(?:if\s+exists\s+)?(?:public\.)?"?(\w+)"?(.*)"#).unwrap();
    let add = Regex::new(r#"(?i)add\s+column\s+(?:if\s+not\s+exists\s+)?"?(\w+)"?"#).unwrap();
    let comment = Regex::new(r"--[^\n]*").unwrap();
    let mut found = BTreeSet::new();
    let mut scanned = 0;
    for dir in ["postgres", "postgres-enterprise", "postgres-open"] {
        let Ok(entries) = std::fs::read_dir(root.join(dir)) else { continue };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("sql") {
                continue;
            }
            scanned += 1;
            let sql = std::fs::read_to_string(&path).unwrap();
            let sql = comment.replace_all(&sql, "");
            for statement in sql.split(';') {
                if let Some(m) = create.captures(statement) {
                    for line in m[2].lines() {
                        if let Some(c) = column.captures(line) {
                            if is_cipher_column(&c[1]) || is_nonce_column(&c[1]) {
                                found.insert((m[1].to_ascii_lowercase(), c[1].to_ascii_lowercase()));
                            }
                        }
                    }
                }
                for m in alter.captures_iter(statement) {
                    for c in add.captures_iter(&m[2]) {
                        if is_cipher_column(&c[1]) || is_nonce_column(&c[1]) {
                            found.insert((m[1].to_ascii_lowercase(), c[1].to_ascii_lowercase()));
                        }
                    }
                }
            }
        }
    }
    assert!(scanned > 50, "migration scan found only {scanned} files under {}", root.display());
    found
}

fn covered() -> BTreeSet<(String, String)> {
    let mut set = BTreeSet::new();
    for t in TARGETS {
        set.insert((t.table.to_string(), t.column.to_string()));
        if let Storage::Bytea { nonce_column } = t.storage {
            set.insert((t.table.to_string(), nonce_column.to_string()));
        }
    }
    for (table, column, _) in NOT_REWRAP_TARGETS {
        set.insert((table.to_string(), column.to_string()));
    }
    set
}

#[test]
fn every_migrated_secret_column_is_a_rewrap_target() {
    let covered = covered();
    let missing: Vec<_> = migration_columns()
        .into_iter()
        .filter(|col| !covered.contains(col))
        .collect();
    assert!(
        missing.is_empty(),
        "secret-looking columns with no credential re-wrap target: {missing:?}\n\
         Add each to nanosiem_core::crypto::rotation::TARGETS (or, if it holds no \
         EncryptionService ciphertext, to NOT_REWRAP_TARGETS here with the reason)."
    );
}

#[test]
fn the_scan_sees_known_targets() {
    // Guards the scanner itself: if the regexes stop matching, the test above
    // would pass vacuously.
    let found = migration_columns();
    for known in [("cloud_credentials", "credentials_encrypted"), ("webhooks", "url_encrypted"), ("users", "totp_secret_nonce")] {
        assert!(found.contains(&(known.0.into(), known.1.into())), "scanner missed {known:?}");
    }
}
