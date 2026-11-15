// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5412: production code starts typed ClickHouse INSERTs only through
//! `nanosiem_core::db::clickhouse_insert::insert`.
//!
//! clickhouse-rs 0.14.3+ escapes the whole `Client::insert(table)` argument
//! as ONE identifier, so a qualified `nanosiem.logs` silently targets a table
//! literally named `nanosiem.logs` and fails at runtime (UNKNOWN_TABLE), with
//! a clean compile. This scan keeps every writer on the seam that quotes each
//! part. Test code may call the client directly with bare names.

use std::path::{Path, PathBuf};

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if name != "tests" && name != "target" && name != "node_modules" {
                rust_sources(&path, out);
            }
        } else if name.ends_with(".rs") && name != "tests.rs" && !name.ends_with("_tests.rs") {
            out.push(path);
        }
    }
}

#[test]
fn production_typed_inserts_go_through_the_qualified_name_seam() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = Vec::new();
    for krate in [
        "nanosiem-core",
        "nanosiem-enterprise",
        "nanosiem-api",
        "nanosiem-api-lib",
        "nanosiem-search",
        "nano-connector",
    ] {
        rust_sources(&repo.join(krate).join("src"), &mut files);
    }
    assert!(files.len() > 100, "scan found only {} files; the walk broke", files.len());

    let seam = Path::new("db").join("clickhouse_insert.rs");
    let mut offenders = Vec::new();
    for file in &files {
        if file.ends_with(&seam) {
            continue;
        }
        let text = std::fs::read_to_string(file).unwrap();
        for (n, line) in text.lines().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            if code.contains(".insert::<") || code.contains(".inserter::<") {
                offenders.push(format!("{}:{}: {}", file.display(), n + 1, line.trim()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "typed ClickHouse inserts must use nanosiem_core::db::clickhouse_insert::insert \
         (clickhouse-rs escapes a qualified `db.table` as one identifier):\n  {}",
        offenders.join("\n  ")
    );
}
