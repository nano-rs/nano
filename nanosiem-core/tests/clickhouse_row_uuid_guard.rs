// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5461: every `uuid::Uuid` field on a `clickhouse::Row` struct must carry
//! `#[serde(with = "clickhouse::serde::uuid")]` (or `...::uuid::option`).
//!
//! clickhouse-rs validates RowBinary against the server schema and expects a
//! UUID as a (u64, u64) pair. Without the adapter the uuid crate emits
//! length-prefixed bytes, so the read fails at runtime with "ClickHouse type
//! UUID as &[u8; N] which is not compatible" and a clean compile. The ingest
//! watchdog shipped like that and never loaded its durable state.

use std::path::{Path, PathBuf};

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = entry.file_name();
            if name != "target" && name != "node_modules" {
                rust_sources(&path, out);
            }
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// True for `#[derive(...)]` lines that derive clickhouse's `Row` (not sqlx's
/// `FromRow`).
fn derives_clickhouse_row(line: &str) -> bool {
    let Some(start) = line.find("derive(") else {
        return false;
    };
    line[start + "derive(".len()..]
        .split([',', ')'])
        .map(str::trim)
        .any(|item| item == "Row" || item == "clickhouse::Row")
}

fn is_bare_uuid_field(line: &str) -> bool {
    let line = line.trim();
    let Some((_, ty)) = line.split_once(':') else {
        return false;
    };
    let ty = ty.trim().trim_end_matches(',').trim();
    matches!(
        ty,
        "Uuid" | "uuid::Uuid" | "Option<Uuid>" | "Option<uuid::Uuid>"
    )
}

#[test]
fn clickhouse_row_uuid_fields_use_the_clickhouse_serde_adapter() {
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

    let mut offenders = Vec::new();
    for file in &files {
        let Ok(text) = std::fs::read_to_string(file) else {
            continue;
        };
        let lines: Vec<&str> = text.lines().collect();
        let mut in_row = false;
        for (idx, line) in lines.iter().enumerate() {
            if derives_clickhouse_row(line) {
                in_row = true;
                continue;
            }
            if !in_row {
                continue;
            }
            if line.trim_start().starts_with('}') {
                in_row = false;
                continue;
            }
            if is_bare_uuid_field(line) {
                let previous = idx.checked_sub(1).map(|i| lines[i]).unwrap_or("");
                if !previous.contains("clickhouse::serde::uuid") {
                    offenders.push(format!("{}:{}: {}", file.display(), idx + 1, line.trim()));
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "clickhouse::Row Uuid fields without #[serde(with = \"clickhouse::serde::uuid\")]:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn guard_recognises_the_shapes_it_scans_for() {
    assert!(derives_clickhouse_row("#[derive(Debug, Row, Deserialize)]"));
    assert!(derives_clickhouse_row("#[derive(clickhouse::Row, Serialize)]"));
    assert!(!derives_clickhouse_row("#[derive(Debug, sqlx::FromRow)]"));
    assert!(!derives_clickhouse_row("#[derive(Debug, FromRow)]"));
    assert!(is_bare_uuid_field("    event_id: Uuid,"));
    assert!(is_bare_uuid_field("    pub id: Option<uuid::Uuid>,"));
    assert!(!is_bare_uuid_field("    name: String,"));
}
