// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5821 guard: a transactional PostgreSQL migration must not run its own
//! transaction control.
//!
//! sqlx runs every migration that does not start with `-- no-transaction` in
//! a transaction it opens, and inserts the `_sqlx_migrations` row in that same
//! transaction. A `BEGIN;` inside the file only warns ("there is already a
//! transaction in progress"), but its `COMMIT;` commits sqlx's transaction
//! early: the migration's changes are then committed separately from the row
//! recording them, and sqlx's own COMMIT warns "there is no transaction in
//! progress". A migration that needs its own commits (for example to release
//! locks between phases) must opt out with `-- no-transaction` instead.
//!
//! The legacy files below did this before the guard existed. They are applied
//! everywhere and checksum-locked (editing one fails every existing install at
//! boot), so they are allowlisted by version and the list may only shrink.
//!
//! DB-free: text analysis of the checked-in migrations. The enterprise
//! directory is read at runtime and skipped when absent (open-core mirror).

use std::path::{Path, PathBuf};

/// Versions that wrap themselves in `BEGIN; … COMMIT;` inside sqlx's
/// transaction. Applied and checksum-locked: never add to this list.
const LEGACY_SELF_WRAPPED: &[u64] = &[152, 153, 154, 155, 160, 161, 162, 9_000_008, 9_000_052];

fn migration_dirs() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("migrations");
    vec![root.join("postgres"), root.join("postgres-enterprise")]
}

/// Split `sql` into top-level statements with one lexical pass, the way
/// PostgreSQL reads it: `-- …` line comments, nested `/* … */` block
/// comments, `'…'` strings (`''` doubling, and backslash escapes in `E'…'`),
/// `"…"` quoted identifiers and `$tag$ … $tag$` dollar quotes are skipped as
/// a whole, so neither a `;` nor a keyword inside them counts. Only a
/// top-level `;` ends a statement. Each statement comes back as its
/// uppercased words outside those regions.
fn top_level_statements(sql: &str) -> Vec<String> {
    let chars: Vec<char> = sql.chars().collect();
    let mut statements = Vec::new();
    let mut current = String::new();
    let mut i = 0;
    let at = |i: usize| chars.get(i).copied();
    while i < chars.len() {
        let c = chars[i];
        match c {
            '-' if at(i + 1) == Some('-') => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
                current.push(' ');
            }
            '/' if at(i + 1) == Some('*') => {
                let mut depth = 1;
                i += 2;
                while i < chars.len() && depth > 0 {
                    if chars[i] == '/' && at(i + 1) == Some('*') {
                        depth += 1;
                        i += 2;
                    } else if chars[i] == '*' && at(i + 1) == Some('/') {
                        depth -= 1;
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                current.push(' ');
            }
            '\'' => {
                // E'…' (or e'…') allows backslash escapes.
                let escapes = i > 0
                    && matches!(chars[i - 1], 'E' | 'e')
                    && (i < 2 || !(chars[i - 2].is_alphanumeric() || chars[i - 2] == '_'));
                i += 1;
                while i < chars.len() {
                    match chars[i] {
                        '\\' if escapes => i += 2,
                        '\'' if at(i + 1) == Some('\'') => i += 2,
                        '\'' => {
                            i += 1;
                            break;
                        }
                        _ => i += 1,
                    }
                }
                current.push(' ');
            }
            '"' => {
                i += 1;
                while i < chars.len() {
                    if chars[i] == '"' && at(i + 1) == Some('"') {
                        i += 2;
                    } else if chars[i] == '"' {
                        i += 1;
                        break;
                    } else {
                        i += 1;
                    }
                }
                current.push(' ');
            }
            '$' => {
                // A dollar-quote tag: empty, or a letter/underscore (or
                // non-ASCII) then letters, digits, underscores. `$1` is a
                // parameter, not a quote. Inside an identifier (`a$b$`), `$`
                // is an identifier character.
                let in_word = i > 0 && (chars[i - 1].is_alphanumeric() || chars[i - 1] == '_');
                let mut j = i + 1;
                let tag_ok = match at(j) {
                    Some(ch) if ch.is_alphabetic() || ch == '_' || !ch.is_ascii() => true,
                    Some('$') => true,
                    _ => false,
                };
                if tag_ok && !in_word {
                    while j < chars.len() && (chars[j].is_alphanumeric() || chars[j] == '_' || !chars[j].is_ascii()) && chars[j] != '$' {
                        j += 1;
                    }
                }
                if tag_ok && !in_word && at(j) == Some('$') {
                    let delimiter: String = chars[i..=j].iter().collect();
                    let body_start = j + 1;
                    let rest: String = chars[body_start..].iter().collect();
                    match rest.find(&delimiter) {
                        Some(offset) => {
                            i = body_start + rest[..offset].chars().count() + delimiter.chars().count();
                        }
                        None => i = chars.len(), // unterminated: PostgreSQL fails too
                    }
                    current.push(' ');
                } else {
                    current.push(c);
                    i += 1;
                }
            }
            ';' => {
                statements.push(std::mem::take(&mut current));
                i += 1;
            }
            _ => {
                current.push(c);
                i += 1;
            }
        }
    }
    statements.push(current);
    statements
        .into_iter()
        .map(|stmt| stmt.split_whitespace().collect::<Vec<_>>().join(" ").to_uppercase())
        .filter(|stmt| !stmt.is_empty())
        .collect()
}

/// Top-level transaction-control statements in `sql`, by statement text.
fn transaction_control_statements(sql: &str) -> Vec<String> {
    top_level_statements(sql)
        .into_iter()
        .filter(|stmt| {
            let first = stmt.split(' ').next().unwrap_or("");
            matches!(first, "BEGIN" | "COMMIT" | "ROLLBACK" | "END" | "ABORT")
                || stmt.starts_with("START TRANSACTION")
        })
        .collect()
}

fn version_of(path: &Path) -> Option<u64> {
    let name = path.file_name()?.to_str()?;
    name.split('_').next()?.parse().ok()
}

#[test]
fn transactional_migrations_do_not_run_their_own_transaction_control() {
    let mut scanned = 0usize;
    let mut violations = Vec::new();
    let mut legacy_seen = Vec::new();
    for dir in migration_dirs() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue; // enterprise overlay stripped from the open-core mirror
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("sql") {
                continue;
            }
            let sql = std::fs::read_to_string(&path).expect("read migration");
            scanned += 1;
            // Same opt-out test sqlx applies (`vendor/sqlx-core/src/migrate/source.rs`).
            if sql.starts_with("-- no-transaction") {
                continue;
            }
            let found = transaction_control_statements(&sql);
            if found.is_empty() {
                continue;
            }
            let version = version_of(&path).expect("numbered migration");
            if LEGACY_SELF_WRAPPED.contains(&version) {
                legacy_seen.push(version);
                continue;
            }
            violations.push(format!("{}: {found:?}", path.display()));
        }
    }
    assert!(scanned > 100, "expected the migration directories, scanned {scanned} files");
    assert!(
        violations.is_empty(),
        "transactional migrations must not BEGIN/COMMIT/ROLLBACK themselves (sqlx already \
         runs them in a transaction; start the file with `-- no-transaction` if it needs \
         its own commits):\n{}",
        violations.join("\n")
    );
    // Keep the allowlist honest: every open-tier entry must still be present
    // (enterprise entries are absent from the open-core mirror).
    for version in LEGACY_SELF_WRAPPED.iter().filter(|v| **v < 9_000_000) {
        assert!(
            legacy_seen.contains(version),
            "allowlisted migration {version} no longer self-wraps; drop it from the list"
        );
    }
}

#[test]
fn detector_ignores_plpgsql_blocks_and_comments() {
    let plpgsql = "DO $$\nBEGIN\n  PERFORM 1;\nEND;\n$$;\nCREATE FUNCTION f() RETURNS int AS $fn$ BEGIN RETURN 1; END; $fn$ LANGUAGE plpgsql;";
    assert!(transaction_control_statements(plpgsql).is_empty());
    assert!(transaction_control_statements("-- COMMIT;\nSELECT 1;").is_empty());
    assert!(transaction_control_statements("UPDATE t SET a = $1;").is_empty());

    let wrapped = "BEGIN;\nCREATE TABLE t (id int);\nCOMMIT;\n";
    assert_eq!(transaction_control_statements(wrapped), vec!["BEGIN", "COMMIT"]);
    assert_eq!(
        transaction_control_statements("start transaction;\nSELECT 1;\nrollback;"),
        vec!["START TRANSACTION", "ROLLBACK"]
    );
}

/// Review cases (NAN-5821): every quoting form is lexed in one pass.
#[test]
fn detector_lexes_comments_strings_and_dollar_quotes_in_one_pass() {
    // `$$` in a line comment neither hides the rest of the file ...
    assert_eq!(
        transaction_control_statements("-- Uses a DO $$ block.\nBEGIN;\nCREATE TABLE t (id int);\nCOMMIT;\n"),
        vec!["BEGIN", "COMMIT"]
    );
    // ... nor pairs with a real dollar quote and exposes its PL/pgSQL body.
    assert_eq!(
        transaction_control_statements(
            "-- a DO $$ block below\nDO $$ BEGIN PERFORM 1; END; $$;\nCOMMIT;\n"
        ),
        vec!["COMMIT"]
    );
    // A digit cannot start a dollar-quote tag.
    assert_eq!(
        transaction_control_statements("SELECT 1; -- costs $100$ total\nCOMMIT;"),
        vec!["COMMIT"]
    );
    // `--` inside a string does not swallow the statement's `;` ...
    assert_eq!(
        transaction_control_statements(
            "COMMENT ON TABLE t IS 'built with --features enterprise';\nBEGIN;\nCOMMIT;"
        ),
        vec!["BEGIN", "COMMIT"]
    );
    // ... and `;` inside a string, a doubled quote, an E'' escape or a quoted
    // identifier does not split a statement.
    assert!(transaction_control_statements(
        "COMMENT ON COLUMN t.x IS 'Start time; end time is exclusive';\n\
         COMMENT ON COLUMN t.y IS 'it''s; commit sha';\n\
         SELECT E'a\\'; commit';\n\
         CREATE TABLE \"weird; commit\" (id int);"
    )
    .is_empty());
    // Block comments around and inside statements, nested ones included.
    assert_eq!(
        transaction_control_statements(
            "/* header */ BEGIN; CREATE TABLE t (id int); /* footer */ COMMIT;"
        ),
        vec!["BEGIN", "COMMIT"]
    );
    assert!(transaction_control_statements("SELECT 1; /* note; COMMIT; */").is_empty());
    assert!(transaction_control_statements("SELECT 1; /* a /* nested; COMMIT; */ still; ROLLBACK; */").is_empty());
    // A tagged dollar quote containing `$$` and `;`.
    assert!(transaction_control_statements(
        "CREATE FUNCTION f() RETURNS int AS $body$ BEGIN RETURN $$x$$; END; $body$ LANGUAGE plpgsql;"
    )
    .is_empty());
}
