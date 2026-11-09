// SPDX-License-Identifier: AGPL-3.0-or-later
//! Source lint: forbid the raw-interpolation shapes behind the 2026-11-08
//! security review findings (NAN-5009/5010/5018/5034).
//!
//! This is a textual tripwire for regressions of KNOWN bad shapes, not a proof.
//! The semantic gate is the injection canary in
//! `search/service/npl_injection_canary_tests.rs`. Use the helpers in
//! [`crate::sql_hygiene`] instead of any of these shapes.
//!
//! A line that legitimately matches (a compile-time constant, a value that is
//! allowlisted right after) carries `// sql-lint: allow(<reason>)` on the same
//! line or the line above.

use std::path::{Path, PathBuf};

struct Rule {
    name: &'static str,
    pattern: &'static str,
    why: &'static str,
    /// Path prefixes (relative to the workspace root) the rule applies to.
    scope: &'static [&'static str],
}

/// Where nPL / detection SQL is generated.
const CODEGEN: &[&str] = &[
    "nanosiem-core/src/query/clickhouse_sql_gen",
    "nanosiem-core/src/search/service",
    "nanosiem-core/src/detection/materialized_view.rs",
];

const RULES: &[Rule] = &[
    Rule {
        name: "strip-and-rewrap",
        pattern: r#"trim_matches\('\\''\)|trim_start_matches\('\\''\)|trim_end_matches\('\\''\)|strip_prefix\('\\''\)"#,
        why: "stripping quotes off lowered SQL and re-wrapping it is how NAN-5010 happened; \
              read the raw AST literal and use sql_hygiene::string_literal",
        scope: CODEGEN,
    },
    Rule {
        name: "inline-literal-escaper",
        pattern: r#"replace\('\\'', "(''|\\\\')"\)"#,
        why: "use sql_hygiene::escape_sql_string / string_literal",
        scope: SCANNED,
    },
    Rule {
        name: "inline-identifier-quoter",
        pattern: r#"replace\('"', "\\"\\""\)"#,
        why: "use sql_hygiene::quote_identifier / quote_identifier_always \
              (quote-doubling alone ignores ClickHouse backslash escapes)",
        scope: SCANNED,
    },
    Rule {
        name: "raw-qualified-column",
        pattern: r#"format!\("l\.\{"#,
        why: "use sql_hygiene::qualified_column (NAN-5009 sibling)",
        scope: CODEGEN,
    },
    Rule {
        name: "raw-ddl-object-name",
        pattern: r#""(DROP|CREATE|ALTER|RENAME|TRUNCATE|OPTIMIZE|EXCHANGE)\b[^"]*\{"#,
        why: "DDL object names must be derived or validated, never read raw (NAN-5018)",
        scope: &["nanosiem-core/src/detection", "nanosiem-enterprise/src/tuning"],
    },
];

/// Directories scanned, relative to the workspace root. Missing directories
/// (the enterprise crate in the open-core mirror) are skipped.
const SCANNED: &[&str] = &[
    "nanosiem-core/src/query",
    "nanosiem-core/src/search",
    "nanosiem-core/src/detection",
    "nanosiem-core/src/prevalence",
    "nanosiem-core/src/gdpr",
    "nanosiem-core/src/health",
    "nanosiem-core/src/feeds",
    "nanosiem-core/src/settings",
    "nanosiem-core/src/platform_enrichment",
    "nanosiem-core/src/log_sources",
    "nanosiem-search/src",
    "nanosiem-api/src/handlers",
    "nanosiem-enterprise/src",
];

fn is_test_file(path: &Path) -> bool {
    let s = path.to_string_lossy();
    s.ends_with("_tests.rs")
        || s.ends_with("/tests.rs")
        || s.contains("/tests/")
        || s.ends_with("_test.rs")
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") && !is_test_file(&path) {
            out.push(path);
        }
    }
}

/// Lines of non-test code: everything before the first `#[cfg(test)]` module.
fn non_test_lines(src: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    for line in src.lines() {
        if line.trim_start().starts_with("#[cfg(test)]") {
            break;
        }
        lines.push(line);
    }
    lines
}

#[test]
fn generated_sql_never_uses_raw_interpolation_shapes() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let compiled: Vec<(regex::Regex, &Rule)> = RULES
        .iter()
        .map(|r| (regex::Regex::new(r.pattern).expect("lint regex"), r))
        .collect();

    let mut files = Vec::new();
    for dir in SCANNED {
        rust_files(&root.join(dir), &mut files);
    }
    assert!(files.len() > 200, "lint scanned too few files: {}", files.len());

    let mut violations = Vec::new();
    for file in &files {
        let rel = file.strip_prefix(&root).unwrap_or(file).to_string_lossy().into_owned();
        let src = std::fs::read_to_string(file).expect("read source");
        let lines = non_test_lines(&src);
        for (i, line) in lines.iter().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            let allowed = line.contains("sql-lint: allow")
                || i.checked_sub(1)
                    .and_then(|p| lines.get(p))
                    .is_some_and(|prev| prev.contains("sql-lint: allow"));
            if allowed {
                continue;
            }
            for (re, rule) in &compiled {
                if !rule.scope.iter().any(|prefix| rel.starts_with(prefix)) {
                    continue;
                }
                if re.is_match(line) {
                    violations.push(format!(
                        "{}:{}: [{}] {}\n    {}",
                        rel,
                        i + 1,
                        rule.name,
                        rule.why,
                        line.trim()
                    ));
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "{} raw SQL interpolation shape(s):\n{}",
        violations.len(),
        violations.join("\n")
    );
}
