// SPDX-License-Identifier: AGPL-3.0-or-later
//
//! NAN-4903 content-landing proof: every upstream OCSF detection rule
//! (nano-rs content repo, unchanged) parses, every dotted field it names is an
//! OCSF attribute or a column of `ocsf_logs`, and the SQL the OCSF-profiled
//! generator emits executes against a ClickHouse carrying the generated schema
//! (`clickhouse/ocsf/init.sql`) loaded with the upstream parsers' samples.
//!
//! Opt-in (needs a checkout of the rules repo and a migrated ClickHouse):
//!
//! ```text
//! NANO_CONTENT_RULES_DIR=~/src/nano-rules \
//! CLICKHOUSE_TEST_URL=http://127.0.0.1:18124 CLICKHOUSE_ADMIN_USER=default CLICKHOUSE_ADMIN_PASSWORD= \
//!   cargo test -p nanosiem-core --test ocsf_content_rules_live -- --ignored --nocapture
//! ```
//!
//! The per-rule report prints rows returned so a reviewer can see which rules
//! the sample corpus exercises; the test fails on any parse, codegen or
//! ClickHouse execution error.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use nanosiem_core::query::{parse_query, ClickHouseSqlGenerator, TimeRange};
use nanosiem_core::search::query_processing::query_manipulation::strip_post_prevalence_commands;
use nanosiem_core::schema::{OcsfProfile, SchemaProfile};

fn rules_dir() -> Option<PathBuf> {
    std::env::var_os("NANO_CONTENT_RULES_DIR").map(PathBuf::from)
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.file_name().is_some_and(|n| n.to_string_lossy().starts_with('.')) {
            continue;
        }
        if p.is_dir() {
            collect(&p, out);
        } else if p.extension().is_some_and(|x| x == "yml" || x == "yaml") {
            out.push(p);
        }
    }
}

/// Rule files are `---\n<yaml front matter>\n---\n<nPL>`.
fn split_rule(text: &str) -> Option<(serde_yaml::Value, String)> {
    let rest = text.strip_prefix("---\n")?;
    let (front, body) = rest.split_once("\n---\n")?;
    Some((serde_yaml::from_str(front).ok()?, body.trim().to_string()))
}

/// Dotted identifiers outside string literals (`a.b.c`), the field references a
/// rule can make. Mirrors the static scan in the design doc §7.
fn dotted_fields(npl: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_str = false;
    let mut in_regex = false;
    let mut escaped = false;
    let mut last_sig = ' ';
    for c in npl.chars() {
        // `field=/regex/` literals are not field references either.
        if in_regex {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '/' {
                in_regex = false;
            }
            continue;
        }
        if !in_str && c == '/' && matches!(last_sig, '=' | '~') {
            in_regex = true;
            cur.clear();
            continue;
        }
        if !c.is_whitespace() {
            last_sig = c;
        }
        // Inside a string a backslash escapes the next char (`"\\pipe\\"` ends
        // at the final quote), so track escapes rather than the previous char.
        if in_str {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_str = false;
            }
            cur.clear();
            continue;
        }
        if c == '"' {
            in_str = true;
            if cur.contains('.') && cur.chars().next().is_some_and(|c| c.is_ascii_lowercase()) {
                out.push(cur.trim_end_matches('.').to_string());
            }
            cur.clear();
            continue;
        }
        if c.is_ascii_alphanumeric() || c == '_' || c == '.' {
            cur.push(c);
        } else {
            if cur.contains('.') && cur.chars().next().is_some_and(|c| c.is_ascii_lowercase()) {
                out.push(cur.trim_end_matches('.').to_string());
            }
            cur.clear();
        }
    }
    if cur.contains('.') {
        out.push(cur);
    }
    out
}

async fn exec(sql: &str) -> Result<String, String> {
    let url = std::env::var("CLICKHOUSE_TEST_URL").unwrap_or_else(|_| "http://localhost:8123".into());
    // Never `default`: nano's users.d keeps it container-local.
    let user = std::env::var("CLICKHOUSE_ADMIN_USER").unwrap_or_else(|_| "nanosiem_admin".into());
    let pass = std::env::var("CLICKHOUSE_ADMIN_PASSWORD").unwrap_or_default();
    let url = format!("{}/?default_format=TSV&max_execution_time=60", url.trim_end_matches('/'));
    let resp = reqwest::Client::new()
        .post(&url)
        .basic_auth(user, Some(pass))
        .body(sql.to_string())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = resp.status();
    let body = resp.text().await.map_err(|e| e.to_string())?;
    if status.is_success() {
        Ok(body)
    } else {
        Err(body.chars().take(600).collect())
    }
}

#[tokio::test]
#[ignore = "needs NANO_CONTENT_RULES_DIR and a migrated ClickHouse (see module docs)"]
async fn upstream_ocsf_rules_resolve_and_execute() {
    let Some(dir) = rules_dir() else {
        eprintln!("NANO_CONTENT_RULES_DIR unset — skipping");
        return;
    };
    let mut files = Vec::new();
    collect(&dir, &mut files);
    files.sort();
    assert!(!files.is_empty(), "no rule files under {}", dir.display());

    let profile = OcsfProfile::new();
    let gen = ClickHouseSqlGenerator::with_table("nanosiem.ocsf_logs".to_string())
        .with_profile(Arc::new(OcsfProfile::new()));
    // Wide window: upstream samples carry their original (old) timestamps.
    let range = TimeRange {
        start: "2000-01-02T00:00:00Z".parse().unwrap(),
        end: "2030-01-01T00:00:00Z".parse().unwrap(),
    };

    let mut failures = Vec::new();
    let mut unknown_fields = Vec::new();
    let (mut ran, mut matched) = (0usize, 0usize);
    for f in &files {
        let text = std::fs::read_to_string(f).unwrap();
        let Some((_meta, npl)) = split_rule(&text) else {
            failures.push(format!("{}: not a ---front matter--- rule file", f.display()));
            continue;
        };
        for field in dotted_fields(&npl) {
            // `unmapped.*` is the vendor spill namespace by definition.
            if !field.starts_with("unmapped.") && !profile.is_known_field(&field) {
                unknown_fields.push(format!("{}: {field}", f.display()));
            }
        }
        let query = match parse_query(&npl) {
            Ok(q) => q,
            Err(e) => {
                failures.push(format!("{}: parse: {e}", f.display()));
                continue;
            }
        };
        // Production runs everything after `| prevalence` as search-service
        // post-processing (host_count etc. are added in Rust, not SQL), so
        // compile exactly the SQL part the service sends to ClickHouse.
        let query = strip_post_prevalence_commands(&query);
        let sql = match gen.generate(&query, &range) {
            Ok(s) => s,
            Err(e) => {
                failures.push(format!("{}: codegen: {e}", f.display()));
                continue;
            }
        };
        match exec(&sql).await {
            Ok(rows) => {
                ran += 1;
                let n = rows.lines().filter(|l| !l.is_empty()).count();
                if n > 0 {
                    matched += 1;
                }
                println!("ok   {:>5} rows  {}", n, f.strip_prefix(&dir).unwrap_or(f).display());
            }
            Err(e) => failures.push(format!("{}: clickhouse: {e}\nSQL: {sql}", f.display())),
        }
    }
    println!(
        "\n{} rule files, {ran} executed, {matched} returned rows, {} failures, {} unknown fields",
        files.len(),
        failures.len(),
        unknown_fields.len()
    );
    for u in &unknown_fields {
        println!("unknown field  {u}");
    }
    assert!(failures.is_empty(), "rule failures:\n{}", failures.join("\n\n"));
    assert!(
        unknown_fields.is_empty(),
        "dotted fields the OCSF profile cannot resolve:\n{}",
        unknown_fields.join("\n")
    );
}
