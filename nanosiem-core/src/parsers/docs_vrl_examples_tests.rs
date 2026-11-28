// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5804: every ```vrl example in the parser docs compiles and, when it is a
//! whole parser (it sets `.class_uid`), its output passes the OCSF publish check.
//!
//! The pages: `docs/user-guide/parsers.md`, the source `tools/generate-docs.sh`
//! feeds the model, and `docs/generated/parsers.md`, what it wrote. Both run
//! through the same engine the Test and Publish buttons use: the parser-test
//! sandbox's validation (every gate plus the VRL compile) and its runner, then
//! `validate_ocsf_event`, the publish gate (`ocsf_attestation::apply_ocsf_validation`).
//! A whole parser passes when at least one sample line (the kind of log it is
//! written for) becomes an event that passes that check.
//!
//! A snippet that continues an earlier example (`.unmapped.x = parsed.x`)
//! says so on its first line, `# continues: parsed`. It is compiled with each
//! named variable bound to the parsed JSON object first, so every compile
//! error in it still fails the test. Nothing else is exempt.
//!
//! The open-core mirror strips `docs/` (tools/sync-to-nano-mirror.sh keeps
//! only docs/img), so the test is a no-op there, like the openapi docs guard
//! in nanosiem-api/src/openapi.rs; in this repo a missing page still fails.
use super::test_sandbox::{execute, Outcome, ParserTestJob, Work};
use super::validate_ocsf_event;
use super::vrl_functions::VrlRegistry;
use serde_json::{json, Value};
use std::path::Path;

const PAGES: &[&str] = &["docs/user-guide/parsers.md", "docs/generated/parsers.md"];

/// Raw log lines a doc example may be written for, wrapped the way a raw
/// sample reaches a parser (`{"message": <line>}`). A whole parser must turn
/// at least one of them into an event that carries `class_uid`.
fn samples() -> Vec<Value> {
    [
        r#"{"timestamp":"2026-01-02T03:04:05Z","ts":"1767323045","level":"info","component":"api","action":"login","user":"Alice","success":true,"status":"ok","client_ip":"10.0.0.5","server_ip":"10.0.0.9","trace_id":"t-1","request_id":"r-1","correlation_id":"c-1","custom":"x"}"#,
        r#"192.168.1.10 - frank [10/Oct/2026:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326 "http://example.com/" "Mozilla/5.0""#,
        "<34>1 2026-10-11T22:14:15.003Z web-01 sshd 4321 ID47 - user=alice src=10.0.0.5 Failed password",
        r#"{"EventID":4624,"TimeCreated":"2026-01-02T03:04:05.000Z","Computer":"WS-01","LogonType":"3","TargetUserName":"Alice","IpAddress":"10.0.0.5"}"#,
    ]
    .iter()
    .map(|line| json!({ "message": line }))
    .collect()
}

fn vrl_blocks(markdown: &str) -> Vec<(usize, String)> {
    let mut blocks = Vec::new();
    let mut current: Option<(usize, String)> = None;
    for (index, line) in markdown.lines().enumerate() {
        match &mut current {
            None if line.trim() == "```vrl" => current = Some((index + 1, String::new())),
            None => {}
            Some(_) if line.trim() == "```" => blocks.extend(current.take()),
            Some((_, body)) => {
                body.push_str(line);
                body.push('\n');
            }
        }
    }
    assert!(current.is_none(), "unterminated ```vrl block");
    blocks
}

fn diagnostics(code: &str) -> Vec<String> {
    let job = ParserTestJob {
        registry: VrlRegistry::Parser,
        work: Work::ValidateCollect { code: code.into() },
    };
    match execute(&job) {
        Outcome::ValidateCollect(verdict, each) if !verdict.valid => {
            if each.is_empty() {
                vec![verdict.error.unwrap_or_else(|| "invalid".into())]
            } else {
                each
            }
        }
        Outcome::ValidateCollect(..) => Vec::new(),
        other => vec![format!("unexpected outcome {other:?}")],
    }
}

fn run(code: &str) -> Vec<Result<Value, String>> {
    let job = ParserTestJob {
        registry: VrlRegistry::Parser,
        work: Work::Each { code: code.into(), inputs: samples() },
    };
    match execute(&job) {
        Outcome::Each(Ok(rows)) => rows,
        Outcome::Each(Err(error)) => vec![Err(error)],
        other => vec![Err(format!("unexpected outcome {other:?}"))],
    }
}

/// The variables a `# continues: a, b` snippet assumes, or `None` for a
/// stand-alone example.
fn continues(code: &str) -> Option<Vec<String>> {
    let first = code.lines().next()?.trim();
    let vars = first.strip_prefix("# continues:")?;
    let vars: Vec<String> = vars.split(',').map(|v| v.trim().to_string()).filter(|v| !v.is_empty()).collect();
    assert!(
        vars.iter().all(|v| v.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')),
        "bad `# continues:` line: {first}"
    );
    Some(vars)
}

#[test]
fn every_parser_doc_vrl_example_compiles_and_passes_the_ocsf_publish_check() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    if !root.join("docs/user-guide").is_dir() {
        eprintln!("docs/user-guide is absent (open-core mirror); skipping the parser doc examples");
        return;
    }
    let mut failures = Vec::new();
    let mut checked = 0;
    for page in PAGES {
        let markdown = std::fs::read_to_string(root.join(page)).unwrap_or_else(|e| panic!("{page}: {e}"));
        let blocks = vrl_blocks(&markdown);
        assert!(!blocks.is_empty(), "{page} has no ```vrl examples");
        for (line, code) in blocks {
            let at = format!("{page}:{line}");
            checked += 1;
            if let Some(vars) = continues(&code) {
                let prelude: String =
                    vars.iter().map(|v| format!("{v} = object!(parse_json!(.message))\n")).collect();
                let errors = diagnostics(&format!("{prelude}{code}"));
                if !errors.is_empty() {
                    failures.push(format!("{at}: snippet does not compile: {}", errors.join(" | ")));
                }
                continue;
            }
            let errors = diagnostics(&code);
            if !errors.is_empty() {
                failures.push(format!("{at}: does not compile: {}", errors.join(" | ")));
                continue;
            }
            if !code.contains(".class_uid") {
                continue;
            }
            let events: Vec<Value> = run(&code)
                .into_iter()
                .filter_map(Result::ok)
                .filter(|event| event.get("class_uid").is_some())
                .collect();
            if events.is_empty() {
                failures.push(format!("{at}: sets .class_uid but no sample produced an event with it"));
                continue;
            }
            // The example is written for one kind of log, so it passes when the
            // event it makes from a matching sample passes the publish check.
            let verdicts: Vec<Vec<String>> = events
                .iter()
                .map(|event| {
                    validate_ocsf_event(event)
                        .errors
                        .iter()
                        .map(|e| format!("{}: {}", e.attribute_path, e.message))
                        .collect()
                })
                .collect();
            if verdicts.iter().all(|errors| !errors.is_empty()) {
                let fewest = verdicts.iter().min_by_key(|errors| errors.len()).expect("non-empty");
                failures.push(format!("{at}: fails the OCSF publish check: {}", fewest.join("; ")));
            }
        }
    }
    assert!(checked > 0, "no runnable ```vrl example found");
    assert!(failures.is_empty(), "{} parser doc example(s) broken:\n{}", failures.len(), failures.join("\n"));
}
