// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5079: the OCSF publish gate falls back to a first-party parser's
//! bundled `samples:` when the operator supplies none (exact `parser_vrl`
//! match). Every bundled sample must then pass VRL and OCSF validation, or a
//! library install is refused. This walks a nano-rs/parsers checkout and runs
//! each `parsers-ocsf/*/parser.yaml` sample through the same chain the gate
//! uses (`{"message": raw}` → one compile → `validate_ocsf_event`).
//!
//! Opt-in: `NANO_PARSERS_DIR=/path/to/parsers cargo test -p nanosiem-core \
//!   --test first_party_parser_samples_ocsf -- --ignored --nocapture`

use nanosiem_core::parser_repository::parse_parser_yaml;
use nanosiem_core::parsers::{validate_ocsf_event, VrlValidator};

#[tokio::test]
#[ignore = "needs a nano-rs/parsers checkout in NANO_PARSERS_DIR"]
async fn first_party_bundled_samples_pass_the_ocsf_gate() {
    let Ok(root) = std::env::var("NANO_PARSERS_DIR") else {
        panic!("set NANO_PARSERS_DIR to a nano-rs/parsers checkout");
    };
    let dir = std::path::Path::new(&root).join("parsers-ocsf");
    nanosiem_core::parsers::test_sandbox::permit_in_process_for_test_harness();
    let validator = VrlValidator::new();
    let mut failures = Vec::new();
    let mut checked = 0usize;
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .expect("parsers-ocsf directory")
        .flatten()
        .map(|entry| entry.path().join("parser.yaml"))
        .filter(|path| path.is_file())
        .collect();
    entries.sort();
    for path in entries {
        let content = std::fs::read_to_string(&path).unwrap();
        let Ok(parsed) = parse_parser_yaml(&content) else {
            failures.push(format!("{}: YAML does not parse", path.display()));
            continue;
        };
        let Some(vrl) = parsed.parser_vrl.as_deref() else { continue };
        eprintln!("parser {}", parsed.name);
        let samples = parsed.samples.unwrap_or_default();
        let inputs: Vec<String> = samples
            .iter()
            .map(|sample| serde_json::json!({ "message": sample.raw }).to_string())
            .collect();
        // One compile per parser, as the publish gate does.
        let results = validator.test_vrl_batch(vrl, &inputs).await.expect("VRL worker");
        for (index, result) in results.into_iter().enumerate() {
            checked += 1;
            let label = format!("{} sample {}", parsed.name, index + 1);
            if !result.success {
                failures.push(format!("{label}: VRL: {}", result.error.unwrap_or_default()));
                continue;
            }
            let Some(output) = result.output else { continue };
            let report = validate_ocsf_event(&output);
            if !report.valid {
                let errors = report
                    .errors
                    .iter()
                    .take(3)
                    .map(|e| format!("{} ({})", e.attribute_path, e.code))
                    .collect::<Vec<_>>()
                    .join("; ");
                failures.push(format!("{label}: OCSF: {errors}"));
            }
        }
    }
    eprintln!("checked {checked} bundled samples, {} failed", failures.len());
    for failure in &failures {
        eprintln!("  {failure}");
    }
    assert!(failures.is_empty(), "{} bundled samples fail the OCSF gate", failures.len());
}
