// SPDX-License-Identifier: AGPL-3.0-or-later

//! Print nano's input contract for parser programs (NAN-5883).
//!
//! The same classifier the Vector config renderer uses
//! (`vector_config::hec_payload::input_contract`): a `# nano:input=json|text|
//! json_or_text` declaration, else inference from the first structural
//! decoder (comments and generated blocks skipped). Content repositories run
//! this pinned binary instead of keeping a port of the rules.
//!
//! Input: newline-delimited JSON on stdin, one `{"name": "...", "parser_vrl":
//! "..."}` per line. Output: one line per input,
//! `{"name", "contract", "declared", "declared_v1", "declared_v2", "inferred",
//! "legacy", "warnings", "reads_json_first"}`: `legacy` is what nano before
//! v2.0.36 decides; `reads_json_first` flags a `text` parser whose first
//! decoder is `parse_json`. A line that is not such an object prints
//! `{"line", "error"}`, and the program then exits with status 2.

use std::io::{self, BufRead, BufWriter, Write};

use nanosiem_core::parsers::parser_input_contract;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct Program {
    #[serde(default)]
    name: Option<String>,
    parser_vrl: String,
}

#[derive(Serialize)]
struct Verdict<'a> {
    name: Option<&'a str>,
    contract: &'static str,
    declared: bool,
    declared_v1: Option<&'static str>,
    declared_v2: Option<&'static str>,
    inferred: &'static str,
    legacy: &'static str,
    warnings: &'a [String],
    reads_json_first: bool,
}

#[derive(Serialize)]
struct LineError {
    line: usize,
    error: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut output = BufWriter::new(stdout.lock());
    let mut malformed = false;
    for (index, line) in stdin.lock().lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<Program>(&line) {
            Ok(program) => {
                let verdict = parser_input_contract(&program.parser_vrl);
                serde_json::to_writer(
                    &mut output,
                    &Verdict {
                        name: program.name.as_deref(),
                        contract: verdict.contract.as_str(),
                        declared: verdict.declared,
                        declared_v1: verdict.declared_v1.map(|c| c.as_str()),
                        declared_v2: verdict.declared_v2.map(|c| c.as_str()),
                        inferred: verdict.inferred.as_str(),
                        legacy: verdict.legacy.as_str(),
                        warnings: &verdict.warnings,
                        reads_json_first: verdict.reads_json_first,
                    },
                )?;
            }
            Err(error) => {
                malformed = true;
                serde_json::to_writer(&mut output, &LineError { line: index + 1, error: error.to_string() })?
            }
        }
        output.write_all(b"\n")?;
    }
    output.flush()?;
    if malformed {
        drop(output);
        std::process::exit(2);
    }
    Ok(())
}
