// SPDX-License-Identifier: AGPL-3.0-or-later

//! Validate newline-delimited JSON events with Nano's embedded OCSF contract.
//!
//! The Log Sources API uses the same library function. This tiny stdin/stdout
//! adapter exists so corpus and official-validator differential tests do not
//! need a running Nano stack.

use std::io::{self, BufRead, BufWriter, Write};

use nanosiem_core::parsers::{validate_ocsf_event, OcsfValidationResult};
use serde::Serialize;

#[derive(Serialize)]
struct LineResult {
    line: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    parse_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    validation: Option<OcsfValidationResult>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut output = BufWriter::new(stdout.lock());

    for (index, line) in stdin.lock().lines().enumerate() {
        let line_number = index + 1;
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let result = match serde_json::from_str(&line) {
            Ok(event) => LineResult {
                line: line_number,
                parse_error: None,
                validation: Some(validate_ocsf_event(&event)),
            },
            Err(error) => LineResult {
                line: line_number,
                parse_error: Some(error.to_string()),
                validation: None,
            },
        };
        serde_json::to_writer(&mut output, &result)?;
        output.write_all(b"\n")?;
    }
    output.flush()?;
    Ok(())
}
