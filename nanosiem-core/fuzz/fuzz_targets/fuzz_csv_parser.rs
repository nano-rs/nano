#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use nanosiem_core::upload::{FileFormat, FileParser, ParserConfig};

#[derive(Arbitrary, Debug)]
struct CsvFuzzInput {
    data: Vec<u8>,
    delimiter: u8,
    has_headers: bool,
}

fuzz_target!(|input: CsvFuzzInput| {
    // Only use printable ASCII delimiters to avoid weird edge cases
    let delimiter = match input.delimiter % 4 {
        0 => ',',
        1 => '\t',
        2 => '|',
        3 => ';',
        _ => ',',
    };

    let parser = FileParser::new();
    let config = ParserConfig {
        format: FileFormat::Csv,
        csv_delimiter: delimiter,
        csv_has_headers: input.has_headers,
        custom_headers: None,
        encoding: "utf-8".to_string(),
        max_records: Some(1000), // Limit to prevent DoS
        skip_invalid: true,
    };

    // Parser should never panic regardless of input
    let _ = parser.parse(&input.data, &config);
});
