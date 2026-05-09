#![no_main]

use libfuzzer_sys::fuzz_target;
use nanosiem_core::upload::{FileFormat, FileParser, ParserConfig};

fuzz_target!(|data: &[u8]| {
    let parser = FileParser::new();

    // Test with auto-detect format
    let config_auto = ParserConfig {
        format: FileFormat::Csv, // Will be overridden by detect_format
        csv_delimiter: ',',
        csv_has_headers: true,
        custom_headers: None,
        encoding: "utf-8".to_string(),
        max_records: Some(1000), // Limit to prevent DoS
        skip_invalid: true,
    };

    // Try parsing with auto-detection
    let _ = parser.parse(data, &config_auto);

    // Also test format detection directly
    let _ = FileParser::detect_format(data);

    // Test preview (limited parsing)
    let _ = parser.preview(data, &config_auto, 10);
});
