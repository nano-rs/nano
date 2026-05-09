#![no_main]

use libfuzzer_sys::fuzz_target;
use nanosiem_core::ingestion::LogParser;

fuzz_target!(|data: &[u8]| {
    // Convert to string - log parser expects text input
    if let Ok(input) = std::str::from_utf8(data) {
        let parser = LogParser::new();

        // Test main parse entry point (auto-detects format: syslog, CEF, LEEF, JSON)
        let _ = parser.parse(input);
    }
});
