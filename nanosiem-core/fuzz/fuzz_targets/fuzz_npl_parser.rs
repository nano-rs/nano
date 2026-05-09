#![no_main]

use libfuzzer_sys::fuzz_target;
use nanosiem_core::query::parse_query;

fuzz_target!(|data: &[u8]| {
    // Convert bytes to string - parser should handle any UTF-8 input gracefully
    if let Ok(input) = std::str::from_utf8(data) {
        // The parser should NEVER panic, regardless of input
        // It should return Ok(Query) or Err(ParseError)
        let _ = parse_query(input);
    }
});
