#![no_main]

use libfuzzer_sys::fuzz_target;
use nanosiem_core::query::{parse_query, ClickHouseSqlGenerator, TimeRange};
use chrono::{Utc, Duration};

fuzz_target!(|data: &[u8]| {
    // Convert bytes to string
    if let Ok(input) = std::str::from_utf8(data) {
        // First parse the query
        if let Ok(query) = parse_query(input) {
            // If parsing succeeds, try to generate SQL
            // This catches cases where valid AST produces invalid/dangerous SQL
            let time_range = TimeRange {
                start: Utc::now() - Duration::hours(24),
                end: Utc::now(),
            };

            // SQL generation should never panic
            let generator = ClickHouseSqlGenerator::new();
            let _ = generator.generate(&query, &time_range);
        }
    }
});
