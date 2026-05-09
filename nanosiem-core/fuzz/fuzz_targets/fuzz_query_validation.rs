#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

use nanosiem_core::query::{
    parse_query, validate_field_name, suggest_similar_fields,
    validate_query_fields, analyze_query_cost,
};

#[derive(Arbitrary, Debug)]
struct QueryValidationInput {
    field_name: String,
    query_string: String,
    max_suggestions: u8,
}

fuzz_target!(|input: QueryValidationInput| {
    // Limit input sizes to prevent OOM
    if input.field_name.len() > 1000 {
        return;
    }
    if input.query_string.len() > 5000 {
        return;
    }

    // 1. Fuzz validate_field_name - should never panic
    let _ = validate_field_name(&input.field_name);

    // 2. Fuzz suggest_similar_fields with bounded suggestions
    // Cap at 20 suggestions to avoid excessive computation
    let max_suggestions = (input.max_suggestions % 20) as usize + 1;
    let _ = suggest_similar_fields(&input.field_name, max_suggestions);

    // 3. If query parses successfully, fuzz validation functions
    if let Ok(query) = parse_query(&input.query_string) {
        // Fuzz validate_query_fields - walks AST validating field names
        let _ = validate_query_fields(&query);

        // Fuzz analyze_query_cost - query cost/complexity analysis
        let _ = analyze_query_cost(&query);
    }
});
