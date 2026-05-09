#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use chrono::Utc;
use uuid::Uuid;
use std::collections::HashMap;

use nanosiem_core::parsers::{
    AutoDetector, DetectionPattern, PatternRule,
};

#[derive(Arbitrary, Debug)]
struct AutoDetectFuzzInput {
    log_content: String,
    patterns: Vec<FuzzPattern>,
    field_values: Vec<(String, String)>,
    threshold: u8,
}

#[derive(Arbitrary, Debug)]
struct FuzzPattern {
    source_type: String,
    rules: Vec<FuzzRule>,
}

#[derive(Arbitrary, Debug)]
struct FuzzRule {
    field: String,
    regex: String,
    weight: u8,
}

fuzz_target!(|input: AutoDetectFuzzInput| {
    // Limit input sizes to prevent OOM
    if input.log_content.len() > 10_000 {
        return;
    }
    if input.patterns.len() > 10 {
        return;
    }

    // Convert fuzz patterns to DetectionPattern
    let detection_patterns: Vec<DetectionPattern> = input
        .patterns
        .iter()
        .filter(|p| !p.rules.is_empty() && p.rules.len() <= 5)
        .map(|p| {
            let rules: Vec<PatternRule> = p
                .rules
                .iter()
                .filter(|r| r.regex.len() <= 100) // Limit regex length
                .map(|r| PatternRule {
                    field: r.field.clone(),
                    regex: r.regex.clone(),
                    weight: (r.weight as f32) / 255.0,
                })
                .collect();

            let patterns_json = serde_json::to_value(&rules).unwrap_or_default();

            DetectionPattern {
                id: Uuid::now_v7(),
                source_type: p.source_type.clone(),
                patterns: patterns_json,
                priority: 0,
                enabled: true,
                created_at: Utc::now(),
            }
        })
        .collect();

    if detection_patterns.is_empty() {
        return;
    }

    // Create detector with arbitrary threshold
    let threshold = (input.threshold as f32) / 255.0;
    let mut detector = AutoDetector::with_threshold(threshold);

    // Load patterns - this compiles regexes, may fail on invalid patterns
    if detector.load_patterns_from_list(detection_patterns).is_err() {
        return; // Invalid regex is expected, not a bug
    }

    // Build fields map
    let fields: HashMap<String, String> = input
        .field_values
        .iter()
        .take(10)
        .cloned()
        .collect();

    // Run detection - should never panic
    let _ = detector.detect(&input.log_content);
    let _ = detector.detect_with_fields(&input.log_content, Some(&fields));
});
