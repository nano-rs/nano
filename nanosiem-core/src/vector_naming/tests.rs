//! Tests for canonical Vector component naming (NAN-2196).

use super::{safe_name, source_component_id};

#[test]
fn safe_name_collapses_non_alphanumerics_and_lowercases() {
    assert_eq!(safe_name("AWS ALB"), "aws_alb");
    assert_eq!(safe_name("my-source"), "my_source");
    assert_eq!(safe_name("Prod/Firewall #2"), "prod_firewall__2");
    assert_eq!(safe_name("already_safe"), "already_safe");
}

#[test]
fn safe_name_is_lossy_and_that_is_intentional() {
    // Documented in the module docs: several distinct names collapse to one
    // identifier. Anything needing the original must keep it separately.
    assert_eq!(safe_name("My Source"), safe_name("my-source"));
    assert_eq!(safe_name("a.b"), safe_name("a b"));
}

#[test]
fn safe_name_handles_unicode_and_empty() {
    // `is_alphanumeric` is Unicode-aware, so these survive rather than collapse.
    assert_eq!(safe_name("café"), "café");
    assert_eq!(safe_name("日本語"), "日本語");
    assert_eq!(safe_name(""), "");
    assert_eq!(safe_name("---"), "___");
}

/// The load-bearing assertion for NAN-2196.
///
/// `source_component_id` is how a collector error is attributed back to a log
/// source. If it ever stops matching the `[sources.<id>]` key the config
/// generator writes, attribution silently yields nothing — and a broken source
/// renders as merely quiet, which is the precise bug the error channel exists
/// to fix. A silent failure, so it gets an explicit test.
#[test]
fn component_id_matches_generated_source_name() {
    // Mirrors `format!("{}_source", safe_name(name))` in
    // `source_configs::service::generate_*_source`.
    for name in [
        "AWS ALB",
        "aws_alb",
        "Prod Kafka",
        "gcp pub/sub",
        "Splunk HEC #1",
    ] {
        assert_eq!(
            source_component_id(name),
            format!("{}_source", safe_name(name)),
            "component id must equal the generated [sources.…] key for {name:?}"
        );
    }
}

#[test]
fn component_id_is_stable_for_the_real_nan2186_case() {
    // The source that failed during NAN-2186 validation reported
    // component_id=aws_alb_source. Pinning the exact observed value.
    assert_eq!(source_component_id("AWS ALB"), "aws_alb_source");
}
