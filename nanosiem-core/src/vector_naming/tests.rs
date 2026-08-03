//! Tests for canonical Vector component naming (NAN-2196).

use super::{
    describe_identity_collisions, describe_identity_conflict, find_identity_collisions,
    find_identity_holder, safe_name, source_component_id,
};

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

// ---------------------------------------------------------------------------
// NAN-2305: generated-identity uniqueness
// ---------------------------------------------------------------------------

fn row(seed: u128, name: &str) -> (uuid::Uuid, String, String) {
    (
        uuid::Uuid::from_u128(seed),
        safe_name(name),
        name.to_string(),
    )
}

/// The defect itself: three names a user can plausibly pick, one generated
/// filename / route key. Without a set-level check these deploy silently and
/// the last writer's config is the only one on disk.
#[test]
fn names_differing_only_by_case_spacing_or_punctuation_collide() {
    let found = find_identity_collisions([
        row(1, "My Source"),
        row(2, "my-source"),
        row(3, "My/Source"),
    ]);

    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].generated_id, "my_source");
    assert_eq!(found[0].names, ["My Source", "My/Source", "my-source"]);
}

/// Distinct names must not be flagged — a false positive here fails a deploy
/// that was fine, which stops ingestion just as effectively as the bug.
#[test]
fn distinct_generated_identifiers_are_not_a_collision() {
    let found = find_identity_collisions([
        row(1, "Apache HTTP Server"),
        row(2, "Microsoft Sysmon (JSON)"),
        row(3, "AWS CloudTrail"),
    ]);
    assert!(found.is_empty(), "{found:?}");
}

/// Callers assemble parser slices from concatenated lists. One row appearing
/// twice is not two sources contending for a filename, and must not fail the
/// deploy.
#[test]
fn one_row_listed_twice_is_not_a_collision() {
    let found = find_identity_collisions([row(1, "My Source"), row(1, "My Source")]);
    assert!(found.is_empty(), "{found:?}");
}

/// Unicode alphanumerics survive `safe_name`, so these are genuinely distinct
/// identifiers. Pinned because migration 283's SQL index normalizes with the
/// ASCII-only `[^A-Za-z0-9]` and WOULD collapse them — the divergence is
/// deliberate (see the migration) and this records which side is which.
#[test]
fn unicode_alphanumerics_do_not_collide_in_rust() {
    let found = find_identity_collisions([row(1, "Café"), row(2, "Cafe")]);
    assert!(found.is_empty(), "{found:?}");
}

/// The create/rename path: an existing holder is found by generated value,
/// not by display name.
#[test]
fn identity_holder_is_found_across_differing_display_names() {
    let existing = [
        (safe_name("Apache HTTP Server"), "Apache HTTP Server".into()),
        (safe_name("My Source"), "My Source".into()),
    ];

    assert_eq!(
        find_identity_holder(&safe_name("my-source"), existing.clone()),
        Some("My Source".to_string()),
    );
    assert_eq!(find_identity_holder(&safe_name("Okta"), existing), None);
}

/// A rename that keeps the same stem must be allowed. Callers exclude the row
/// under edit; if they did not, `My Source` → `My  Source` would be rejected
/// as conflicting with itself and renames would be unreachable.
#[test]
fn excluded_row_does_not_conflict_with_itself() {
    let self_row = uuid::Uuid::from_u128(1);
    let rows = [(self_row, "My Source".to_string())];

    let holder = find_identity_holder(
        &safe_name("My  Source"),
        rows.iter()
            .filter(|(id, _)| *id != self_row)
            .map(|(_, name)| (safe_name(name), name.clone())),
    );
    assert_eq!(holder, None);
}

/// The message has to name the generated value AND the conflicting row —
/// "name already exists" is false here, the names visibly differ.
#[test]
fn conflict_message_names_generated_value_and_holder() {
    let msg = describe_identity_conflict("log source", "my-source", "my_source", "My Source");

    assert!(msg.contains("my-source"), "{msg}");
    assert!(msg.contains("my_source"), "{msg}");
    assert!(msg.contains("My Source"), "{msg}");
}

/// Deploy refusal must list every claimant, because resolving it is a rename
/// only the operator can choose.
#[test]
fn collision_message_lists_every_claimant() {
    let found = find_identity_collisions([row(1, "My Source"), row(2, "my-source")]);
    let msg = describe_identity_collisions("log source", &found);

    assert!(msg.contains("refusing to deploy"), "{msg}");
    assert!(msg.contains("my_source"), "{msg}");
    assert!(msg.contains("My Source"), "{msg}");
    assert!(msg.contains("my-source"), "{msg}");
}
