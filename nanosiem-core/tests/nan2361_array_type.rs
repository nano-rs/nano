use nanosiem_core::schema::{FieldType, OcsfProfile, SchemaProfile};
use std::collections::BTreeMap;

fn lake_profile() -> OcsfProfile {
    let mut types = BTreeMap::new();
    types.insert("file.hashes.value".to_string(), FieldType::Array);
    types.insert("enrichments.name".to_string(), FieldType::Array);
    OcsfProfile::try_lake_1_9_with_snapshot_field_types(types).expect("profile")
}

#[test]
fn snapshot_array_type_wins_over_logical_element_type() {
    let profile = lake_profile();
    assert_eq!(profile.field_type("file.hashes.value"), Some(FieldType::Array));
    assert_eq!(profile.field_type("enrichments.name"), Some(FieldType::Array));
}

/// The real check: an equality predicate on an array leaf must compile to
/// membership, not a scalar comparison against the rendered array.
#[test]
fn array_leaf_equality_compiles_to_membership() {
    let profile = lake_profile();
    let query = nanosiem_core::query::parse_query(
        r#"* | where file.hashes.value = "deadbeef""#,
    )
    .expect("parse");
    let now = chrono::Utc::now();
    let range = nanosiem_core::query::TimeRange {
        start: now - chrono::Duration::hours(1),
        end: now,
    };
    let generator = nanosiem_core::query::ClickHouseSqlGenerator::new()
        .with_profile(std::sync::Arc::new(profile));
    let sql = generator.generate(&query, &range).expect("codegen");
    assert!(
        sql.contains("arrayExists"),
        "array leaf must use membership, got:\n{sql}"
    );
    assert!(
        !sql.contains(r#"lower(toString("file.hashes.value")) ="#),
        "scalar comparison against an array silently matches nothing:\n{sql}"
    );
}

/// The rarity slider emits `<= N`. A range against an array leaf must mean "any
/// element satisfies", not a scalar compare against the rendered array -- the
/// same silent-wrong-answer shape equality had.
#[test]
fn range_comparators_on_array_leaves_use_membership() {
    let profile = lake_profile();
    let query = nanosiem_core::query::parse_query(r#"* | where file.hashes.value < "m""#)
        .expect("parse");
    let now = chrono::Utc::now();
    let range = nanosiem_core::query::TimeRange {
        start: now - chrono::Duration::hours(1),
        end: now,
    };
    let sql = nanosiem_core::query::ClickHouseSqlGenerator::new()
        .with_profile(std::sync::Arc::new(profile))
        .generate(&query, &range)
        .expect("codegen");
    assert!(
        sql.contains("arrayExists"),
        "range on an array leaf must use membership:\n{sql}"
    );
    // NULL elements (an enrichment of another kind lacking this field) must fail
    // the predicate rather than poison the row.
    assert!(
        sql.contains("IS NOT NULL"),
        "array range must skip NULL elements:\n{sql}"
    );
}

/// The exact shape the rarity slider produces.
#[test]
fn slider_style_host_count_threshold_compiles_to_membership() {
    use nanosiem_core::schema::{FieldType, OcsfProfile};
    use std::collections::BTreeMap;
    let mut types = BTreeMap::new();
    types.insert("enrichments.data.host_count".to_string(), FieldType::Array);
    let profile = OcsfProfile::try_lake_1_9_with_snapshot_field_types(types).expect("profile");
    let query = nanosiem_core::query::parse_query(
        "* | where enrichments.data.host_count <= 25",
    )
    .expect("parse");
    let now = chrono::Utc::now();
    let range = nanosiem_core::query::TimeRange {
        start: now - chrono::Duration::hours(1),
        end: now,
    };
    let sql = nanosiem_core::query::ClickHouseSqlGenerator::new()
        .with_profile(std::sync::Arc::new(profile))
        .generate(&query, &range)
        .expect("codegen");
    assert!(sql.contains("arrayExists"), "slider filter must use membership:\n{sql}");
    assert!(sql.contains("<= 25"), "threshold must survive:\n{sql}");
}

/// A lake tenant that has NOT deployed prevalence stamping has no
/// `enrichments.data.host_count` column, and must get a clean "unknown field"
/// rather than a query referencing a column its Iceberg schema lacks. This is
/// why those leaves are advertised from the SNAPSHOT rather than statically.
#[test]
fn prevalence_leaves_are_known_only_when_the_snapshot_carries_them() {
    use nanosiem_core::schema::{OcsfProfile, SchemaProfile};
    use std::collections::BTreeMap;
    // A snapshot with IOC leaves but no prevalence leaves -- the exact state of
    // a tenant running IOC enrichment on an older build.
    let mut types = BTreeMap::new();
    types.insert(
        "enrichments.data.confidence".to_string(),
        nanosiem_core::schema::FieldType::Array,
    );
    let profile = OcsfProfile::try_lake_1_9_with_snapshot_field_types(types).expect("profile");
    assert!(
        !profile.is_known_field("enrichments.data.host_count"),
        "a prevalence leaf absent from the tenant snapshot must not be known"
    );
    // The leaf the tenant DOES have is known and queryable.
    assert!(profile.is_known_field("enrichments.data.confidence"));
    assert_eq!(
        profile.field_type("enrichments.data.confidence"),
        Some(nanosiem_core::schema::FieldType::Array),
        "a snapshot-carried leaf keeps its physical array type"
    );
}

/// The worker-served schema must take precedence over any manifest file, and an
/// unchanged field set must not rebuild the profile -- generations rotate far
/// more often than the schema changes.
#[test]
fn installed_worker_schema_wins_and_dedupes_by_digest() {
    use nanosiem_core::schema::{FieldType, install_lake_schema_field_types};
    use std::collections::BTreeMap;
    let mut types = BTreeMap::new();
    types.insert("enrichments.data.host_count".to_string(), FieldType::Array);
    let before = nanosiem_core::schema::lake_profile_build_count();
    assert!(
        install_lake_schema_field_types("digest-a", types.clone()).expect("install"),
        "a new digest installs"
    );
    assert!(
        !install_lake_schema_field_types("digest-a", types.clone()).expect("install"),
        "the same digest must not rebuild the profile"
    );
    assert_eq!(
        nanosiem_core::schema::lake_profile_build_count(),
        before + 1,
        "exactly one build for two installs of the same schema"
    );
}

/// An empty inventory is refused: it would make every field unknown, which is
/// indistinguishable from a working schema rejecting the query in front of it.
#[test]
fn an_empty_worker_inventory_is_refused() {
    use nanosiem_core::schema::install_lake_schema_field_types;
    use std::collections::BTreeMap;
    assert!(install_lake_schema_field_types("digest-empty", BTreeMap::new()).is_err());
}
