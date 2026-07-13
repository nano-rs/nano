// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unit tests for [`RiskProfile`](super::RiskProfile) (NAN-1798 P2).

use super::*;

#[test]
fn storage_binding_is_derived_risk_grain() {
    let p = RiskProfile::new();
    assert_eq!(p.id(), SchemaId::Risk);
    assert_eq!(p.table_name(), "nanosiem.logs");
    assert_eq!(p.timestamp_expr(), "last_finding_at");
    assert_eq!(p.keyword_search_column(), "entity");
}

#[test]
fn scores_and_widths_are_numeric_entity_is_not() {
    let p = RiskProfile::new();
    for f in [
        "score_24h",
        "score_7d",
        "raw_score_24h",
        "raw_score_7d",
        "findings_24h",
        "findings_7d",
        "distinct_rules_24h",
        "distinct_rules_7d",
        "distinct_tactics_24h",
        "distinct_tactics_7d",
    ] {
        assert!(p.is_numeric_field(f), "{f} must be numeric");
        assert_eq!(p.field_type(f), Some(FieldType::Long), "{f}");
    }
    assert!(!p.is_numeric_field("entity"));
    assert!(!p.is_numeric_field("last_rule_name"));
    assert_eq!(p.field_type("last_finding_at"), Some(FieldType::Timestamp));
}

#[test]
fn every_dataset_column_is_known_and_resolves_direct() {
    let p = RiskProfile::new();
    for &col in crate::query::clickhouse_sql_gen::otel::RISK_COLUMNS {
        assert!(p.is_known_field(col), "{col} must be known");
        assert_eq!(
            p.resolve(col),
            FieldResolution::ExplicitColumn(col.to_string()),
            "{col} must resolve to a direct column"
        );
    }
    // No spill tail: an unknown name stays a bare identifier (fails loudly at
    // CH) rather than an ext/Map access against the derived grain.
    assert!(!p.is_known_field("src_ip"));
    assert_eq!(
        p.resolve("src_ip"),
        FieldResolution::ExplicitColumn("src_ip".to_string())
    );
}

#[test]
fn entity_is_not_ingest_lowercased() {
    // risk_entity is written raw by the finding logger; equality must not
    // assume the ingest-lowercase contract.
    let p = RiskProfile::new();
    assert!(!p.is_lowercased_at_ingest("entity"));
    assert!(!p.is_lowercased_at_ingest("last_rule_name"));
}
