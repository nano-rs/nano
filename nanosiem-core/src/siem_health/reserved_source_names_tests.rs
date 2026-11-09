// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5032: SIEM Health flags log sources stored under a platform-owned
//! source type (the upgrade path for tenants that named a source `audit`).

use super::tests::base_zero_metrics_fixture;
use super::*;
use crate::siem_health::collector::classify_reserved_source_names;

#[test]
fn enforced_and_warn_only_route_keys_are_classified() {
    let names = classify_reserved_source_names(
        ["audit", "syslog", "findings", "signal", "nano_custom", "nano_enrich", "audit"]
            .into_iter()
            .map(String::from),
    );
    assert_eq!(names.enforced, vec!["audit".to_string(), "findings".to_string()]);
    assert_eq!(names.warn_only, vec!["nano_custom".to_string(), "signal".to_string()]);
}

#[test]
fn a_tenant_with_no_reserved_names_gets_no_finding() {
    assert!(reserved_source_name_recommendations(&Default::default()).is_empty());
}

#[test]
fn reserved_names_surface_on_the_fresh_short_circuit_too() {
    let mut metrics = base_zero_metrics_fixture();
    metrics.reserved_source_names = classify_reserved_source_names(
        ["audit", "signals"].into_iter().map(String::from),
    );
    let mut analysis = fallback_report(&metrics);
    ensure_reserved_source_name_findings(&mut analysis, &metrics);
    let titles: Vec<&str> = analysis.recommendations.iter().map(|r| r.title.as_str()).collect();
    assert!(titles.iter().any(|t| t.contains("reserved for nano's own records")), "{titles:?}");
    assert!(titles.iter().any(|t| t.contains("reserved for future platform use")), "{titles:?}");
    let high = analysis
        .recommendations
        .iter()
        .find(|r| r.title.contains("nano's own records"))
        .unwrap();
    assert_eq!(high.priority, "high");
    assert!(high.description.contains("audit"));
}
