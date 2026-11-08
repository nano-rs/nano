// SPDX-License-Identifier: AGPL-3.0-or-later

use super::ParserRepositoryService;

#[test]
fn otlp_source_configuration_accepts_the_otlp_import_contract() {
    assert!(ParserRepositoryService::is_dispatch_compatible(
        "otlp", "otlp"
    ));
    assert_eq!(
        ParserRepositoryService::config_type_for_ingestion_method("otlp"),
        "otlp"
    );
}

#[test]
fn otlp_legacy_names_resolve_to_the_shared_otlp_configuration() {
    for alias in ["opentelemetry", "otel"] {
        assert!(
            ParserRepositoryService::is_dispatch_compatible("otlp", alias),
            "OTLP source config rejected ingestion alias {alias}"
        );
        assert!(
            ParserRepositoryService::is_dispatch_compatible(alias, "otlp"),
            "OTLP ingestion rejected source-config alias {alias}"
        );
        assert_eq!(
            ParserRepositoryService::config_type_for_ingestion_method(alias),
            "otlp"
        );
    }
}

#[test]
fn otlp_still_rejects_cross_transport_dispatches() {
    for config_type in ["http", "vector", "kafka", "aws_s3", "splunk_hec"] {
        assert!(
            !ParserRepositoryService::is_dispatch_compatible(config_type, "otlp"),
            "OTLP parser accepted unrelated {config_type} dispatch"
        );
    }
}
