// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

#[test]
fn parses_and_deduplicates_refresh_declarations() {
    let sql = "-- nano:refresh-view nanosiem.ip_enrichment_dict_refresh reload=ip_geo_pair\n\
               SELECT 1;\n\
               -- nano:refresh-view nanosiem.ioc_enrichment_dict_refresh reload=nanosiem.ioc_enrichment_dict\n\
               -- nano:refresh-view nanosiem.ip_enrichment_dict_refresh reload=ip_geo_pair\n";
    assert_eq!(
        parse_directives(sql).unwrap(),
        vec![
            MigrationRefreshDirective {
                view: "nanosiem.ioc_enrichment_dict_refresh".into(),
                reload_target: "nanosiem.ioc_enrichment_dict".into(),
            },
            MigrationRefreshDirective {
                view: "nanosiem.ip_enrichment_dict_refresh".into(),
                reload_target: IP_GEO_PAIR_RELOAD.into(),
            },
        ]
    );
}

#[test]
fn rejects_malformed_or_injectable_refresh_declarations() {
    for sql in [
        "-- nano:refresh-view nanosiem.view",
        "-- nano:refresh-view view reload=nanosiem.dict",
        "-- nano:refresh-view nanosiem.view reload=nanosiem.dict;DROP",
        "-- nano:refresh-view nanosiem.view reload=nanosiem.dict extra",
    ] {
        assert!(parse_directives(sql).is_err(), "accepted {sql:?}");
    }
}

#[test]
fn pending_query_reads_only_due_retryable_latest_revisions() {
    let sql = pending_sql("nanosiem._migration_refreshes");

    assert!(sql.contains("FROM nanosiem._migration_refreshes FINAL"));
    assert!(sql.contains("state IN ('pending', 'failed')"));
    assert!(sql.contains("attempts < 10"));
    assert!(sql.contains("next_attempt_at <= now64(6)"));
    assert!(!sql.contains("GROUP BY"));
}

#[test]
fn exponential_retry_is_capped_at_one_hour() {
    assert_eq!(retry_delay_seconds(1), 60);
    assert_eq!(retry_delay_seconds(2), 120);
    assert_eq!(retry_delay_seconds(6), 1_920);
    assert_eq!(retry_delay_seconds(7), 3_600);
    assert_eq!(retry_delay_seconds(10), 3_600);
}

#[test]
fn durable_phase_parser_distinguishes_reload_only_retries() {
    assert_eq!(
        ActivationPhase::parse("refresh").unwrap(),
        ActivationPhase::Refresh
    );
    assert_eq!(
        ActivationPhase::parse("reload").unwrap(),
        ActivationPhase::Reload
    );
    assert!(ActivationPhase::parse("unknown").is_err());
}
