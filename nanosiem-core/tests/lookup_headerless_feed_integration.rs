// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-2878 follow-up: a scheduled indicator feed that opens with `#` comment
//! lines must ingest as a headerless one-column list, on the first run and
//! on every run after it.
//!
//! Drives the same steps as `SchedulerService::execute_job` without the HTTP
//! fetch: resolve the header choice from the first payload, persist it on the
//! job config, then hand each payload to `UploadService`.
mod common;

use nanosiem_core::{
    FileParser, LookupMode, LookupRepository, LookupService, UploadDestination, UploadParserConfig,
    UploadRequest, UploadService,
};
use uuid::Uuid;

#[tokio::test]
#[ignore = "db-backed; runs in pg-integration CI (cargo test -- --ignored)"]
async fn a_commented_indicator_feed_ingests_headerless_on_schedule() {
    let pool = common::migrated_pool().await;
    let table = format!("nan2878_feed_{}", Uuid::new_v4().simple());
    let uploads = UploadService::new(pool.clone());
    let lookups = LookupService::new(LookupRepository::new(pool.clone()));

    let first = b"# Example blocklist\n# updated 2026-11-02\n\n198.51.100.4\n203.0.113.9\n";
    let second = b"# Example blocklist\n# updated 2026-11-03\n192.0.2.10\n";

    // First run: the scheduler resolves the choice once and saves it.
    let mut config = UploadParserConfig::csv();
    config.has_header = Some(FileParser::resolve_has_header(first, &config));
    assert_eq!(config.has_header, Some(false));

    for (run, payload) in [first.as_slice(), second.as_slice()].into_iter().enumerate() {
        let result = uploads
            .upload(UploadRequest {
                filename: format!("scheduled_{run}.data"),
                content: payload.to_vec(),
                destination: UploadDestination::LookupTable {
                    table_name: table.clone(),
                    primary_key: None,
                    mode: LookupMode::Append,
                },
                config: config.clone(),
                idempotency_key: Some(Uuid::new_v4()),
            })
            .await
            .unwrap_or_else(|e| panic!("run {run} must ingest: {e}"));
        assert!(result.records_ingested > 0, "run {run}: {result:?}");
    }

    let stored = lookups.get_table(&table).await.unwrap();
    let columns: Vec<&str> = stored.columns.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(columns, ["ip"], "no comment line may become a column");

    let mut ips: Vec<String> = lookups
        .read_all_rows(&table)
        .await
        .unwrap()
        .into_iter()
        .map(|row| row["ip"].as_str().unwrap().to_string())
        .collect();
    ips.sort();
    assert_eq!(ips, ["192.0.2.10", "198.51.100.4", "203.0.113.9"]);

    lookups.drop_table(&table).await.unwrap();
}
