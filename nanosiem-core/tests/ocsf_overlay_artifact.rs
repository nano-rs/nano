// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-1476 regression guard: the OCSF overlay artifact the migrator applies
//! when `NANO_SCHEMA_PROFILE=ocsf` must exist and define the base tables that
//! the schema layer (`logs_table_for` / `ingest_table_for`) and the api/jobs
//! boot validation require. Without these, a fresh OCSF deployment cannot boot
//! (api/jobs fail-fast on the missing `ocsf_logs`) — the exact failure this
//! overlay step was added to prevent.
//!
//! This is a static-artifact check (runs in CI without a live ClickHouse). The
//! runtime apply path is exercised by `migrator_bootstrap`-style live tests and
//! was validated end-to-end on a fresh install.

use nanosiem_core::schema::{ingest_table_for, logs_table_for, SchemaId};

/// The OCSF overlay init script, loaded the same way the migrator does at
/// runtime (`<CLICKHOUSE_MIGRATIONS_DIR>/ocsf/init.sql`).
const OCSF_INIT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/ocsf/init.sql"
));

#[test]
fn overlay_creates_the_tables_the_schema_layer_resolves_for_ocsf() {
    // The names the running services will read from / write to under OCSF.
    let read_table = logs_table_for(SchemaId::Ocsf); // ocsf_logs
    let ingest_table = ingest_table_for(SchemaId::Ocsf); // ocsf_logs_raw

    for table in [read_table, ingest_table] {
        let create = format!("CREATE TABLE IF NOT EXISTS nanosiem.{table}");
        assert!(
            OCSF_INIT.contains(&create),
            "clickhouse/ocsf/init.sql is missing `{create}` — a fresh \
             NANO_SCHEMA_PROFILE=ocsf deploy would fail boot validation \
             (the migrator applies this file as the OCSF overlay; NAN-1476)"
        );
    }

    // The raw → stored derivation MV must also be present, or ingested rows
    // never reach `ocsf_logs`.
    assert!(
        OCSF_INIT.contains("CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_logs_raw_mv"),
        "clickhouse/ocsf/init.sql is missing the ocsf_logs_raw_mv derivation view"
    );
}
