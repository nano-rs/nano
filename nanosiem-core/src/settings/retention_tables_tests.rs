// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5346: retention applies to every event table that still holds rows.

use super::*;

#[test]
fn udm_retention_targets_logs_only() {
    assert_eq!(retention_tables_for("logs"), ["logs"]);
}

/// An OCSF install still creates `logs` and keeps its historical rows; the
/// operator's retention applies there too, after the active table.
#[test]
fn ocsf_retention_also_targets_logs() {
    assert_eq!(retention_tables_for("ocsf_logs"), ["ocsf_logs", "logs"]);
}

#[test]
fn ttl_sql_per_table_and_cluster() {
    let tables = retention_tables_for("ocsf_logs");
    let sql: Vec<String> = tables.iter().map(|t| retention_ttl_sql(t, "", 30)).collect();
    assert_eq!(
        sql,
        [
            "ALTER TABLE ocsf_logs MODIFY TTL timestamp + INTERVAL 30 DAY DELETE",
            "ALTER TABLE logs MODIFY TTL timestamp + INTERVAL 30 DAY DELETE",
        ]
    );
    assert_eq!(
        retention_ttl_sql("logs", " ON CLUSTER 'nano'", 7),
        "ALTER TABLE logs ON CLUSTER 'nano' MODIFY TTL timestamp + INTERVAL 7 DAY DELETE"
    );
    // The UDM statement is byte-identical to the pre-NAN-5346 one.
    assert_eq!(
        retention_ttl_sql("logs", "", 90),
        format!("ALTER TABLE {}{} MODIFY TTL timestamp + INTERVAL {} DAY DELETE", "logs", "", 90)
    );
}
