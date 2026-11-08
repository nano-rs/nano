// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use std::collections::HashSet;

fn instant(text: &str) -> DateTime<Utc> {
    text.parse().unwrap()
}

#[test]
fn udm_copy_preserves_original_before_delete() {
    let clamped = instant("2026-11-04T00:00:00Z");
    let sql = copy_sql(
        "nanosiem._future_timestamp_repair_set",
        "nanosiem.logs",
        RepairShape::for_schema(SchemaId::Udm).unwrap(),
        Uuid::nil(),
        clamped,
        instant("2026-11-05T00:00:00Z"),
    );

    assert!(sql.starts_with("INSERT INTO nanosiem.logs SELECT * REPLACE("));
    assert!(sql.contains("toString(source.timestamp), source.original_timestamp"));
    assert!(sql.contains(
        "(source.id, fromUnixTimestamp64Micro(toUnixTimestamp64Micro(source.timestamp), 'UTC')) GLOBAL IN"
    ));
    assert!(sql.contains("_future_timestamp_repair_set"));
    assert!(!sql.contains("GLOBAL NOT IN"));
}

#[test]
fn ocsf_copy_leaves_original_inside_event() {
    let sql = copy_sql(
        "nanosiem._future_timestamp_repair_set",
        "nanosiem.ocsf_logs",
        RepairShape::for_schema(SchemaId::Ocsf).unwrap(),
        Uuid::nil(),
        instant("2026-11-04T00:00:00Z"),
        instant("2026-11-05T00:00:00Z"),
    );

    assert!(!sql.contains("original_timestamp"));
    assert!(sql.contains("intDiv(toUnixTimestamp64Milli(source.timestamp), 1000)"));
    assert!(sql.contains("AS timestamp"));
}

#[test]
fn delete_is_synchronous_and_cluster_aware_by_construction() {
    let sql = delete_sql(
        "nanosiem._future_timestamp_repair_set",
        "nanosiem.logs",
        RepairShape::for_schema(SchemaId::Udm).unwrap(),
        Uuid::nil(),
        instant("2026-11-05T00:00:00Z"),
        "",
    );
    assert!(sql.starts_with("ALTER TABLE nanosiem.logs"));
    assert!(sql.contains("DELETE WHERE timestamp >"));
    assert!(
        sql.contains("(id, fromUnixTimestamp64Micro(toUnixTimestamp64Micro(timestamp), 'UTC')) IN")
    );
    assert!(sql.contains("event_id, source_timestamp"));
    assert!(sql.ends_with("SETTINGS mutations_sync = 2"));
}

#[test]
fn datetime64_3_stage_encoding_is_lossless_across_26_8_and_26_10() {
    assert_eq!(
        staged_timestamp("timestamp", 3),
        "fromUnixTimestamp64Micro(toUnixTimestamp64Milli(timestamp), 'UTC')"
    );
    assert!(!staged_timestamp("timestamp", 3).contains("toDateTime64(timestamp, 6"));
}

#[test]
fn ip_repair_buffers_exact_rows_before_restoring_a_lower_version() {
    let materialize = ip_buffer_materialize_sql(
        "nanosiem._future_timestamp_ip_repair_rows",
        "nanosiem._future_timestamp_repair_set",
        "nanosiem.ip_enrichments",
        Uuid::nil(),
        instant("2026-11-05T00:00:00Z"),
    );
    let restore = ip_buffer_restore_sql(
        "nanosiem._future_timestamp_ip_repair_rows",
        "nanosiem.ip_enrichments",
        Uuid::nil(),
    );
    assert!(materialize.starts_with("INSERT INTO nanosiem._future_timestamp_ip_repair_rows"));
    assert!(materialize.contains("reinterpretAsUUID(sipHash128(tuple(source.source_id"));
    assert!(materialize.contains("event_id FROM nanosiem._future_timestamp_repair_set"));
    assert!(restore.starts_with("INSERT INTO nanosiem.ip_enrichments"));
    assert!(restore.contains("fromUnixTimestamp64Milli(intDiv("));
}

#[test]
fn user_registry_repair_preserves_replacing_version_and_repairs_all_three_dates() {
    let sql = epoch_millis_update_sql(
        EpochMillisRepairShape::UserRegistry,
        "nanosiem._future_timestamp_repair_set",
        "nanosiem.user_registry",
        Uuid::nil(),
        instant("2026-11-05T00:00:00Z"),
        "",
    );
    assert!(sql.contains("last_sign_in_at = fromUnixTimestamp64Milli(intDiv("));
    assert!(sql.contains("created_in_directory_at = fromUnixTimestamp64Milli(intDiv("));
    assert!(sql.contains("last_synced_at = fromUnixTimestamp64Milli(intDiv("));
    assert!(!sql.contains("version ="));
}

#[test]
fn partition_key_repairs_copy_before_exact_delete() {
    for shape in [
        EpochMillisRepairShape::CustomEnrichmentResults,
        EpochMillisRepairShape::SyntheticCheckResults,
    ] {
        let copy = epoch_millis_copy_sql(
            shape,
            "nanosiem._future_timestamp_repair_set",
            &format!("nanosiem.{}", shape.table()),
            Uuid::nil(),
            instant("2026-11-05T00:00:00Z"),
        );
        let delete = epoch_millis_delete_sql(
            shape,
            "nanosiem._future_timestamp_repair_set",
            &format!("nanosiem.{}", shape.table()),
            Uuid::nil(),
            instant("2026-11-05T00:00:00Z"),
            "",
        );
        assert!(copy.starts_with("INSERT INTO"));
        assert!(copy.contains("SELECT * REPLACE("));
        assert!(copy.contains("GLOBAL IN"));
        assert!(
            copy.contains("GLOBAL NOT IN"),
            "corrected copy must be restart-idempotent: {copy}"
        );
        assert!(delete.starts_with("ALTER TABLE"));
        assert!(delete.contains("event_id FROM nanosiem._future_timestamp_repair_set"));
        assert!(delete.ends_with("SETTINGS mutations_sync = 2"));
    }
}

#[test]
fn support_mutations_use_the_resolved_cluster_clause() {
    let on_cluster = " ON CLUSTER `nanosiem_cluster`";
    let delete = epoch_millis_delete_sql(
        EpochMillisRepairShape::SyntheticCheckResults,
        "nanosiem._future_timestamp_repair_set",
        "nanosiem.synthetic_check_results",
        Uuid::nil(),
        instant("2026-11-05T00:00:00Z"),
        on_cluster,
    );
    let update = epoch_millis_update_sql(
        EpochMillisRepairShape::UserRegistry,
        "nanosiem._future_timestamp_repair_set",
        "nanosiem.user_registry",
        Uuid::nil(),
        instant("2026-11-05T00:00:00Z"),
        on_cluster,
    );
    assert!(delete.starts_with(
        "ALTER TABLE nanosiem.synthetic_check_results ON CLUSTER `nanosiem_cluster` DELETE"
    ));
    assert!(update
        .starts_with("ALTER TABLE nanosiem.user_registry ON CLUSTER `nanosiem_cluster` UPDATE"));
}

#[test]
fn pending_ip_cleanup_is_scoped_to_one_repair_id() {
    let repair_id = Uuid::from_u128(42);
    let cleanup = ip_buffer_cleanup_sql("nanosiem._future_timestamp_ip_repair_rows", repair_id);
    assert!(cleanup.contains(&format!("repair_id = toUUID('{repair_id}')")));
    assert!(!cleanup.contains("WHERE 1"));
}

#[test]
fn lock_metadata_round_trips_and_cluster_drop_is_explicit() {
    let owner = Uuid::from_u128(7);
    let lease = instant("2026-11-05T06:00:00Z");
    let comment = repair_lock_comment(owner, lease);
    assert_eq!(parse_repair_lock_comment(&comment).unwrap(), (owner, lease));
    assert_eq!(
        drop_lock_sql(
            "nanosiem",
            " ON CLUSTER `nanosiem_cluster`",
            FUTURE_REPAIR_LOCK_TABLE,
        ),
        "DROP TABLE nanosiem._future_timestamp_repair_lock ON CLUSTER `nanosiem_cluster` SYNC"
    );
}

#[test]
fn new_future_row_after_copy_survives_exact_delete() {
    let original = (Uuid::from_u128(1), 4_070_908_800_000_i64);
    let late = (Uuid::from_u128(2), 4_102_444_800_000_i64);
    let repair_set = HashSet::from([original]);
    let mut future_rows = vec![original];

    // The copy has completed. Ingest races in a new future row before DELETE.
    future_rows.push(late);
    future_rows.retain(|row| !repair_set.contains(row));

    assert_eq!(future_rows, vec![late]);
}

#[test]
fn clustered_repair_synchronizes_the_materialized_set_before_delete() {
    assert_eq!(
        sync_repair_set_sql(
            "nanosiem._future_timestamp_repair_set",
            " ON CLUSTER `nanosiem_cluster`"
        ),
        Some(
            "SYSTEM SYNC REPLICA ON CLUSTER `nanosiem_cluster` nanosiem._future_timestamp_repair_set"
                .to_string()
        )
    );
    assert_eq!(
        sync_repair_set_sql("nanosiem._future_timestamp_repair_set", ""),
        None
    );
}
