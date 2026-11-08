// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4939 live ClickHouse scenario. Run this same test against 26.8 and
//! 26.10; it seeds the exact bare-epoch-millisecond shape in every affected
//! support-table class, then proves preview, repair, ReplacingMergeTree winner
//! semantics, corrected partition/TTL inputs, and an idempotent rerun.

use nanosiem_core::db::future_timestamp_repair::FutureTimestampRepair;
use nanosiem_core::schema::SchemaId;
use uuid::Uuid;

fn env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("{key} must be set for this live suite"))
}

async fn exec(ch: &clickhouse::Client, sql: &str) {
    ch.query(sql)
        .execute()
        .await
        .unwrap_or_else(|error| panic!("{error}: {sql}"));
}

#[tokio::test]
#[ignore = "requires a lane-owned ClickHouse 26.8 or 26.10 container"]
async fn repairs_all_epoch_millisecond_table_classes_and_reruns_as_noop() {
    let ch = clickhouse::Client::default()
        .with_url(env("NANOSIEM_TEST_CLICKHOUSE_URL"))
        .with_user(env("NANOSIEM_TEST_CLICKHOUSE_USER"))
        .with_password(env("NANOSIEM_TEST_CLICKHOUSE_PASSWORD"))
        .with_validation(false)
        .with_compression(clickhouse::Compression::None)
        .with_option("async_insert", "0")
        .with_option("wait_for_async_insert", "1");
    let database = format!("nan4939_{}", Uuid::new_v4().simple());
    exec(&ch, &format!("CREATE DATABASE {database}")).await;

    for ddl in [
        format!(
            "CREATE TABLE {database}.logs (id UUID, timestamp DateTime64(6, 'UTC'), \
             original_timestamp String DEFAULT '') ENGINE=MergeTree ORDER BY (timestamp, id)"
        ),
        format!(
            "CREATE TABLE {database}.ocsf_logs (timestamp DateTime64(3, 'UTC'), id UUID, \
             source_type LowCardinality(String), event String) ENGINE=MergeTree \
             PARTITION BY toYYYYMMDD(timestamp) ORDER BY (timestamp, id)"
        ),
        format!(
            "CREATE TABLE {database}._future_timestamp_repair_set (repair_id UUID, \
             source_table LowCardinality(String), event_id UUID, \
             source_timestamp DateTime64(6, 'UTC'), created_at DateTime64(6, 'UTC') DEFAULT now64(6)) \
             ENGINE=MergeTree ORDER BY (repair_id, source_table, event_id, source_timestamp)"
        ),
        format!(
            "CREATE TABLE {database}.ip_enrichments (network String, source_id LowCardinality(String), \
             country String DEFAULT '', country_code String DEFAULT '', continent String DEFAULT '', \
             continent_code String DEFAULT '', asn String DEFAULT '', as_name String DEFAULT '', \
             as_domain String DEFAULT '', updated_at DateTime64(3, 'UTC'), deleted UInt8) \
             ENGINE=ReplacingMergeTree(updated_at) ORDER BY (source_id, network) \
             SETTINGS max_bytes_to_merge_at_max_space_in_pool=0"
        ),
        format!(
            "CREATE TABLE {database}._future_timestamp_ip_repair_rows (repair_id UUID, \
             network String, source_id LowCardinality(String), country String DEFAULT '', \
             country_code String DEFAULT '', continent String DEFAULT '', continent_code String DEFAULT '', \
             asn String DEFAULT '', as_name String DEFAULT '', as_domain String DEFAULT '', \
             updated_at DateTime64(3, 'UTC'), deleted UInt8, \
             created_at DateTime64(6, 'UTC') DEFAULT now64(6)) ENGINE=MergeTree \
             ORDER BY (repair_id, source_id, network, updated_at)"
        ),
        format!(
            "CREATE TABLE {database}.custom_enrichment_results (namespace LowCardinality(String), \
             enrichment_id UUID, enrichment_name LowCardinality(String), key_type LowCardinality(String), \
             key_value String, marker String, fetched_at DateTime64(3, 'UTC'), \
             expires_at DateTime64(3, 'UTC'), version UInt32) \
             ENGINE=ReplacingMergeTree(version) PARTITION BY toYYYYMM(fetched_at) \
             ORDER BY (namespace, enrichment_name, key_type, key_value) \
             TTL expires_at + INTERVAL 7 DAY"
        ),
        format!(
            "CREATE TABLE {database}.user_registry (provider_id LowCardinality(String), external_id String, \
             marker String, last_sign_in_at DateTime64(3, 'UTC'), \
             created_in_directory_at DateTime64(3, 'UTC'), account_status LowCardinality(String), \
             last_synced_at DateTime64(3, 'UTC'), version UInt64) \
             ENGINE=ReplacingMergeTree(version) ORDER BY (provider_id, external_id) \
             SETTINGS max_bytes_to_merge_at_max_space_in_pool=0"
        ),
        format!(
            "CREATE TABLE {database}.synthetic_check_results (check_id String, \
             timestamp DateTime64(3, 'UTC'), success UInt8, latency_ms Float64, \
             status_code UInt16, error String) ENGINE=MergeTree \
             PARTITION BY toYYYYMMDD(timestamp) ORDER BY (check_id, timestamp)"
        ),
    ] {
        exec(&ch, &ddl).await;
    }
    let now_ms: i64 = ch
        .query("SELECT toUnixTimestamp64Milli(now64(3))")
        .fetch_one()
        .await
        .unwrap();
    let old_active_ms = now_ms - 2 * 60 * 60 * 1000;
    let tombstone_ms = now_ms - 60 * 60 * 1000;
    let new_active_ms = now_ms - 30 * 60 * 1000;
    let sign_in_ms = now_ms - 10 * 24 * 60 * 60 * 1000;
    let created_ms = now_ms - 100 * 24 * 60 * 60 * 1000;
    let expires_ms = now_ms + 30 * 24 * 60 * 60 * 1000;
    let finding_id = Uuid::new_v4();
    let audit_id = Uuid::new_v4();
    exec(
        &ch,
        &format!(
            "INSERT INTO {database}.ocsf_logs VALUES \
             ({tombstone_ms}, toUUID('{finding_id}'), 'findings', 'finding'), \
             ({tombstone_ms}, toUUID('{audit_id}'), 'audit', 'audit')"
        ),
    )
    .await;

    // IP: one source was re-enabled after the bad tombstone and must become
    // visible; a second source was not re-enabled and must remain deleted.
    for values in [
        format!("('198.51.100.0/24', 'reenabled', 'old-active', fromUnixTimestamp64Milli({old_active_ms}), 0)"),
        format!("('198.51.100.0/24', 'reenabled', 'bad-tombstone', {tombstone_ms}, 1)"),
        format!("('198.51.100.0/24', 'reenabled', 'new-active', fromUnixTimestamp64Milli({new_active_ms}), 0)"),
        format!("('203.0.113.0/24', 'still-deleted', 'old-active', fromUnixTimestamp64Milli({old_active_ms}), 0)"),
        format!("('203.0.113.0/24', 'still-deleted', 'bad-tombstone', {tombstone_ms}, 1)"),
    ] {
        exec(
            &ch,
            &format!(
                "INSERT INTO {database}.ip_enrichments \
                 (network, source_id, as_name, updated_at, deleted) VALUES {values}"
            ),
        )
        .await;
    }
    let before_ip: Vec<(String, u8)> = ch
        .query(&format!(
            "SELECT source_id, deleted FROM {database}.ip_enrichments FINAL ORDER BY source_id"
        ))
        .fetch_all()
        .await
        .unwrap();
    assert_eq!(
        before_ip,
        vec![("reenabled".into(), 1), ("still-deleted".into(), 1)]
    );

    exec(
        &ch,
        &format!(
            "INSERT INTO {database}.custom_enrichment_results VALUES \
             ('default', generateUUIDv4(), 'feed', 'domain', 'bad.example', 'custom', \
              {tombstone_ms}, {expires_ms}, 1)"
        ),
    )
    .await;
    exec(
        &ch,
        &format!(
            "INSERT INTO {database}.user_registry VALUES \
             ('provider', 'user', 'bad-tombstone', \
              {sign_in_ms}, {created_ms}, 'deleted', {tombstone_ms}, 100)"
        ),
    )
    .await;
    exec(
        &ch,
        &format!(
            "INSERT INTO {database}.user_registry VALUES \
             ('provider', 'user', 'new-active', fromUnixTimestamp64Milli({sign_in_ms} + 1000), \
              fromUnixTimestamp64Milli({created_ms} + 1000), 'active', \
              fromUnixTimestamp64Milli({new_active_ms}), 101)"
        ),
    )
    .await;
    exec(
        &ch,
        &format!(
            "INSERT INTO {database}.synthetic_check_results VALUES \
             ('check', {tombstone_ms}, 1, 12.5, 200, '')"
        ),
    )
    .await;

    let repair = FutureTimestampRepair::new(&ch, &database, SchemaId::Udm, 86_400)
        .await
        .unwrap();
    let contender = FutureTimestampRepair::new(&ch, &database, SchemaId::Udm, 86_400)
        .await
        .unwrap();
    let (first_lock, second_lock) = tokio::join!(
        repair.acquire_confirm_lock(),
        contender.acquire_confirm_lock()
    );
    assert_ne!(
        first_lock.is_ok(),
        second_lock.is_ok(),
        "exactly one concurrent confirmed repair must own the global lock"
    );
    match (first_lock, second_lock) {
        (Ok(lock), Err(_)) | (Err(_), Ok(lock)) => lock.release().await.unwrap(),
        _ => unreachable!(),
    }
    assert_eq!(repair.preview().await.unwrap().future_rows, 0);
    let previews = repair.preview_epoch_millis_tables().await.unwrap();
    let counts: Vec<(&str, u64)> = previews
        .iter()
        .map(|preview| (preview.source_table.as_str(), preview.affected_rows))
        .collect();
    assert_eq!(
        counts,
        vec![
            ("ip_enrichments", 2),
            ("custom_enrichment_results", 1),
            ("user_registry", 1),
            ("synthetic_check_results", 1),
        ]
    );
    let confirmed_lock = repair.acquire_confirm_lock().await.unwrap();
    for preview in &previews {
        repair.execute_epoch_millis_table(preview).await.unwrap();
    }

    let after_ip: Vec<(String, String, u8)> = ch
        .query(&format!(
            "SELECT source_id, as_name, deleted FROM {database}.ip_enrichments FINAL ORDER BY source_id"
        ))
        .fetch_all()
        .await
        .unwrap();
    assert_eq!(
        after_ip,
        vec![
            ("reenabled".into(), "new-active".into(), 0),
            ("still-deleted".into(), "bad-tombstone".into(), 1),
        ]
    );

    let custom: (i64, i64, u32) = ch
        .query(&format!(
            "SELECT dateDiff('second', fetched_at, now64(3)), \
             dateDiff('day', now64(3), expires_at), toYYYYMM(fetched_at) \
             FROM {database}.custom_enrichment_results FINAL"
        ))
        .fetch_one()
        .await
        .unwrap();
    assert!((0..=7_200).contains(&custom.0), "fetched age: {custom:?}");
    assert!((29..=30).contains(&custom.1), "expiry: {custom:?}");
    let current_month: u32 = ch
        .query("SELECT toYYYYMM(now())")
        .fetch_one()
        .await
        .unwrap();
    assert_eq!(custom.2, current_month, "partition month: {custom:?}");

    let user: (String, u64, i64, i64, i64) = ch
        .query(&format!(
            "SELECT marker, version, toUnixTimestamp64Milli(last_sign_in_at), \
             toUnixTimestamp64Milli(created_in_directory_at), \
             toUnixTimestamp64Milli(last_synced_at) \
             FROM {database}.user_registry FINAL"
        ))
        .fetch_one()
        .await
        .unwrap();
    assert_eq!(user.0, "new-active");
    assert_eq!(user.1, 101);
    assert!(user.2 < 10_000_000_000_000 && user.3 < 10_000_000_000_000);
    assert!(user.4 < 10_000_000_000_000);
    let repaired_tombstone_count: u64 = ch
        .query(&format!(
            "SELECT count() FROM {database}.user_registry WHERE version = 100 \
             AND toUnixTimestamp64Milli(last_synced_at) < 10000000000000"
        ))
        .fetch_one()
        .await
        .unwrap();
    assert_eq!(repaired_tombstone_count, 1);

    let synthetic: (i64, u32) = ch
        .query(&format!(
            "SELECT dateDiff('second', timestamp, now64(3)), toYYYYMMDD(timestamp) \
             FROM {database}.synthetic_check_results"
        ))
        .fetch_one()
        .await
        .unwrap();
    assert!(
        (0..=7_200).contains(&synthetic.0),
        "synthetic: {synthetic:?}"
    );
    let current_day: u32 = ch
        .query("SELECT toYYYYMMDD(now())")
        .fetch_one()
        .await
        .unwrap();
    assert_eq!(synthetic.1, current_day);

    let ocsf_repair = FutureTimestampRepair::new(&ch, &database, SchemaId::Ocsf, 86_400)
        .await
        .unwrap();
    let ocsf_preview = ocsf_repair.preview().await.unwrap();
    assert_eq!(ocsf_preview.future_rows, 2);
    assert_eq!(ocsf_preview.recoverable_epoch_millis_rows, 2);
    let ocsf_outcome = ocsf_repair.execute(&ocsf_preview).await.unwrap();
    assert_eq!(ocsf_outcome.copied_ids, 2);
    assert_eq!(ocsf_outcome.deleted_rows, 2);
    let ocsf_rows: Vec<(String, i64, u32)> = ch
        .query(&format!(
            "SELECT source_type, toUnixTimestamp64Milli(timestamp), toYYYYMMDD(timestamp) \
             FROM {database}.ocsf_logs ORDER BY source_type"
        ))
        .fetch_all()
        .await
        .unwrap();
    assert_eq!(
        ocsf_rows,
        vec![
            ("audit".into(), tombstone_ms, current_day),
            ("findings".into(), tombstone_ms, current_day),
        ]
    );
    confirmed_lock.release().await.unwrap();

    // Kill-after-insert boundary for a plain MergeTree: the corrected copy and
    // the old run's staging fingerprint committed, but the bad source DELETE
    // did not. A fresh repair id must detect that corrected fingerprint and
    // avoid inserting a second copy before it deletes the bad source.
    let killed_repair_id = Uuid::new_v4();
    let unrelated_repair_id = Uuid::new_v4();
    let crash_ms = tombstone_ms - 1_000;
    exec(
        &ch,
        &format!(
            "INSERT INTO {database}.synthetic_check_results VALUES \
             ('killed-after-copy', {crash_ms}, 1, 42.0, 204, ''), \
             ('killed-after-copy', fromUnixTimestamp64Milli({crash_ms}), 1, 42.0, 204, '')"
        ),
    )
    .await;
    exec(
        &ch,
        &format!(
            "INSERT INTO {database}._future_timestamp_repair_set \
             (repair_id, source_table, event_id, source_timestamp) \
             SELECT toUUID('{killed_repair_id}'), 'synthetic_check_results', \
                    reinterpretAsUUID(sipHash128(tuple( \
                        check_id, intDiv(toUnixTimestamp64Milli(timestamp), 1000), \
                        success, latency_ms, status_code, error))), \
                    fromUnixTimestamp64Micro( \
                        intDiv(toUnixTimestamp64Milli(timestamp), 1000) * 1000, 'UTC') \
             FROM {database}.synthetic_check_results \
             WHERE check_id='killed-after-copy' \
               AND toUnixTimestamp64Milli(timestamp) >= 100000000000000"
        ),
    )
    .await;
    // An unrelated completed id proves manual cleanup is repair-id scoped.
    exec(
        &ch,
        &format!(
            "INSERT INTO {database}._future_timestamp_repair_set \
             (repair_id, source_table, event_id, source_timestamp) VALUES \
             (toUUID('{unrelated_repair_id}'), 'synthetic_check_results', \
              generateUUIDv4(), now64(6))"
        ),
    )
    .await;

    let restart = FutureTimestampRepair::new(&ch, &database, SchemaId::Udm, 86_400)
        .await
        .unwrap();
    let restart_previews = restart.preview_epoch_millis_tables().await.unwrap();
    let synthetic_restart = restart_previews
        .iter()
        .find(|preview| preview.source_table == "synthetic_check_results")
        .unwrap();
    assert_eq!(synthetic_restart.affected_rows, 1);
    let restart_lock = restart.acquire_confirm_lock().await.unwrap();
    restart
        .execute_epoch_millis_table(synthetic_restart)
        .await
        .unwrap();
    restart_lock.release().await.unwrap();
    let corrected_after_restart: u64 = ch
        .query(&format!(
            "SELECT count() FROM {database}.synthetic_check_results \
             WHERE check_id='killed-after-copy' \
               AND toUnixTimestamp64Milli(timestamp)={crash_ms}"
        ))
        .fetch_one()
        .await
        .unwrap();
    assert_eq!(
        corrected_after_restart, 1,
        "restart after committed copy must not duplicate a synthetic result"
    );
    let killed_purge = restart.preview_purge(killed_repair_id).await.unwrap();
    assert_eq!(killed_purge.staged_rows, 1);
    assert_eq!(killed_purge.staged_originals_remaining, 0);
    restart.purge_completed_repair(&killed_purge).await.unwrap();
    let staged_ids_after_purge: Vec<String> = ch
        .query(&format!(
            "SELECT DISTINCT toString(repair_id) \
             FROM {database}._future_timestamp_repair_set ORDER BY repair_id"
        ))
        .fetch_all()
        .await
        .unwrap();
    assert_eq!(
        staged_ids_after_purge,
        vec![unrelated_repair_id.to_string()]
    );
    let unrelated_purge = restart.preview_purge(unrelated_repair_id).await.unwrap();
    restart
        .purge_completed_repair(&unrelated_purge)
        .await
        .unwrap();

    // Crash-resume shape: a confirmed run durably buffered a tombstone and
    // deleted the bad winner, then lost connectivity before restore/cleanup.
    exec(
        &ch,
        &format!(
            "INSERT INTO {database}._future_timestamp_ip_repair_rows \
             (repair_id,network,source_id,as_name,updated_at,deleted) VALUES \
             (generateUUIDv4(),'192.0.2.0/24','pending','resume-me',{tombstone_ms},1)"
        ),
    )
    .await;
    let resume = FutureTimestampRepair::new(&ch, &database, SchemaId::Udm, 86_400)
        .await
        .unwrap();
    let resume_previews = resume.preview_epoch_millis_tables().await.unwrap();
    let ip_resume = resume_previews
        .iter()
        .find(|preview| preview.source_table == "ip_enrichments")
        .unwrap();
    assert_eq!(ip_resume.affected_rows, 0);
    assert_eq!(ip_resume.pending_buffer_rows, 1);
    let resume_lock = resume.acquire_confirm_lock().await.unwrap();
    resume.execute_epoch_millis_table(ip_resume).await.unwrap();
    resume_lock.release().await.unwrap();
    let resumed: u64 = ch
        .query(&format!(
            "SELECT count() FROM {database}.ip_enrichments WHERE source_id='pending' \
             AND toUnixTimestamp64Milli(updated_at)={tombstone_ms} AND deleted=1"
        ))
        .fetch_one()
        .await
        .unwrap();
    assert_eq!(resumed, 1);
    let pending_buffer: u64 = ch
        .query(&format!(
            "SELECT count() FROM {database}._future_timestamp_ip_repair_rows"
        ))
        .fetch_one()
        .await
        .unwrap();
    assert_eq!(pending_buffer, 0);

    let rerun = FutureTimestampRepair::new(&ch, &database, SchemaId::Udm, 86_400)
        .await
        .unwrap();
    assert!(rerun
        .preview_epoch_millis_tables()
        .await
        .unwrap()
        .iter()
        .all(|preview| preview.affected_rows == 0));
    assert_eq!(
        FutureTimestampRepair::new(&ch, &database, SchemaId::Ocsf, 86_400)
            .await
            .unwrap()
            .preview()
            .await
            .unwrap()
            .future_rows,
        0
    );

    // A Distributed wrapper changes read scope to every shard. With no
    // multi-node cluster target discoverable, construction must fail closed
    // before a later mutation could be sent to only this connection's shard.
    exec(
        &ch,
        &format!(
            "CREATE TABLE {database}.synthetic_check_results_distributed \
             AS {database}.synthetic_check_results \
             ENGINE=Distributed('default', '{database}', \
                                'synthetic_check_results', rand())"
        ),
    )
    .await;
    let topology_error = FutureTimestampRepair::new(&ch, &database, SchemaId::Udm, 86_400)
        .await
        .err()
        .expect("a Distributed wrapper without a multi-node mutation target must fail closed");
    assert!(
        format!("{topology_error:#}").contains("no multi-node cluster"),
        "unexpected topology error: {topology_error:#}"
    );
    exec(&ch, &format!("DROP DATABASE {database} SYNC")).await;
}
