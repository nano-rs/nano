// SPDX-License-Identifier: AGPL-3.0-or-later

//! Data collector for SIEM health metrics
//!
//! Queries ClickHouse for ingestion/parsing metrics and PostgreSQL for detection metrics.

use chrono::Utc;
use clickhouse::Client as ClickHouseClient;
use sqlx::PgPool;
use tracing::{info, warn};

use super::types::*;
use crate::db::TableNames;

/// Collect all health metrics from ClickHouse and PostgreSQL
pub async fn collect_metrics(
    pool: &PgPool,
    ch_client: &ClickHouseClient,
    is_clustered: bool,
) -> CollectedMetrics {
    let ingestion = collect_ingestion_metrics(ch_client, is_clustered).await;
    let parsing = collect_parsing_metrics(ch_client, is_clustered).await;
    let enrichment = collect_enrichment_metrics(pool, ch_client, is_clustered).await;
    let detection = collect_detection_metrics(pool).await;
    let alerting = collect_alerting_metrics(pool).await;

    CollectedMetrics {
        ingestion,
        parsing,
        enrichment,
        detection,
        alerting,
        collected_at: Utc::now(),
    }
}

/// Collect ingestion health metrics from ClickHouse
async fn collect_ingestion_metrics(
    ch: &ClickHouseClient,
    is_clustered: bool,
) -> IngestionMetrics {
    // Get per-source-type volumes for last 24h and prior 24h
    let logs_table =
        TableNames::new(is_clustered).read(crate::schema::active_logs_table());
    let sql = format!(
        r#"
        SELECT
            source_type,
            countIf(timestamp >= now() - INTERVAL 24 HOUR) AS count_24h,
            countIf(timestamp >= now() - INTERVAL 48 HOUR AND timestamp < now() - INTERVAL 24 HOUR) AS count_prior_24h
        FROM {logs_table}
        WHERE timestamp >= now() - INTERVAL 48 HOUR
          AND source_type != 'audit'
          AND source_type != ''
        GROUP BY source_type
        ORDER BY count_24h DESC
    "#
    );

    let mut source_volumes: Vec<SourceVolumeMetric> = Vec::new();
    let mut total_24h: u64 = 0;
    let mut total_prior_24h: u64 = 0;
    let mut silent_sources: Vec<String> = Vec::new();

    match ch.query(&sql).fetch_all::<(String, u64, u64)>().await {
        Ok(rows) => {
            for (source_type, count_24h, count_prior_24h) in rows {
                total_24h += count_24h;
                total_prior_24h += count_prior_24h;

                let change_pct = if count_prior_24h > 0 {
                    ((count_24h as f64 - count_prior_24h as f64) / count_prior_24h as f64) * 100.0
                } else if count_24h > 0 {
                    100.0 // New source
                } else {
                    0.0
                };

                if count_24h == 0 && count_prior_24h > 0 {
                    silent_sources.push(source_type.clone());
                }

                source_volumes.push(SourceVolumeMetric {
                    source_type,
                    count_24h,
                    count_prior_24h,
                    change_pct,
                });
            }
        }
        Err(e) => {
            warn!("Failed to collect ingestion metrics: {}", e);
        }
    }

    let insert_integrity = collect_insert_integrity(ch, is_clustered).await;

    info!(
        "Collected ingestion metrics: {} source types, {} events (24h), {} silent sources, {} unhealthy logs dicts",
        source_volumes.len(),
        total_24h,
        silent_sources.len(),
        insert_integrity.failed_logs_dictionaries.len()
    );

    IngestionMetrics {
        source_volumes,
        total_events_24h: total_24h,
        total_events_prior_24h: total_prior_24h,
        silent_sources,
        insert_integrity,
    }
}

/// The `system.<table>` source for an insert-integrity probe: wrapped in
/// `clusterAllReplicas('<cluster>', system.<table>)` on a clustered deployment
/// (so every shard's node-local system tables are read), or plain
/// `system.<table>` on single-node — byte-identical to the pre-cluster SQL.
///
/// NAN-1728 (M-3): `system.*` tables are node-local. Reading only the connected
/// node (a) can pair the NAN-1404 inserts-vs-parts correlation across two
/// *different* LB'd nodes → false silent-loss alarms, and (b) leaves a real
/// stall on any *other* shard completely unmonitored.
fn probe_source(cluster: Option<&str>, table: &str) -> String {
    match cluster {
        Some(c) => format!(
            "clusterAllReplicas('{}', system.{})",
            crate::sql_hygiene::escape_sql_string(c),
            table
        ),
        None => format!("system.{table}"),
    }
}

/// Collect insert-path integrity signals (NAN-1405) — the storage-layer tells
/// of the NAN-1404 silent-loss class. Every probe is best-effort: on a
/// pre-NAN-1405 deployment the app user lacks the system-table grants and the
/// probe degrades to its default (`probes_available` stays false), matching
/// the warn-and-continue posture of the other collectors.
///
/// NAN-1728 (M-3): on a clustered deployment (`is_clustered` + `CLICKHOUSE_CLUSTER`
/// set) the `system.query_log` / `part_log` / `errors` / `view_refreshes` /
/// `asynchronous_insert_log` probes read cluster-wide via `clusterAllReplicas`
/// so a stall on ANY node is caught, and the inserts-vs-parts correlation is
/// done per node (`GROUP BY hostName()`) so mismatched LB routing can no longer
/// forge or mask a NAN-1404 alarm. A `system.distribution_queue` probe surfaces
/// stuck async-forward inserts. On single-node every probe emits the exact
/// pre-cluster `system.*` SQL — this whole cluster path is a no-op there.
async fn collect_insert_integrity(
    ch: &ClickHouseClient,
    is_clustered: bool,
) -> InsertIntegrityMetrics {
    let logs_base = crate::schema::active_logs_table();
    let local_table = format!("nanosiem.{logs_base}");
    let mut m = InsertIntegrityMetrics::default();

    // Cluster name for `clusterAllReplicas(...)`, gated on the authoritative
    // pool-detected `is_clustered` AND the deploy's `CLICKHOUSE_CLUSTER` env
    // (the same source `on_cluster_clause` reads). `None` ⇒ single-node ⇒ every
    // probe below emits its original node-local SQL.
    let cluster: Option<String> = if is_clustered {
        std::env::var("CLICKHOUSE_CLUSTER")
            .ok()
            .map(|c| c.trim().to_string())
            .filter(|c| !c.is_empty())
    } else {
        None
    };
    let cluster_ref = cluster.as_deref();

    // 1) ACK-layer vs storage-layer pairing — the exact NAN-1404 correlation:
    // INSERT queries keep "finishing" (Vector ACKed, HTTP 200) while ZERO new
    // parts reach disk because every async-insert flush throws and discards
    // its batch. NOTE: written_rows on the per-query async entries is 0 even
    // when healthy (verified live, 791/795 on a healthy node) — the rows are
    // attributed to the flush, so parts created is the trustworthy signal.
    // Inserts target the local table even in cluster mode, but match the
    // distributed name too in case a writer routes through it.
    let inserts_where = format!(
        "type = 'QueryFinish' AND query_kind = 'Insert' \
         AND event_time >= now() - INTERVAL 1 HOUR \
         AND (has(tables, '{local_table}') OR has(tables, '{local_table}_distributed'))"
    );
    let parts_where = format!(
        "database = 'nanosiem' AND table = '{logs_base}' \
         AND event_type = 'NewPart' \
         AND event_time >= now() - INTERVAL 1 HOUR"
    );
    if let Some(cl) = cluster_ref {
        // NAN-1728 (M-3): correlate per node. Two cluster-wide `count() GROUP BY
        // hostName()` reads give the inserts and new-parts each node produced;
        // pairing them WITHIN a node is the only way to distinguish a genuine
        // NAN-1404 stall (a node ACKing inserts while creating no parts) from the
        // benign case where inserts and parts simply happened on different nodes.
        let insert_sql = format!(
            "SELECT hostName() AS host, count() AS inserts FROM {} WHERE {} GROUP BY host",
            probe_source(Some(cl), "query_log"),
            inserts_where
        );
        let inserts_by_host = match ch.query(&insert_sql).fetch_all::<(String, u64)>().await {
            Ok(rows) => {
                m.probes_available = true;
                Some(rows)
            }
            Err(e) => {
                warn!("Insert-integrity probe: system.query_log unavailable cluster-wide (grant missing? NAN-1405): {}", e);
                None
            }
        };
        let parts_sql = format!(
            "SELECT hostName() AS host, count() AS new_parts FROM {} WHERE {} GROUP BY host",
            probe_source(Some(cl), "part_log"),
            parts_where
        );
        let parts_by_host = match ch.query(&parts_sql).fetch_all::<(String, u64)>().await {
            Ok(rows) => {
                m.probes_available = true;
                m.new_parts_probe_ok = true;
                Some(rows)
            }
            Err(e) => {
                warn!("Insert-integrity probe: system.part_log unavailable cluster-wide (grant missing? NAN-1405/1461): {}", e);
                None
            }
        };
        match (inserts_by_host, parts_by_host) {
            (Some(ins), Some(parts)) => {
                let parts_map: std::collections::HashMap<String, u64> = parts.into_iter().collect();
                let total_inserts: u64 = ins.iter().map(|(_, n)| *n).sum();
                let total_parts: u64 = parts_map.values().sum();
                // A stall on ANY node: it finished inserts but produced no parts.
                // Report that node's figures so the analyzer's `inserts >= 10 &&
                // new_parts == 0` rule fires (it would be masked by a cluster-wide
                // SUM that other healthy nodes' parts inflate).
                let stalled = ins
                    .iter()
                    .find(|(host, n)| *n >= 10 && parts_map.get(host).copied().unwrap_or(0) == 0);
                if let Some((host, n)) = stalled {
                    warn!(
                        "Insert-integrity: node {} finished {} inserts in 1h but created 0 new parts \
                         (per-node NAN-1404 stall — other nodes may be masking it in aggregate)",
                        host, n
                    );
                    m.logs_inserts_1h = *n;
                    m.new_parts_1h = 0;
                } else {
                    m.logs_inserts_1h = total_inserts;
                    m.new_parts_1h = total_parts;
                }
            }
            // One probe's grant is missing: fall back to the cluster-wide totals
            // for whichever succeeded (matches the single-node independent handling).
            (Some(ins), None) => m.logs_inserts_1h = ins.iter().map(|(_, n)| *n).sum(),
            (None, Some(parts)) => m.new_parts_1h = parts.iter().map(|(_, n)| *n).sum(),
            (None, None) => {}
        }
    } else {
        let sql = format!("SELECT count() AS inserts FROM system.query_log WHERE {inserts_where}");
        match ch.query(&sql).fetch_one::<u64>().await {
            Ok(inserts) => {
                m.probes_available = true;
                m.logs_inserts_1h = inserts;
            }
            Err(e) => warn!(
                "Insert-integrity probe: system.query_log unavailable (grant missing? NAN-1405): {}",
                e
            ),
        }
        let sql = format!("SELECT count() AS new_parts FROM system.part_log WHERE {parts_where}");
        match ch.query(&sql).fetch_one::<u64>().await {
            Ok(new_parts) => {
                m.probes_available = true;
                m.new_parts_probe_ok = true;
                m.new_parts_1h = new_parts;
            }
            Err(e) => warn!(
                "Insert-integrity probe: system.part_log unavailable (grant missing? NAN-1405/1461): {}",
                e
            ),
        }
    }

    // 2) Error-counter tells from system.errors. The counters never reset, so
    // gate on last_error_time recency to keep them actionable. NAN-1728 (M-3):
    // sum per-name across all nodes so an error spiking on any one shard surfaces
    // (`system.errors` is per-node); single-node emits the original ungrouped SQL.
    let sql = if let Some(cl) = cluster_ref {
        format!(
            "SELECT name, sum(value) AS value FROM {} \
             WHERE name IN ('MEMORY_LIMIT_EXCEEDED', 'CACHE_DICTIONARY_UPDATE_FAIL') \
               AND last_error_time >= now() - INTERVAL 24 HOUR \
             GROUP BY name",
            probe_source(Some(cl), "errors")
        )
    } else {
        "SELECT name, value FROM system.errors \
               WHERE name IN ('MEMORY_LIMIT_EXCEEDED', 'CACHE_DICTIONARY_UPDATE_FAIL') \
                 AND last_error_time >= now() - INTERVAL 24 HOUR"
            .to_string()
    };
    match ch.query(&sql).fetch_all::<(String, u64)>().await {
        Ok(rows) => {
            m.probes_available = true;
            for (name, value) in rows {
                match name.as_str() {
                    "MEMORY_LIMIT_EXCEEDED" => m.memory_limit_errors = value,
                    "CACHE_DICTIONARY_UPDATE_FAIL" => m.cache_dictionary_update_fails = value,
                    _ => {}
                }
            }
        }
        Err(e) => warn!(
            "Insert-integrity probe: system.errors unavailable (grant missing? NAN-1405): {}",
            e
        ),
    }

    // 3) FAILED dictionaries referenced by the logs table's MATERIALIZED
    // columns. Discovered from the live DDL (not a hardcoded list) so the set
    // tracks schema/profile changes by construction. dictGetOrDefault THROWS
    // when its dictionary is FAILED, so any hit here means inserts are being
    // rejected at flush time right now.
    let referenced = match ch
        .query(&format!(
            "SELECT create_table_query FROM system.tables \
             WHERE database = 'nanosiem' AND name = '{logs_base}'"
        ))
        .fetch_all::<String>()
        .await
    {
        Ok(rows) => rows
            .first()
            .map(|ddl| extract_dict_references(ddl))
            .unwrap_or_default(),
        Err(e) => {
            warn!("Insert-integrity probe: logs DDL unavailable: {}", e);
            Vec::new()
        }
    };
    if !referenced.is_empty() {
        let in_list = referenced
            .iter()
            .map(|n| format!("'{}'", crate::sql_hygiene::escape_sql_string(n)))
            .collect::<Vec<_>>()
            .join(", ");
        // Fetch ALL referenced dicts (not just FAILED) and filter in Rust:
        // system.dictionaries rows are filtered by SHOW DICTIONARIES visibility,
        // so a missing grant returns ZERO rows without an error — a FAILED-only
        // query can't tell "all healthy" from "blind" (NAN-1437). The DDL just
        // told us these dicts exist; seeing none of them means the grant is
        // missing and this probe must not claim it ran.
        let sql = format!(
            // toString(status): CH 26.4 made system.dictionaries.status an
            // Enum8('NOT_LOADED'=0,'LOADED'=1,'FAILED'=2,…) — deserializing it
            // directly into a String fails (NAN-1629). Cast so the client gets
            // a String and dict_is_unhealthy's status prefix check still matches.
            "SELECT concat(database, '.', name), toString(status), substring(last_exception, 1, 300) \
             FROM system.dictionaries \
             WHERE concat(database, '.', name) IN ({in_list})"
        );
        match ch.query(&sql).fetch_all::<(String, String, String)>().await {
            Ok(rows) if rows.is_empty() => warn!(
                "Insert-integrity probe: logs DDL references {} dictionaries but \
                 system.dictionaries shows none — GRANT SHOW DICTIONARIES ON *.* \
                 missing? (NAN-1437); unhealthy-dict detection is blind",
                referenced.len()
            ),
            Ok(rows) => {
                m.probes_available = true;
                // Flag FAILED status AND LOADED/NOT_LOADED-with-exception: a
                // degraded CACHE dict (the prevalence dicts) reports LOADED while
                // throwing at flush, so a status-only filter misses the halt
                // (NAN-1667, gap G2).
                m.failed_logs_dictionaries = rows
                    .into_iter()
                    .filter(|(_, status, last_exception)| {
                        dict_is_unhealthy(status, last_exception)
                    })
                    .map(|(name, _, last_exception)| FailedDictionary {
                        name,
                        last_exception,
                    })
                    .collect();
            }
            Err(e) => warn!(
                "Insert-integrity probe: system.dictionaries unavailable (grant missing? NAN-1405): {}",
                e
            ),
        }
    }

    // 4) Failing / disabled / overdue dictionary-staging refreshes (NAN-1407;
    // cadence-widened in NAN-1482). The *_dict_refresh refreshable MVs
    // repopulate the *_dict_staging tables the enrichment dicts load from; a
    // broken refresh keeps serving the last good snapshot (rows still land —
    // that's the design), but the staleness must surface somewhere. Cadence now
    // varies per view (ip_enrichment 6h, the other four 1h — NAN-1482), so the
    // old fixed "last success > 1h" threshold would false-flag the slow views
    // EVERY cycle. Key off the SCHEDULE instead: flag exception != '' (refresher
    // failing, retrying), status = 'Disabled' (refresher stopped), or
    // next_refresh_time more than 1h in the past (a scheduled refresh came due
    // and never ran — wedged). A healthy view's next_refresh_time sits in the
    // FUTURE at any cadence, so this is cadence-independent and never flaps on
    // the 6h ip_enrichment refresh. A view that has NEVER succeeded carries a
    // non-empty exception once its first refresh fails (covered); the brief
    // window right after CREATE (future next_refresh, empty exception) is not
    // flagged. The reported `age` is last-success staleness, for display. 26.4
    // note: system.view_refreshes has NO last_refresh_result column —
    // exception / status / next_refresh_time / last_success_time are the
    // signal columns.
    // NAN-1728 (M-3): the refreshable *_dict_refresh MVs are per-node, so a
    // refresh wedged on one shard is invisible from another. Read cluster-wide
    // and label each hit with its node (`hostName()/view`) so any node's stall
    // surfaces without collapsing distinct nodes into one row. Single-node emits
    // the original ungrouped, unlabeled SQL.
    let sql = if let Some(cl) = cluster_ref {
        format!(
            "SELECT concat(hostName(), '/', view) AS view, substring(exception, 1, 300) AS exception, \
                      toUInt64(if(last_success_time IS NULL, 0, \
                                  dateDiff('second', last_success_time, now()))) AS age \
               FROM {} \
               WHERE database = 'nanosiem' AND view LIKE '%\\_dict\\_refresh' \
                 AND (exception != '' OR status = 'Disabled' \
                      OR next_refresh_time < now() - INTERVAL 1 HOUR)",
            probe_source(Some(cl), "view_refreshes")
        )
    } else {
        "SELECT view, substring(exception, 1, 300) AS exception, \
                      toUInt64(if(last_success_time IS NULL, 0, \
                                  dateDiff('second', last_success_time, now()))) AS age \
               FROM system.view_refreshes \
               WHERE database = 'nanosiem' AND view LIKE '%\\_dict\\_refresh' \
                 AND (exception != '' OR status = 'Disabled' \
                      OR next_refresh_time < now() - INTERVAL 1 HOUR)"
            .to_string()
    };
    match ch.query(&sql).fetch_all::<(String, String, u64)>().await {
        Ok(rows) => {
            m.probes_available = true;
            m.stale_dict_refreshes = rows
                .into_iter()
                .map(|(view, exception, last_success_age_secs)| StaleDictRefresh {
                    view,
                    exception,
                    last_success_age_secs,
                })
                .collect();
        }
        Err(e) => warn!(
            "Insert-integrity probe: system.view_refreshes unavailable (grant missing? NAN-1407): {}",
            e
        ),
    }

    // 5) Flush failures from asynchronous_insert_log — only populated once the
    // NAN-1405 server config ships (the table does not exist before that, and
    // None distinguishes "log not enabled" from "no failures").
    // NAN-1728 (M-3): the countIf/anyLastIf aggregates run over the union of
    // every node's rows when `probe_source` wraps the table in
    // `clusterAllReplicas`, so a flush failure on any shard is counted; on
    // single-node the source is plain `system.asynchronous_insert_log`.
    let sql = format!(
        "SELECT countIf(status != 'Ok') AS failures, \
                anyLastIf(substring(exception, 1, 300), status != 'Ok') AS last_error \
         FROM {} \
         WHERE event_time >= now() - INTERVAL 1 HOUR \
           AND database = 'nanosiem' \
           AND table IN ('{logs_base}', '{logs_base}_distributed')",
        probe_source(cluster_ref, "asynchronous_insert_log")
    );
    match ch.query(&sql).fetch_one::<(u64, String)>().await {
        Ok((failures, last_error)) => {
            m.probes_available = true;
            m.async_insert_failures_1h = Some(failures);
            if !last_error.is_empty() {
                m.last_async_insert_error = Some(last_error);
            }
        }
        Err(e) => {
            // Expected on deployments whose server config predates NAN-1405.
            info!(
                "Insert-integrity probe: asynchronous_insert_log unavailable (not enabled yet?): {}",
                e
            );
        }
    }

    // 6) NAN-1728 (H7 tail): stuck async-forward inserts. When the ingest profile
    // uses insert_distributed_sync=0, a row acked by the receiving node sits in
    // its `.bin` distribution send queue until forwarded to the target shard — a
    // wedged or erroring queue means acked rows are NOT yet durable on any shard,
    // the exact hazard H7 flags for the audit path. `system.distribution_queue`
    // is per-node and only populated for Distributed tables, so this probe runs
    // cluster-wide and ONLY when clustered — a pure no-op on single-node.
    if let Some(cl) = cluster_ref {
        let sql = format!(
            "SELECT hostName() AS host, database, table, data_files, error_count, \
                    substring(last_exception, 1, 300) AS last_exception \
             FROM {} \
             WHERE database = 'nanosiem' AND (error_count > 0 OR data_files > 0)",
            probe_source(Some(cl), "distribution_queue")
        );
        match ch
            .query(&sql)
            .fetch_all::<(String, String, String, u64, u64, String)>()
            .await
        {
            Ok(rows) => {
                m.probes_available = true;
                for (host, db, table, data_files, error_count, last_exception) in rows {
                    if error_count > 0 {
                        warn!(
                            "Insert-integrity: distribution queue erroring on {} for {}.{} \
                             ({} pending .bin files, {} errors): {} — acked rows may not be \
                             durable on the target shard (NAN-1728 H7)",
                            host, db, table, data_files, error_count, last_exception
                        );
                    } else {
                        info!(
                            "Insert-integrity: distribution queue backlog on {} for {}.{} \
                             ({} pending .bin files, forwarding not yet complete)",
                            host, db, table, data_files
                        );
                    }
                }
            }
            Err(e) => info!(
                "Insert-integrity probe: system.distribution_queue unavailable \
                 (grant missing or no distributed tables?): {}",
                e
            ),
        }
    }

    m
}

/// Extract fully qualified dictionary names referenced by `dictGet*` calls in
/// a CREATE TABLE statement (the logs table's MATERIALIZED enrichment columns).
fn extract_dict_references(ddl: &str) -> Vec<String> {
    // dictGetOrDefault('nanosiem.ip_enrichment_dict', ...) — capture the first
    // quoted argument of any dictGet-family call.
    let re = regex::Regex::new(r"dictGet\w*\(\s*'([^']+)'").expect("static regex compiles");
    let mut names: Vec<String> = re.captures_iter(ddl).map(|c| c[1].to_string()).collect();
    names.sort();
    names.dedup();
    names
}

/// Whether a referenced dictionary is currently halting inserts.
///
/// `dictGetOrDefault` on a logs MATERIALIZED column THROWS at flush both when the
/// dictionary status is `FAILED*` (FLAT/HASHED load failure) AND when a
/// CACHE-layout dictionary's source is erroring — but a broken CACHE dict does
/// NOT report `FAILED`. Reproduced on CH 26.4 (COMPLEX_KEY_CACHE, missing source
/// table): the first failing lookup flips status to **`LOADED`** while populating
/// `last_exception` (Code 510 CACHE_DICTIONARY_UPDATE_FAIL), and every lookup
/// throws — the same total ingestion halt as a FAILED dict, invisible to a
/// status-only filter. `last_exception` is a CURRENT signal: it CLEARS on the
/// next successful update (verified), so keying off it never false-flags a
/// recovered dict. A benign never-referenced lazy dict sits at `NOT_LOADED` with
/// an EMPTY exception and is correctly not flagged.
///
/// Why the plain `last_exception != ''` clause is false-positive-safe across ALL
/// layouts, not just cache (verified on CH 26.4): a HASHED/Trie/FLAT dict (the
/// enrichment dicts) that fails a BACKGROUND reload keeps serving its last good
/// snapshot, stays `LOADED`, and leaves `last_exception` EMPTY — `dictGet` never
/// throws, so it never halts inserts and is correctly not flagged. Those dicts
/// only carry a non-empty `last_exception` when their INITIAL load fails, which
/// also flips status to `FAILED` (throwing → a real halt). So a non-empty
/// exception always means "throwing right now", regardless of layout.
/// (NAN-1667, audit gap G2.)
fn dict_is_unhealthy(status: &str, last_exception: &str) -> bool {
    // starts_with also catches FAILED_AND_RELOADING.
    status.starts_with("FAILED") || !last_exception.is_empty()
}

/// Collect parsing health metrics from ClickHouse
async fn collect_parsing_metrics(
    ch: &ClickHouseClient,
    is_clustered: bool,
) -> ParsingMetrics {
    // Field coverage: percentage of events where key fields are populated.
    // Resolve the active profile once so the table name AND the column set used
    // by the coverage / ext-usage builders agree (UDM columns on `logs`, OCSF
    // promoted columns on `ocsf_logs`). NAN-1259.
    let ocsf = crate::schema::active_profile_from_env()
        .map(|p| p.id() == crate::schema::SchemaId::Ocsf)
        .unwrap_or(false);
    let logs_table =
        TableNames::new(is_clustered).read(crate::schema::active_logs_table());
    let coverage_sql = build_field_coverage_sql(&logs_table, ocsf);

    let mut field_coverage: Vec<FieldCoverageMetric> = Vec::new();
    match ch
        .query(&coverage_sql)
        .fetch_all::<(String, u64, f64, f64, f64, f64)>()
        .await
    {
        Ok(rows) => {
            for (source_type, total_events, src_ip_pct, user_pct, event_type_pct, message_pct) in
                rows
            {
                field_coverage.push(FieldCoverageMetric {
                    source_type,
                    total_events,
                    src_ip_filled_pct: src_ip_pct,
                    user_filled_pct: user_pct,
                    event_type_filled_pct: event_type_pct,
                    message_filled_pct: message_pct,
                });
            }
        }
        Err(e) => {
            warn!("Failed to collect field coverage metrics: {}", e);
        }
    }

    let ext_sql = build_ext_usage_sql(&logs_table, ocsf);

    let mut high_ext_sources: Vec<ExtUsageMetric> = Vec::new();
    match ch.query(&ext_sql).fetch_all::<(String, u64, f64)>().await {
        Ok(rows) => {
            for (source_type, total_events, ext_pct) in rows {
                high_ext_sources.push(ExtUsageMetric {
                    source_type,
                    total_events,
                    ext_usage_pct: ext_pct,
                });
            }
        }
        Err(e) => {
            warn!("Failed to collect ext usage metrics: {}", e);
        }
    }

    // NAN-1643: ingest-lowercase invariant tripwire. UDM-only —
    // `LOWERCASE_NORMALIZED_FIELDS` names physical `logs` columns; the OCSF
    // table carries its own lowercased promoted columns, so skip rather than
    // error on columns that don't exist there (same posture as the
    // identity-enrichment probes, NAN-1241).
    let lowercase_invariant_violations = if ocsf {
        vec![]
    } else {
        collect_lowercase_invariant_violations(ch, &logs_table).await
    };

    info!(
        "Collected parsing metrics: {} source types with coverage, {} with high ext usage, {} lowercase-invariant violations",
        field_coverage.len(),
        high_ext_sources.len(),
        lowercase_invariant_violations.len()
    );

    ParsingMetrics {
        field_coverage,
        high_ext_sources,
        lowercase_invariant_violations,
    }
}

/// NAN-1643: watch production data for ingest-lowercase invariant drift.
///
/// The query generator compares `LOWERCASE_NORMALIZED_FIELDS` columns RAW
/// (`src_ip = '<lowered>'`, no lower() wrapper) so their raw-column bloom/PK
/// indexes prune. That is only row-correct while ingest keeps those columns
/// all-lowercase (Vector downcases them; probed 0/1.75B violations on
/// Saturn). Nothing else watches the DATA for drift — a new ingest lane,
/// backfill, or parser regression writing mixed-case would silently diverge
/// query results. Best-effort like the other collectors: on error, warn and
/// return empty (absence never alarms).
async fn collect_lowercase_invariant_violations(
    ch: &ClickHouseClient,
    logs_table: &str,
) -> Vec<LowercaseInvariantViolation> {
    let sql = build_lowercase_invariant_sql(logs_table);
    match ch.query(&sql).fetch_all::<(String, u64)>().await {
        Ok(rows) => rows
            .into_iter()
            .map(|(column, violation_count)| LowercaseInvariantViolation {
                column,
                violation_count,
            })
            .collect(),
        Err(e) => {
            warn!("Failed to collect lowercase-invariant violations: {}", e);
            vec![]
        }
    }
}

/// The columns the invariant probe covers: every `LOWERCASE_NORMALIZED_FIELDS`
/// entry that is a physical `logs` column, which drops (a) alias SPELLINGS the
/// router doesn't know as columns (`sourcetype` — not in `EXPLICIT_COLUMNS`)
/// and (b) DDL ALIAS columns (`event_type` is `ALIAS action` in the logs
/// schema — its leg would double-count `action`'s violations under a second
/// name; sourced from the UDM profile's `default_view_renames`, the single
/// Rust-side record of that alias pair). Derived, not hand-copied, so a
/// column added to the raw-compare set is probed by construction.
fn lowercase_invariant_columns() -> Vec<&'static str> {
    use crate::query::clickhouse_sql_gen::{EXPLICIT_COLUMNS, LOWERCASE_NORMALIZED_FIELDS};
    use crate::schema::SchemaProfile;
    let ddl_aliases = crate::schema::UdmProfile.default_view_renames();
    LOWERCASE_NORMALIZED_FIELDS
        .iter()
        .copied()
        .filter(|c| EXPLICIT_COLUMNS.contains(c))
        .filter(|c| !ddl_aliases.iter().any(|(_, alias)| alias == c))
        .collect()
}

/// Build the invariant-probe SQL: ONE bounded scan (1h window, no GROUP BY)
/// carrying a `countIf(col != lower(col))` leg per probed column — never a
/// query per column. The aggregate row is pivoted to `(column, violations)`
/// rows via ARRAY JOIN so the client-side row type stays fixed while the
/// column set evolves; `WHERE t.2 > 0` keeps the healthy case at zero rows.
/// The window is deliberately recent: pre-invariant history (mixed-case rows
/// ingested before the Vector downcase lanes) must not flag forever — the
/// tripwire is for ACTIVE drift. Validated on local CH (26.4): zero rows on
/// invariant-clean data, and the legs count real mixed-case when present.
fn build_lowercase_invariant_sql(logs_table: &str) -> String {
    let legs = lowercase_invariant_columns()
        .iter()
        .map(|c| format!("('{c}', countIf({c} != lower({c})))"))
        .collect::<Vec<_>>()
        .join(",\n                ");
    format!(
        r#"
        SELECT t.1 AS column, t.2 AS violations
        FROM (
            SELECT [
                {legs}
            ] AS pairs
            FROM {logs_table}
            WHERE timestamp > now() - INTERVAL 1 HOUR
        )
        ARRAY JOIN pairs AS t
        WHERE t.2 > 0
    "#
    )
}

/// Collect enrichment health metrics from ClickHouse.
///
/// Computes fleet-wide fill rates for GeoIP / ASN / IOC / user-identity
/// columns over the last 24h, plus a per-source coverage breakdown for the
/// top sources by event volume.
async fn collect_enrichment_metrics(
    pool: &PgPool,
    ch: &ClickHouseClient,
    is_clustered: bool,
) -> EnrichmentMetrics {
    // Installed marketplace/custom enrichment providers. Built into `empty`
    // (cloned into the live rollup below) so the list is attached on every
    // path, including the zero-events short-circuit.
    let empty = EnrichmentMetrics {
        total_events_24h: 0,
        geoip_fill_pct: 0.0,
        asn_fill_pct: 0.0,
        ioc_hit_pct: 0.0,
        identity_fill_pct: 0.0,
        identity_fill_prior_pct: 0.0,
        per_source_coverage: vec![],
        providers: collect_enrichment_providers(pool).await,
    };

    let logs_table =
        TableNames::new(is_clustered).read(crate::schema::active_logs_table());

    // Geo/ASN fill is meaningful only over *geo-eligible* rows — those with a
    // public, locatable IP on either end. The previous metric counted
    // `enriched_src_country` over ALL rows, which (a) ignored destination
    // enrichment entirely and (b) buried real coverage under host-based and
    // private-IP traffic that can never be geo-located. A proxy whose src_ip
    // is all 10.x but whose dest_ip is fully enriched scored 0% — see NAN-1178.
    // NAN-1241: under OCSF, geo/ASN enrichment lands in the OCSF-native objects
    // (src_endpoint.location.country / *.autonomous_system.number); ioc + identity
    // have no promoted OCSF column yet, so they report 0 there rather than erroring
    // on the UDM-only columns. UDM path byte-identical.
    let ocsf = crate::schema::active_profile_from_env()
        .map(|p| p.id() == crate::schema::SchemaId::Ocsf)
        .unwrap_or(false);
    let (src_pub, dest_pub) = if ocsf {
        (
            public_ipv4_expr("\"src_endpoint.ip\""),
            public_ipv4_expr("\"dst_endpoint.ip\""),
        )
    } else {
        (public_ipv4_expr("src_ip"), public_ipv4_expr("dest_ip"))
    };
    let geo_eligible = format!("({src_pub} OR {dest_pub})");
    let geoip_match = if ocsf {
        "\"src_endpoint.location.country\" != '' OR \"dst_endpoint.location.country\" != ''"
    } else {
        "enriched_src_country != '' OR enriched_dest_country != ''"
    };
    let asn_match = if ocsf {
        "\"src_endpoint.autonomous_system.number\" != 0 OR \"dst_endpoint.autonomous_system.number\" != 0"
    } else {
        "enriched_src_asn != '' OR enriched_dest_asn != ''"
    };
    let ioc_pct_expr = if ocsf {
        "0.0"
    } else {
        "countIf(ioc_confidence > 0) * 100.0 / count()"
    };
    let identity_pct_expr = if ocsf {
        "0.0"
    } else {
        "countIf(user_identity_department != '') * 100.0 / count()"
    };

    // Fleet-wide rollup
    let rollup_sql = format!(
        r#"
        SELECT
            count() AS total_events,
            ifNull(countIf({geo_eligible} AND ({geoip_match})) * 100.0
                   / nullIf(countIf({geo_eligible}), 0), 0) AS geoip_pct,
            ifNull(countIf({geo_eligible} AND ({asn_match})) * 100.0
                   / nullIf(countIf({geo_eligible}), 0), 0) AS asn_pct,
            {ioc_pct_expr} AS ioc_pct,
            {identity_pct_expr} AS identity_pct
        FROM {logs_table}
        WHERE timestamp >= now() - INTERVAL 24 HOUR
          AND source_type != 'audit'
          AND source_type != ''
        "#
    );

    let mut rollup = empty.clone();
    match ch
        .query(&rollup_sql)
        .fetch_one::<(u64, f64, f64, f64, f64)>()
        .await
    {
        Ok((total, geoip, asn, ioc, identity)) => {
            rollup.total_events_24h = total;
            // Guard against NaN: ClickHouse `countIf * 100.0 / count()` returns
            // NaN when no rows match. Short-circuit to zeros so the API never
            // emits NaN, which doesn't survive JSON serialization cleanly.
            if total == 0 {
                return empty;
            }
            rollup.geoip_fill_pct = geoip;
            rollup.asn_fill_pct = asn;
            rollup.ioc_hit_pct = ioc;
            rollup.identity_fill_pct = identity;
        }
        Err(e) => {
            warn!("Failed to collect enrichment rollup: {}", e);
            return empty;
        }
    }

    // Per-source coverage (top 20 by volume, min 100 events to avoid noise).
    // GeoIP coverage is over geo-eligible rows for the same reason as the
    // rollup; a host-based source with no public IPs shows 0 eligible and
    // therefore 0% (it is genuinely N/A for geo, not "broken").
    let per_source_sql = format!(
        r#"
        SELECT
            source_type,
            count() AS total_events,
            ifNull(countIf({geo_eligible} AND ({geoip_match})) * 100.0
                   / nullIf(countIf({geo_eligible}), 0), 0) AS geoip_pct,
            {ioc_pct_expr} AS ioc_pct,
            {identity_pct_expr} AS identity_pct
        FROM {logs_table}
        WHERE timestamp >= now() - INTERVAL 24 HOUR
          AND source_type != 'audit'
          AND source_type != ''
        GROUP BY source_type
        HAVING total_events >= 100
        ORDER BY total_events DESC
        LIMIT 20
        "#
    );

    let mut per_source: Vec<EnrichmentCoverageMetric> = Vec::new();
    match ch
        .query(&per_source_sql)
        .fetch_all::<(String, u64, f64, f64, f64)>()
        .await
    {
        Ok(rows) => {
            for (source_type, total_events, geoip_pct, ioc_pct, identity_pct) in rows {
                per_source.push(EnrichmentCoverageMetric {
                    source_type,
                    total_events,
                    geoip_pct,
                    ioc_pct,
                    identity_pct,
                });
            }
        }
        Err(e) => {
            warn!("Failed to collect per-source enrichment coverage: {}", e);
        }
    }
    rollup.per_source_coverage = per_source;

    // Prior-24h identity fill (24-48h ago). A consumer compares this against
    // the current window to tell "identity was never configured" (both 0 → not
    // a finding) from "identity enrichment stopped" (prior > 0, now 0 → a real
    // regression). NAN-1178.
    // NAN-1241: identity enrichment has no promoted OCSF column, so the prior
    // window is 0 under OCSF (matches the current-window identity_pct above) —
    // skip the UDM-only query rather than error on it.
    if !ocsf {
        let identity_prior_sql = format!(
            r#"
        SELECT ifNull(countIf(user_identity_department != '') * 100.0 / nullIf(count(), 0), 0)
        FROM {logs_table}
        WHERE timestamp >= now() - INTERVAL 48 HOUR
          AND timestamp < now() - INTERVAL 24 HOUR
          AND source_type != 'audit'
          AND source_type != ''
        "#
        );
        match ch.query(&identity_prior_sql).fetch_one::<f64>().await {
            Ok(prior) => rollup.identity_fill_prior_pct = prior,
            Err(e) => warn!("Failed to collect prior-window identity fill: {}", e),
        }
    }

    info!(
        "Collected enrichment metrics: {} events, geoip={:.1}%, ioc={:.1}%, identity={:.1}%",
        rollup.total_events_24h,
        rollup.geoip_fill_pct,
        rollup.ioc_hit_pct,
        rollup.identity_fill_pct
    );

    rollup
}

/// Collect installed marketplace/custom enrichment providers and their last
/// run status. Gives the analyzer ground truth for whether a low coverage
/// number is "not configured" (no provider) or "configured but failing"
/// (provider enabled, last run errored). NAN-1178.
///
/// `custom_enrichments` is an enterprise-managed table; on deployments without
/// it the query errors and we return an empty list (the analyzer then treats
/// optional enrichments as simply not configured).
async fn collect_enrichment_providers(pool: &PgPool) -> Vec<EnrichmentProviderStatus> {
    match sqlx::query_as::<_, (String, String, bool, Option<String>)>(
        "SELECT name, enrichment_type, enabled, last_run_status \
         FROM custom_enrichments \
         ORDER BY enrichment_type, name",
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows
            .into_iter()
            .map(
                |(name, enrichment_type, enabled, last_run_status)| EnrichmentProviderStatus {
                    name,
                    enrichment_type,
                    enabled,
                    last_run_status,
                },
            )
            .collect(),
        Err(e) => {
            // Not an error worth alarming on — absent table or open-core build.
            tracing::debug!("No enrichment providers collected: {}", e);
            vec![]
        }
    }
}

/// Collect detection health metrics from PostgreSQL
async fn collect_detection_metrics(pool: &PgPool) -> DetectionMetrics {
    // Total enabled rules
    let total_enabled: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM detection_rules WHERE mode != 'paused'")
            .fetch_one(pool)
            .await
            .unwrap_or(0);

    // Total detection matches today. Distinguishes a detections-only
    // deployment that is actively firing (Live-mode rules counting matches)
    // from one where nothing is matching — so the alerting scorer doesn't
    // mistake "no alerts, but detections firing" for an outage (NAN-1178).
    let total_matches_24h: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(match_count), 0)::bigint \
         FROM detection_daily_stats WHERE date = CURRENT_DATE",
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    // Rules by mode
    let rules_by_mode: Vec<RulesByMode> = match sqlx::query_as::<_, (String, i64)>(
        "SELECT mode, COUNT(*) FROM detection_rules WHERE mode != 'paused' GROUP BY mode",
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows
            .into_iter()
            .map(|(mode, count)| RulesByMode { mode, count })
            .collect(),
        Err(e) => {
            warn!("Failed to collect rules by mode: {}", e);
            vec![]
        }
    };

    // Stale rules: enabled rules that haven't matched in 30+ days (or never)
    let stale_rules: Vec<StaleRule> =
        match sqlx::query_as::<_, (String, Option<chrono::DateTime<Utc>>)>(
            r#"
        SELECT name, last_match_at
        FROM detection_rules
        WHERE mode = 'alerting'
          AND (last_match_at IS NULL OR last_match_at < NOW() - INTERVAL '30 days')
        ORDER BY last_match_at ASC NULLS FIRST
        LIMIT 50
        "#,
        )
        .fetch_all(pool)
        .await
        {
            Ok(rows) => rows
                .into_iter()
                .map(|(name, last_match)| {
                    let days = match last_match {
                        Some(dt) => (Utc::now() - dt).num_days(),
                        None => 999,
                    };
                    StaleRule {
                        rule_name: name,
                        last_matched: last_match,
                        days_since_match: days,
                    }
                })
                .collect(),
            Err(e) => {
                warn!("Failed to collect stale rules: {}", e);
                vec![]
            }
        };

    // Noisy rules: rules with high match counts in last 24h
    let noisy_rules: Vec<NoisyRule> = match sqlx::query_as::<_, (String, i64, String)>(
        r#"
        SELECT dr.name, COALESCE(ds.match_count, 0) AS matches, dr.severity
        FROM detection_rules dr
        LEFT JOIN detection_daily_stats ds ON dr.id = ds.rule_id AND ds.date = CURRENT_DATE
        WHERE dr.mode != 'paused'
          AND COALESCE(ds.match_count, 0) > 1000
        ORDER BY matches DESC
        LIMIT 20
        "#,
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows
            .into_iter()
            .map(|(name, count, severity)| NoisyRule {
                rule_name: name,
                matches_24h: count,
                severity,
            })
            .collect(),
        Err(e) => {
            warn!("Failed to collect noisy rules: {}", e);
            vec![]
        }
    };

    // Alerts by severity in last 24h
    let alerts_24h: Vec<AlertsBySeverity> = match sqlx::query_as::<_, (String, i64)>(
        r#"
        SELECT severity, COUNT(*)
        FROM alerts
        WHERE created_at >= NOW() - INTERVAL '24 hours'
        GROUP BY severity
        "#,
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows
            .into_iter()
            .map(|(severity, count)| AlertsBySeverity { severity, count })
            .collect(),
        Err(e) => {
            warn!("Failed to collect alerts by severity: {}", e);
            vec![]
        }
    };

    info!(
        "Collected detection metrics: {} enabled rules, {} stale, {} noisy",
        total_enabled,
        stale_rules.len(),
        noisy_rules.len()
    );

    DetectionMetrics {
        total_enabled_rules: total_enabled,
        total_matches_24h,
        rules_by_mode,
        stale_rules,
        noisy_rules,
        alerts_24h_by_severity: alerts_24h,
    }
}

/// Collect alerting health metrics from PostgreSQL.
///
/// Volume + status counts come from the `alerts` table; routing health from
/// `webhooks` + `webhook_delivery_log` + `queue_routing_rules`. MTTA is
/// computed inline against `alerts.acknowledged_at - alerts.created_at`
/// because no pre-built helper exists.
async fn collect_alerting_metrics(pool: &PgPool) -> AlertingMetrics {
    let total_alerts_24h: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM alerts WHERE created_at >= NOW() - INTERVAL '24 hours'",
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    let total_alerts_prior_24h: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*) FROM alerts
        WHERE created_at >= NOW() - INTERVAL '48 hours'
          AND created_at <  NOW() - INTERVAL '24 hours'
        "#,
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    let by_status: Vec<AlertStatusCount> = match sqlx::query_as::<_, (String, i64)>(
        r#"
        SELECT status, COUNT(*)
        FROM alerts
        WHERE created_at >= NOW() - INTERVAL '24 hours'
        GROUP BY status
        "#,
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows
            .into_iter()
            .map(|(status, count)| AlertStatusCount { status, count })
            .collect(),
        Err(e) => {
            warn!("Failed to collect alerts by status: {}", e);
            vec![]
        }
    };

    // MTTA: average minutes between created_at and acknowledged_at, only over
    // alerts that were acknowledged in the window.
    let mean_mtta_minutes: Option<f64> = sqlx::query_scalar(
        r#"
        SELECT AVG(EXTRACT(EPOCH FROM (acknowledged_at - created_at)) / 60.0)::float8
        FROM alerts
        WHERE created_at >= NOW() - INTERVAL '24 hours'
          AND acknowledged_at IS NOT NULL
        "#,
    )
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();

    let active_webhooks: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM webhooks WHERE enabled = true")
            .fetch_one(pool)
            .await
            .unwrap_or(0);

    // Webhook delivery success rate over the last 24h. Both columns are
    // SELECTed with explicit casts so sqlx can infer the row type.
    let (webhook_deliveries_24h, webhook_success_pct): (i64, Option<f64>) =
        match sqlx::query_as::<_, (i64, i64)>(
            r#"
        SELECT
            COUNT(*)::bigint AS total,
            COUNT(*) FILTER (WHERE success = true)::bigint AS succeeded
        FROM webhook_delivery_log
        WHERE delivered_at >= NOW() - INTERVAL '24 hours'
        "#,
        )
        .fetch_one(pool)
        .await
        {
            Ok((total, succeeded)) => {
                let pct = if total > 0 {
                    Some((succeeded as f64 / total as f64) * 100.0)
                } else {
                    None
                };
                (total, pct)
            }
            Err(e) => {
                warn!("Failed to collect webhook delivery stats: {}", e);
                (0, None)
            }
        };

    let active_routing_rules: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM queue_routing_rules WHERE enabled = true")
            .fetch_one(pool)
            .await
            .unwrap_or(0);

    info!(
        "Collected alerting metrics: {} alerts (24h, prior {}), MTTA {:?}m, {} webhooks, {} routing rules",
        total_alerts_24h, total_alerts_prior_24h, mean_mtta_minutes, active_webhooks, active_routing_rules
    );

    AlertingMetrics {
        total_alerts_24h,
        total_alerts_prior_24h,
        by_status,
        mean_mtta_minutes,
        active_webhooks,
        webhook_deliveries_24h,
        webhook_success_pct,
        active_routing_rules,
    }
}

/// Build the per-source field-coverage SQL. Extracted as a pure function so
/// regression tests can pin its shape — the inline version previously had a
/// JSON-vs-String comparison bug (NAN-614) that is hard to catch by reading.
fn build_field_coverage_sql(logs_table: &str, ocsf: bool) -> String {
    // The result tuple `(source_type, total_events, src_ip_pct, user_pct,
    // event_type_pct, message_pct)` is fixed by `FieldCoverageMetric`, so under
    // OCSF we map the four semantic coverage slots onto the canonical OCSF
    // PROMOTED columns rather than the UDM columns (which don't exist on
    // `ocsf_logs`): src_ip → `src_endpoint.ip`, user → `user.name`, event_type
    // → `class_uid` (the OCSF event-kind discriminator; UInt32 so `!= 0`),
    // message → `message`. Dotted OCSF identifiers are double-quoted so
    // ClickHouse reads them as a single column, not a nested-tuple access.
    // UDM path is byte-identical. NAN-1259.
    if ocsf {
        format!(
            r#"
        SELECT
            source_type,
            count() AS total_events,
            countIf("src_endpoint.ip" != '') * 100.0 / count() AS src_ip_pct,
            countIf("user.name" != '') * 100.0 / count() AS user_pct,
            countIf(class_uid != 0) * 100.0 / count() AS event_type_pct,
            countIf(message != '') * 100.0 / count() AS message_pct
        FROM {logs_table}
        WHERE timestamp >= now() - INTERVAL 24 HOUR
          AND source_type != 'audit'
          AND source_type != ''
        GROUP BY source_type
        HAVING total_events >= 100
        ORDER BY total_events DESC
    "#
        )
    } else {
        format!(
            r#"
        SELECT
            source_type,
            count() AS total_events,
            countIf(src_ip != '') * 100.0 / count() AS src_ip_pct,
            countIf(user != '') * 100.0 / count() AS user_pct,
            countIf(event_type != '') * 100.0 / count() AS event_type_pct,
            countIf(message != '') * 100.0 / count() AS message_pct
        FROM {logs_table}
        WHERE timestamp >= now() - INTERVAL 24 HOUR
          AND source_type != 'audit'
          AND source_type != ''
        GROUP BY source_type
        HAVING total_events >= 100
        ORDER BY total_events DESC
    "#
        )
    }
}

/// SQL boolean expression: true when `col` holds a *globally routable*,
/// geo-locatable IPv4.
///
/// Geo-eligibility must mean "an IP the geo provider (IPinfo Lite) can actually
/// map." That excludes not just RFC1918 private space, loopback, and
/// link-local, but every other
/// non-global block: shared CGN space, the RFC5737 documentation ranges
/// (`192.0.2/24`, `198.51.100/24`, `203.0.113/24` — heavily used by synthetic
/// data and never geolocatable), benchmarking space, multicast, and the
/// reserved/broadcast `240/4`. Counting these in an enrichment denominator
/// understates coverage: validated on the demo tenant, the ASN/GeoIP "gap" was
/// almost entirely cloudtrail events on TEST-NET ranges plus multicast — i.e.
/// every mappable IP WAS mapped (NAN-1178). IPv6 is treated as ineligible here
/// — current SIEM traffic is overwhelmingly v4 and `isIPv4String` gates it out.
fn public_ipv4_expr(col: &str) -> String {
    let non_global = [
        "0.0.0.0/8",        // "this network"
        "10.0.0.0/8",       // RFC1918
        "100.64.0.0/10",    // CGN / shared address space
        "127.0.0.0/8",      // loopback
        "169.254.0.0/16",   // link-local
        "172.16.0.0/12",    // RFC1918
        "192.0.0.0/24",     // IETF protocol assignments
        "192.0.2.0/24",     // TEST-NET-1 (RFC5737 documentation)
        "192.168.0.0/16",   // RFC1918
        "198.18.0.0/15",    // benchmarking (RFC2544)
        "198.51.100.0/24",  // TEST-NET-2 (RFC5737 documentation)
        "203.0.113.0/24",   // TEST-NET-3 (RFC5737 documentation)
        "224.0.0.0/4",      // multicast
        "240.0.0.0/4",      // reserved + broadcast
    ];
    let mut expr = format!("(isIPv4String({col})");
    for range in non_global {
        expr.push_str(&format!(" AND NOT isIPAddressInRange({col}, '{range}')"));
    }
    expr.push(')');
    expr
}

/// Build the ext-column usage SQL.
///
/// `ext` is a JSON column (init.sql:508). An earlier implementation used
/// `length(toString(ext)) > 2`, which is broken: ClickHouse's JSON `toString`
/// serializes the full dynamic schema and almost always returns more than 2
/// chars even when the row's payload is effectively empty (NAN-614). Counting
/// keys is the correct emptiness check.
///
/// But "has ≥1 ext key" still saturates to ~100% for every structured source,
/// because even a well-normalized parser drops a handful of vendor/overflow
/// fields into `ext` on every row (apache_access averages a single ext key and
/// reads 100%). On its own that is NOT a normalization failure. So the finding
/// is gated to genuine passthrough: high ext usage *and* the canonical UDM
/// fields (`event_type` plus any entity) mostly empty. A source with
/// `event_type` populated is normalized regardless of how much overflow it
/// carries — NAN-1178. The HAVING references aggregates directly (ClickHouse
/// allows this) so the SELECT tuple stays `(source_type, total_events, ext_pct)`.
///
/// `ext` is a native ClickHouse `JSON` column, so the emptiness check uses the
/// native `JSONAllPaths(ext)` rather than `JSONExtractKeys(toString(ext))`. The
/// `toString` variant reserializes the full dynamic JSON for every row, which
/// dominated the scan (75s over 22M rows on demo); `JSONAllPaths` reads the
/// column directly with no reserialization (~15s, same bytes read). For the
/// `> 0` emptiness predicate the two are equivalent — `JSONAllPaths` returns all
/// paths (incl. nested) vs. only top-level keys, but any non-empty `ext` yields
/// ≥1 of each. Verified identical per-source on the demo tenant (NAN-1180). This
/// is per-row `length()`, NOT `arrayJoin(JSONAllPaths)` — no row explosion.
fn build_ext_usage_sql(logs_table: &str, ocsf: bool) -> String {
    // UDM path is byte-identical (the `ext` JSON column, UDM guard fields). OCSF
    // has no `ext`; its raw JSON payload lives in the `event` column, the
    // event-type analog is `class_uid` (UInt32, so `!= 0` not `!= ''`), and the
    // entity guard uses OCSF promoted columns (`src_endpoint.ip`, `user.name`,
    // `dst_endpoint.ip`, double-quoted because they contain dots). NAN-1259.
    if ocsf {
        format!(
            r#"
        SELECT
            source_type,
            count() AS total_events,
            countIf(length(JSONAllPaths(event)) > 0) * 100.0 / count() AS ext_pct
        FROM {logs_table}
        WHERE timestamp >= now() - INTERVAL 24 HOUR
          AND source_type != 'audit'
          AND source_type != ''
        GROUP BY source_type
        HAVING total_events >= 100
           AND ext_pct > 50
           AND countIf(class_uid != 0) * 100.0 / count() < 50
           AND countIf("src_endpoint.ip" != '' OR "user.name" != '' OR "dst_endpoint.ip" != '') * 100.0 / count() < 50
        ORDER BY ext_pct DESC
    "#
        )
    } else {
        format!(
            r#"
        SELECT
            source_type,
            count() AS total_events,
            countIf(length(JSONAllPaths(ext)) > 0) * 100.0 / count() AS ext_pct
        FROM {logs_table}
        WHERE timestamp >= now() - INTERVAL 24 HOUR
          AND source_type != 'audit'
          AND source_type != ''
        GROUP BY source_type
        HAVING total_events >= 100
           AND ext_pct > 50
           AND countIf(event_type != '') * 100.0 / count() < 50
           AND countIf(src_ip != '' OR user != '' OR dest_ip != '') * 100.0 / count() < 50
        ORDER BY ext_pct DESC
    "#
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ext_usage_sql_uses_json_aware_emptiness_check() {
        // Regression: NAN-614. The bug was `length(toString(ext)) > 2`, which
        // hits the JSON column's serialized schema rather than its payload and
        // reports ~100% ext usage for every source. The correct check counts
        // keys on the native JSON column via JSONAllPaths.
        let sql = build_ext_usage_sql("logs", false);
        assert!(
            sql.contains("length(JSONAllPaths(ext)) > 0"),
            "ext_pct must use JSONAllPaths-based emptiness check, got:\n{sql}"
        );
        assert!(
            !sql.contains("length(toString(ext))"),
            "ext_pct must not regress to length(toString(ext)) — that returns ~100% on JSON columns. got:\n{sql}"
        );
        // NAN-1180: the toString(ext) reserialization was the 75s-scan culprit;
        // the native JSONAllPaths path must not reintroduce it.
        assert!(
            !sql.contains("toString(ext)"),
            "ext_pct must not reserialize via toString(ext) — use native JSONAllPaths. got:\n{sql}"
        );
    }

    #[test]
    fn ext_usage_sql_ocsf_uses_event_column_and_promoted_guards() {
        // NAN-1259: OCSF has no `ext` column — the raw JSON payload is `event`,
        // and the normalization guard fields are the OCSF promoted columns
        // (class_uid as the event-type analog + dotted entity columns).
        let sql = build_ext_usage_sql("ocsf_logs", true);
        assert!(
            sql.contains("length(JSONAllPaths(event)) > 0"),
            "OCSF ext_pct must read the `event` JSON column, got:\n{sql}"
        );
        assert!(
            !sql.contains("JSONAllPaths(ext)") && !sql.contains("(ext)"),
            "OCSF ext_pct must not reference the non-existent `ext` column, got:\n{sql}"
        );
        assert!(
            sql.contains("countIf(class_uid != 0)"),
            "OCSF normalization guard must use class_uid (event-type analog), got:\n{sql}"
        );
        // Dotted OCSF entity columns must be double-quoted.
        assert!(
            sql.contains("\"src_endpoint.ip\" != ''")
                && sql.contains("\"user.name\" != ''")
                && sql.contains("\"dst_endpoint.ip\" != ''"),
            "OCSF entity guard must double-quote dotted promoted columns, got:\n{sql}"
        );
    }

    #[test]
    fn ext_usage_sql_only_flags_genuine_passthrough() {
        // NAN-1178: "has ≥1 ext key" saturates to ~100% even for fully
        // normalized sources. The finding must additionally require the
        // canonical UDM fields to be mostly empty, or it false-alarms on
        // every structured parser.
        let sql = build_ext_usage_sql("logs", false);
        assert!(
            sql.contains("countIf(event_type != '') * 100.0 / count() < 50"),
            "high-ext finding must require event_type to be mostly empty, got:\n{sql}"
        );
        assert!(
            sql.contains("src_ip != '' OR user != '' OR dest_ip != ''"),
            "high-ext finding must also require entity fields to be mostly empty, got:\n{sql}"
        );
    }

    #[test]
    fn public_ipv4_expr_excludes_private_and_loopback() {
        // NAN-1178: geo-eligibility must exclude RFC1918 + loopback + link-local
        // so private-IP traffic doesn't drag down enrichment coverage.
        let expr = public_ipv4_expr("src_ip");
        assert!(expr.contains("isIPv4String(src_ip)"));
        for range in [
            // private / loopback / link-local
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "127.0.0.0/8",
            "169.254.0.0/16",
            // reserved / non-geolocatable — must not be counted as eligible
            "100.64.0.0/10",
            "198.51.100.0/24",
            "203.0.113.0/24",
            "224.0.0.0/4",
            "240.0.0.0/4",
        ] {
            assert!(
                expr.contains(range),
                "geo-eligibility must exclude {range}, got:\n{expr}"
            );
        }
    }

    #[test]
    fn field_coverage_sql_filters_audit_and_unknown_sources() {
        let sql = build_field_coverage_sql("logs", false);
        assert!(sql.contains("source_type != 'audit'"));
        assert!(sql.contains("source_type != ''"));
        assert!(sql.contains("HAVING total_events >= 100"));
        // UDM coverage must read the UDM columns, byte-identical to pre-NAN-1259.
        assert!(sql.contains("countIf(src_ip != '')"));
        assert!(sql.contains("countIf(user != '')"));
        assert!(sql.contains("countIf(event_type != '')"));
        assert!(sql.contains("countIf(message != '')"));
    }

    #[test]
    fn field_coverage_sql_ocsf_uses_promoted_columns() {
        // NAN-1259: under OCSF the UDM columns don't exist; the four coverage
        // slots map onto the canonical OCSF promoted columns (dotted entity
        // columns double-quoted, class_uid as the event-type analog).
        let sql = build_field_coverage_sql("ocsf_logs", true);
        assert!(sql.contains("FROM ocsf_logs"));
        assert!(
            sql.contains("countIf(\"src_endpoint.ip\" != '')"),
            "OCSF src_ip slot must read src_endpoint.ip, got:\n{sql}"
        );
        assert!(
            sql.contains("countIf(\"user.name\" != '')"),
            "OCSF user slot must read user.name, got:\n{sql}"
        );
        assert!(
            sql.contains("countIf(class_uid != 0)"),
            "OCSF event_type slot must read class_uid, got:\n{sql}"
        );
        assert!(
            sql.contains("countIf(message != '')"),
            "OCSF message slot must read message, got:\n{sql}"
        );
        // Must not leak UDM-only columns that don't exist on ocsf_logs.
        assert!(
            !sql.contains("countIf(src_ip != '')")
                && !sql.contains("countIf(event_type != '')"),
            "OCSF coverage must not reference UDM columns, got:\n{sql}"
        );
        // Filtering/grouping is shared and must survive.
        assert!(sql.contains("source_type != 'audit'"));
        assert!(sql.contains("HAVING total_events >= 100"));
    }

    #[test]
    fn lowercase_invariant_columns_are_physical_logs_columns() {
        // NAN-1643: the probe set is LOWERCASE_NORMALIZED_FIELDS restricted to
        // physical columns — alias spellings must be dropped, entries deduped
        // to real `logs` columns.
        let cols = lowercase_invariant_columns();
        assert!(
            !cols.contains(&"sourcetype"),
            "alias spelling `sourcetype` must be dropped (source_type is the column), got {cols:?}"
        );
        // `event_type` is `ALIAS action` in the logs DDL (migration 113) —
        // probing it would report action's violations twice under two names.
        assert!(
            !cols.contains(&"event_type"),
            "DDL alias `event_type` must be dropped (action is the column), got {cols:?}"
        );
        assert!(
            cols.contains(&"action"),
            "the physical `action` column must cover the event_type alias, got {cols:?}"
        );
        for expected in ["source_type", "src_ip", "dest_ip", "src_host", "trace_id"] {
            assert!(
                cols.contains(&expected),
                "probe must cover raw-compared column {expected}, got {cols:?}"
            );
        }
        // NAN-1697: `user` left LOWERCASE_NORMALIZED_FIELDS (ingest doesn't
        // downcase it; queries now use lower(user)=), so a mixed-case `user` is
        // no longer a raw-compare violation and must not be probed.
        assert!(
            !cols.contains(&"user"),
            "`user` is no longer raw-compared and must be dropped from the probe, got {cols:?}"
        );
        // Every probed name must be a physical column, or the probe SQL errors.
        for c in &cols {
            assert!(
                crate::query::clickhouse_sql_gen::EXPLICIT_COLUMNS.contains(c),
                "{c} is not a physical logs column"
            );
        }
    }

    #[test]
    fn lowercase_invariant_sql_is_one_bounded_scan() {
        // NAN-1643: ONE aggregate scan with a countIf leg per column — never a
        // query per column — bounded to a 1h window with no GROUP BY (the
        // CH-migrations/probes resource rule: every aggregating query bounded).
        let sql = build_lowercase_invariant_sql("logs");
        assert_eq!(
            sql.matches("FROM logs").count(),
            1,
            "probe must be a single scan, got:\n{sql}"
        );
        assert!(
            sql.contains("timestamp > now() - INTERVAL 1 HOUR"),
            "probe must be time-bounded to the recent window, got:\n{sql}"
        );
        assert!(
            !sql.to_uppercase().contains("GROUP BY"),
            "probe must not group — single aggregate row only, got:\n{sql}"
        );
        for leg in [
            "('src_ip', countIf(src_ip != lower(src_ip)))",
            "('src_host', countIf(src_host != lower(src_host)))",
            "('source_type', countIf(source_type != lower(source_type)))",
        ] {
            assert!(sql.contains(leg), "probe must carry leg {leg}, got:\n{sql}");
        }
        // NAN-1697: `user` is no longer a raw-compared column, so it must not
        // appear as an invariant leg (mixed-case user is legal now).
        assert!(
            !sql.contains("('user', countIf"),
            "`user` must be dropped from the invariant probe, got:\n{sql}"
        );
        // The pivot keeps the healthy case at zero rows.
        assert!(
            sql.contains("ARRAY JOIN pairs AS t") && sql.contains("WHERE t.2 > 0"),
            "probe must pivot to (column, violations) rows and filter zeros, got:\n{sql}"
        );
    }

    #[test]
    fn pre_nan1643_reports_deserialize_without_invariant_field() {
        // Reports stored before NAN-1643 lack the violations key — the
        // serde(default) must keep them loadable.
        let old_json = r#"{
            "field_coverage": [],
            "high_ext_sources": []
        }"#;
        let m: ParsingMetrics =
            serde_json::from_str(old_json).expect("pre-NAN-1643 report deserializes");
        assert!(m.lowercase_invariant_violations.is_empty());
    }

    #[test]
    fn extract_dict_references_finds_all_dictget_forms() {
        // NAN-1405: shaped like the real nanosiem.logs DDL — dictGetOrDefault
        // with a quoted fully-qualified dict name, repeated per MATERIALIZED
        // column, plus a plain dictGet variant for good measure.
        let ddl = r#"CREATE TABLE nanosiem.logs (
            `enriched_src_country` String MATERIALIZED dictGetOrDefault('nanosiem.ip_enrichment_dict', 'country', src_ip, ''),
            `enriched_dest_country` String MATERIALIZED dictGetOrDefault('nanosiem.ip_enrichment_dict', 'country', dest_ip, ''),
            `ioc_confidence` UInt8 MATERIALIZED dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'confidence', dest_ip, 0),
            `prevalence_file_hash` UInt64 MATERIALIZED dictGet('nanosiem.hash_prevalence_dict', 'cnt', file_hash),
            `user_identity_title` String MATERIALIZED dictGetOrDefault('nanosiem.user_registry_dict', 'title', user, '')
        ) ENGINE = MergeTree ORDER BY timestamp"#;
        let refs = extract_dict_references(ddl);
        assert_eq!(
            refs,
            vec![
                "nanosiem.hash_prevalence_dict".to_string(),
                "nanosiem.ioc_enrichment_dict".to_string(),
                "nanosiem.ip_enrichment_dict".to_string(),
                "nanosiem.user_registry_dict".to_string(),
            ],
            "deduped + sorted dict references from the DDL"
        );
        // A dict-free DDL (no enrichment MATERIALIZED columns) yields nothing.
        assert!(extract_dict_references("CREATE TABLE t (x String) ENGINE = Memory").is_empty());
    }

    #[test]
    fn dict_is_unhealthy_flags_failed_and_degraded_but_not_benign() {
        // FAILED family — status-only, no exception needed.
        assert!(dict_is_unhealthy("FAILED", ""));
        assert!(dict_is_unhealthy("FAILED_AND_RELOADING", ""));
        // Degraded CACHE dict: reports LOADED while its source errors — the G2
        // blind spot. Empirically reproduced on CH 26.4 (Code 510).
        assert!(dict_is_unhealthy(
            "LOADED",
            "Code: 510. DB::Exception: Update failed for dictionary ..."
        ));
        // NOT_LOADED with a load exception is unhealthy too.
        assert!(dict_is_unhealthy("NOT_LOADED", "Code: 60. Unknown table ..."));
        // Benign: healthy LOADED dict, and a never-referenced lazy dict sitting
        // at NOT_LOADED with an EMPTY exception — must NOT be flagged (the
        // false-positive trap). last_exception clears on recovery, so a
        // recovered dict lands here on the next probe.
        assert!(!dict_is_unhealthy("LOADED", ""));
        assert!(!dict_is_unhealthy("NOT_LOADED", ""));
    }
}
