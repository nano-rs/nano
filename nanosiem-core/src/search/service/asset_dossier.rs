// SPDX-License-Identifier: AGPL-3.0-or-later

//! Asset dossier — single aggregate endpoint that populates the redesigned Asset view.
//!
//! The redesigned Asset view (NAN-393) renders an entity dossier with identity header,
//! activity timeline, and a 2-column grid of section cards (processes, network, auth,
//! files, dns). This module exposes `query_asset_dossier` which runs those aggregates
//! in parallel against ClickHouse and assembles the response.
//!
//! Alerts and risk are fetched separately by the frontend via `entity_context` (which
//! lives in nanosiem-api and reads from Postgres cases/alerts), and prevalence dots
//! come from the existing `asset-artifacts` endpoint — so this module focuses purely
//! on what can be derived from the UDM event stream in ClickHouse.

use super::SearchService;
use crate::query::TimeRange;
use crate::search::SearchError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ============================================================================
// Response types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema, Default)]
pub struct AssetDossier {
    pub identity: AssetIdentity,
    pub timeline: AssetActivityTimeline,
    pub processes: AssetProcessesSummary,
    pub network: AssetNetworkSummary,
    pub auth: AssetAuthSummary,
    pub files: AssetFilesSummary,
    pub dns: AssetDnsSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema, Default)]
pub struct AssetIdentity {
    /// Latest observed hostname (argMax by timestamp)
    pub hostname: Option<String>,
    /// Latest observed primary IP
    pub ip: Option<String>,
    /// Latest observed MAC address
    pub mac: Option<String>,
    /// Latest observed user (for user-field entities, this is just the entity)
    pub user: Option<String>,
    /// Latest observed vendor_product (proxy for OS/agent)
    pub vendor_product: Option<String>,
    /// First event seen in the query range
    pub first_seen_in_range: Option<String>,
    /// Last event seen in the query range
    pub last_seen_in_range: Option<String>,
    /// Per-source_type health: one entry per log source that saw this entity within the range
    pub log_sources: Vec<AssetLogSource>,
    /// Domain inferred from FQDN (everything after the first dot). Empty when hostname is bare.
    pub domain: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AssetLogSource {
    pub name: String,
    pub event_count: u64,
    pub last_event: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema, Default)]
pub struct AssetActivityTimeline {
    /// Number of buckets in the timeline (default 28 — one per 6h slot across 7d)
    pub buckets: u32,
    /// Lane ordering — always [auth, proc, net, file, alert] for now
    pub lanes: Vec<String>,
    /// Sparse points: [bucket_index, lane_index, weight] — weight in {1, 2, 3}
    pub points: Vec<[u32; 3]>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema, Default)]
pub struct AssetProcessesSummary {
    pub unique: u64,
    pub rare: u64,
    pub unsigned: u64,
    pub from_office: u64,
    pub top: Vec<ProcessTop>,
    pub rare_list: Vec<ProcessRare>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ProcessTop {
    pub name: String,
    pub count: u64,
    /// Prevalence percentage across the fleet (0-100)
    pub prev: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ProcessRare {
    pub name: String,
    pub hash: Option<String>,
    pub prev: f32,
    pub cmd: Option<String>,
    pub flags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema, Default)]
pub struct AssetNetworkSummary {
    pub total_conns: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub unique_dsts: u64,
    pub new_domains: u64,
    pub top_dsts: Vec<NetworkDest>,
    pub rare_countries: Vec<NetworkRareCountry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct NetworkDest {
    pub host: String,
    pub ip: Option<String>,
    pub country: Option<String>,
    pub bytes: u64,
    pub conns: u64,
    /// Reputation: known-good | new-domain | suspicious | unknown
    pub rep: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct NetworkRareCountry {
    pub country: String,
    pub conns: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema, Default)]
pub struct AssetAuthSummary {
    pub success: u64,
    pub failure: u64,
    pub interactive: u64,
    pub network: u64,
    pub lateral: u64,
    pub recent: Vec<AuthRecent>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AuthRecent {
    pub ts: String,
    /// Auth type: interactive | network | vpn | saml | mfa | other
    pub auth_type: String,
    pub user: Option<String>,
    pub src: Option<String>,
    /// success | failure
    pub result: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema, Default)]
pub struct AssetFilesSummary {
    pub writes: u64,
    pub sensitive: u64,
    pub exec: u64,
    pub recent: Vec<FileRecent>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct FileRecent {
    pub ts: String,
    pub path: String,
    pub size_bytes: u64,
    /// create | modify | delete | read
    pub action: String,
    pub proc: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema, Default)]
pub struct AssetDnsSummary {
    pub queries: u64,
    pub unique: u64,
    pub nx: u64,
    pub rare_tlds: u64,
    pub top: Vec<DnsTop>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct DnsTop {
    pub domain: String,
    pub count: u64,
    pub nx: u64,
}

// ============================================================================
// Constants
// ============================================================================

/// Number of buckets across the time range for the activity timeline.
const TIMELINE_BUCKETS: u32 = 28;
/// Recent-events list sizes (auth, files).
const RECENT_LIMIT: usize = 8;
/// Top-N sizes for section cards.
const TOP_LIMIT: usize = 8;
/// Prevalence threshold (in % of fleet) for "rare" process classification.
const RARE_PROCESS_THRESHOLD_PCT: f32 = 10.0;
/// Denominator for "fleet %" prevalence math. The prevalence dictionaries
/// store `host_count` as a UInt16, so this is the sample-fleet size we
/// project those counts against to derive a percentage.
///
/// TODO(NAN-393 follow-up): read the real fleet size from the prevalence
/// service (it's computed at enrichment time, just not exposed here yet)
/// instead of this placeholder derived from the demo dataset. Callers that
/// care about the exact figure should treat percentages as approximate until
/// that plumbing lands.
const ASSUMED_FLEET_SIZE: f32 = 1742.0;

// ============================================================================
// Public entry
// ============================================================================

impl SearchService {
    /// Build the asset dossier for the redesigned Asset view.
    ///
    /// Runs identity + timeline + processes + network + auth + files + dns
    /// aggregates in parallel. Missing ClickHouse returns an empty dossier.
    pub async fn query_asset_dossier(
        &self,
        identifier_field: &str,
        identifier_value: &str,
        identities: &[serde_json::Value],
        time_range: &TimeRange,
    ) -> Result<AssetDossier, SearchError> {
        let clickhouse = match &self.ch_client {
            Some(ch) => ch,
            None => return Ok(AssetDossier::default()),
        };

        let (ips, hostnames, users) =
            Self::collect_asset_identifiers(identities, identifier_field, identifier_value);
        let (identity_clause, bind_values) =
            match Self::build_log_identity_clause(&ips, &hostnames, &users) {
                Some(pair) => pair,
                None => return Ok(AssetDossier::default()),
            };

        let start_str = time_range.start.format("%Y-%m-%d %H:%M:%S%.6f").to_string();
        let end_str = time_range.end.format("%Y-%m-%d %H:%M:%S%.6f").to_string();
        let bucket_seconds = bucket_seconds_for_range(time_range);
        let unix_start = time_range.start.timestamp() as u64;

        let logs_table = self.table_names.read("logs");

        // Kick off all 7 queries in parallel
        let identity_fut = query_identity(
            clickhouse,
            &logs_table,
            &identity_clause,
            &bind_values,
            &start_str,
            &end_str,
        );
        let log_sources_fut = query_log_sources(
            clickhouse,
            &logs_table,
            &identity_clause,
            &bind_values,
            &start_str,
            &end_str,
        );
        let timeline_fut = query_timeline(
            clickhouse,
            &logs_table,
            &identity_clause,
            &bind_values,
            &start_str,
            &end_str,
            bucket_seconds,
            unix_start,
        );
        let processes_fut = query_processes(
            clickhouse,
            &logs_table,
            &identity_clause,
            &bind_values,
            &start_str,
            &end_str,
        );
        let network_fut = query_network(
            clickhouse,
            &logs_table,
            &identity_clause,
            &bind_values,
            &start_str,
            &end_str,
        );
        let auth_fut = query_auth(
            clickhouse,
            &logs_table,
            &identity_clause,
            &bind_values,
            &start_str,
            &end_str,
        );
        let files_fut = query_files(
            clickhouse,
            &logs_table,
            &identity_clause,
            &bind_values,
            &start_str,
            &end_str,
        );
        let dns_fut = query_dns(
            clickhouse,
            &logs_table,
            &identity_clause,
            &bind_values,
            &start_str,
            &end_str,
        );

        let (identity_res, log_sources, timeline, processes, network, auth, files, dns) = tokio::join!(
            identity_fut,
            log_sources_fut,
            timeline_fut,
            processes_fut,
            network_fut,
            auth_fut,
            files_fut,
            dns_fut,
        );

        let mut identity = identity_res.unwrap_or_default();
        identity.log_sources = log_sources;
        if let Some(ref host) = identity.hostname {
            // Only derive a domain from a hostname — not from an IP literal
            if !looks_like_ip(host) {
                if let Some(idx) = host.find('.') {
                    identity.domain = Some(host[idx + 1..].to_string());
                }
            }
        }

        Ok(AssetDossier {
            identity,
            timeline,
            processes,
            network,
            auth,
            files,
            dns,
        })
    }

}

// ============================================================================
// Per-section queries
// ============================================================================

fn apply_binds(
    query: clickhouse::query::Query,
    binds: &[String],
) -> clickhouse::query::Query {
    let mut q = query;
    for val in binds {
        q = q.bind(val);
    }
    q
}

/// Execute one of the per-section dossier queries and return parsed JSON rows.
///
/// Failures are logged at `error` level with the `subquery` tag so a broken
/// section (e.g. a misaligned alias, a changed column) surfaces in log
/// aggregators even though we degrade gracefully by returning empty rows — the
/// UI renders `—` placeholders when data is missing, so a silent failure would
/// otherwise look identical to "entity has no events". The tag lets dashboards
/// count failures per subquery.
async fn fetch_rows(
    query: clickhouse::query::Query,
    subquery: &'static str,
) -> Vec<serde_json::Value> {
    let mut cursor = match query.fetch_bytes("JSONEachRow") {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(subquery, error = %e, "Asset dossier subquery failed to start");
            return Vec::new();
        }
    };
    let mut bytes = Vec::new();
    loop {
        match cursor.next().await {
            Ok(Some(chunk)) => bytes.extend_from_slice(&chunk),
            Ok(None) => break,
            Err(e) => {
                tracing::error!(subquery, error = %e, "Asset dossier subquery chunk read failed");
                break;
            }
        }
    }
    String::from_utf8(bytes)
        .ok()
        .map(|s| {
            s.lines()
                .filter(|l| !l.is_empty())
                .filter_map(|l| serde_json::from_str(l).ok())
                .collect()
        })
        .unwrap_or_default()
}

async fn query_identity(
    ch: &clickhouse::Client,
    logs: &str,
    ident: &str,
    binds: &[String],
    start: &str,
    end: &str,
) -> Option<AssetIdentity> {
    // Use argMaxIf with a non-empty filter rather than argMaxOrNull on nullIf(col, '').
    // With the old shape, if the row with the maximum timestamp happens to have the
    // column blank (common for log sources that partially populate UDM — e.g. squid_proxy
    // rows without src_host/user), the whole column returns NULL even when older events
    // had a real value. argMaxIf skips rows where the column is blank so we always get
    // the latest-populated value when any event has it.
    let sql = format!(
        r#"SELECT
            argMaxIf(src_host,        timestamp, src_host != '')        AS hostname,
            argMaxIf(src_ip,          timestamp, src_ip != '')          AS ip,
            argMaxIf(src_mac,         timestamp, src_mac != '')         AS mac,
            argMaxIf(user,            timestamp, user != '')            AS latest_user,
            argMaxIf(vendor_product,  timestamp, vendor_product != '')  AS vendor_product,
            formatDateTime(min(timestamp), '%Y-%m-%dT%H:%i:%S.%fZ') AS first_seen_in_range,
            formatDateTime(max(timestamp), '%Y-%m-%dT%H:%i:%S.%fZ') AS last_seen_in_range
        FROM {logs}
        PREWHERE timestamp BETWEEN '{start}' AND '{end}' AND ({ident})
        "#
    );
    // argMaxIf on a String column returns "" (not null) when no row matches the filter —
    // treat empty strings as "not observed" so the frontend renders "—" instead of "".
    let str_or_none = |row: &serde_json::Value, key: &str| -> Option<String> {
        row.get(key)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from)
    };

    let rows = fetch_rows(apply_binds(ch.query(&sql), binds), "identity").await;
    rows.into_iter().next().map(|row| AssetIdentity {
        hostname: str_or_none(&row, "hostname"),
        ip: str_or_none(&row, "ip"),
        mac: str_or_none(&row, "mac"),
        user: str_or_none(&row, "latest_user"),
        vendor_product: str_or_none(&row, "vendor_product"),
        first_seen_in_range: str_or_none(&row, "first_seen_in_range"),
        last_seen_in_range: str_or_none(&row, "last_seen_in_range"),
        log_sources: Vec::new(),
        domain: None,
    })
}

async fn query_log_sources(
    ch: &clickhouse::Client,
    logs: &str,
    ident: &str,
    binds: &[String],
    start: &str,
    end: &str,
) -> Vec<AssetLogSource> {
    let sql = format!(
        r#"SELECT
            source_type AS name,
            count() AS event_count,
            formatDateTime(max(timestamp), '%Y-%m-%dT%H:%i:%S.%fZ') AS last_event
        FROM {logs}
        PREWHERE timestamp BETWEEN '{start}' AND '{end}' AND ({ident})
        GROUP BY source_type
        ORDER BY event_count DESC
        LIMIT 16"#
    );
    fetch_rows(apply_binds(ch.query(&sql), binds), "log_sources")
        .await
        .into_iter()
        .filter_map(|row| {
            Some(AssetLogSource {
                name: row.get("name")?.as_str()?.to_string(),
                event_count: row.get("event_count").and_then(|v| v.as_u64()).unwrap_or(0),
                last_event: row.get("last_event")?.as_str()?.to_string(),
            })
        })
        .collect()
}

// Lane classification is shared with `service::asset`'s event-type classifier
// — see `search::classification` for the single source of truth.
use crate::search::classification::LANE_SQL;

async fn query_timeline(
    ch: &clickhouse::Client,
    logs: &str,
    ident: &str,
    binds: &[String],
    start: &str,
    end: &str,
    bucket_seconds: u32,
    unix_start: u64,
) -> AssetActivityTimeline {
    let sql = format!(
        r#"SELECT
            toUInt32(intDiv(toUnixTimestamp(timestamp) - {unix_start}, {bucket_seconds})) AS bucket,
            toInt32({lane}) AS lane,
            count() AS c
        FROM {logs}
        PREWHERE timestamp BETWEEN '{start}' AND '{end}' AND ({ident})
        GROUP BY bucket, lane
        HAVING lane >= 0 AND bucket < {buckets}"#,
        lane = LANE_SQL,
        buckets = TIMELINE_BUCKETS,
    );
    let rows = fetch_rows(apply_binds(ch.query(&sql), binds), "timeline").await;

    // Compute max count per lane so we can normalize weights to {1, 2, 3}
    let mut per_lane_max: BTreeMap<i32, u64> = BTreeMap::new();
    for row in &rows {
        let lane = row.get("lane").and_then(|v| v.as_i64()).unwrap_or(-1) as i32;
        let c = row.get("c").and_then(|v| v.as_u64()).unwrap_or(0);
        per_lane_max.entry(lane).and_modify(|m| *m = (*m).max(c)).or_insert(c);
    }

    let points: Vec<[u32; 3]> = rows
        .into_iter()
        .filter_map(|row| {
            let bucket = row.get("bucket").and_then(|v| v.as_u64())? as u32;
            let lane = row.get("lane").and_then(|v| v.as_i64())? as i32;
            if !(0..5).contains(&lane) {
                return None;
            }
            let c = row.get("c").and_then(|v| v.as_u64()).unwrap_or(0);
            let max = *per_lane_max.get(&lane).unwrap_or(&1).max(&1);
            let ratio = c as f64 / max as f64;
            let weight: u32 = if ratio >= 0.66 {
                3
            } else if ratio >= 0.33 {
                2
            } else if c > 0 {
                1
            } else {
                0
            };
            if weight == 0 {
                return None;
            }
            Some([bucket, lane as u32, weight])
        })
        .collect();

    let _ = bucket_seconds;

    AssetActivityTimeline {
        buckets: TIMELINE_BUCKETS,
        lanes: vec![
            "auth".into(),
            "proc".into(),
            "net".into(),
            "file".into(),
            "alert".into(),
        ],
        points,
    }
}

async fn query_processes(
    ch: &clickhouse::Client,
    logs: &str,
    ident: &str,
    binds: &[String],
    start: &str,
    end: &str,
) -> AssetProcessesSummary {
    // Scalar counters
    let scalar_sql = format!(
        r#"SELECT
            uniqExact(process_name) AS unique,
            countIf(process_name != '' AND prevalence_process_hash < 10000 AND toFloat32(prevalence_process_hash) / {ASSUMED_FLEET_SIZE} * 100 < {rare_pct}) AS rare,
            countIf(lower(parent_process_name) IN ('winword.exe','excel.exe','powerpnt.exe','outlook.exe')) AS from_office
        FROM {logs}
        PREWHERE timestamp BETWEEN '{start}' AND '{end}' AND ({ident}) AND process_name != ''"#,
        rare_pct = RARE_PROCESS_THRESHOLD_PCT
    );
    let top_sql = format!(
        r#"SELECT
            process_name AS name,
            count() AS c,
            avg(toFloat32(if(prevalence_process_hash >= 10000, 100, prevalence_process_hash)) / {ASSUMED_FLEET_SIZE} * 100) AS prev
        FROM {logs}
        PREWHERE timestamp BETWEEN '{start}' AND '{end}' AND ({ident}) AND process_name != ''
        GROUP BY process_name
        ORDER BY c DESC
        LIMIT {TOP_LIMIT}"#
    );
    let rare_sql = format!(
        r#"SELECT
            process_name AS name,
            any(process_hash) AS hash,
            avg(toFloat32(prevalence_process_hash) / {ASSUMED_FLEET_SIZE} * 100) AS prev,
            any(command_line) AS cmd
        FROM {logs}
        PREWHERE timestamp BETWEEN '{start}' AND '{end}' AND ({ident})
            AND process_name != '' AND prevalence_process_hash < 10000
            AND toFloat32(prevalence_process_hash) / {ASSUMED_FLEET_SIZE} * 100 < {RARE_PROCESS_THRESHOLD_PCT}
        GROUP BY process_name
        ORDER BY prev ASC
        LIMIT 5"#
    );

    let (scalars, tops, rares) = tokio::join!(
        fetch_rows(apply_binds(ch.query(&scalar_sql), binds), "processes_scalar"),
        fetch_rows(apply_binds(ch.query(&top_sql), binds), "processes_top"),
        fetch_rows(apply_binds(ch.query(&rare_sql), binds), "processes_rare"),
    );

    let (unique, rare, from_office) = scalars
        .into_iter()
        .next()
        .map(|r| {
            (
                r.get("unique").and_then(|v| v.as_u64()).unwrap_or(0),
                r.get("rare").and_then(|v| v.as_u64()).unwrap_or(0),
                r.get("from_office").and_then(|v| v.as_u64()).unwrap_or(0),
            )
        })
        .unwrap_or((0, 0, 0));

    let top = tops
        .into_iter()
        .filter_map(|r| {
            Some(ProcessTop {
                name: r.get("name")?.as_str()?.to_string(),
                count: r.get("c").and_then(|v| v.as_u64()).unwrap_or(0),
                prev: r.get("prev").and_then(|v| v.as_f64()).unwrap_or(0.0) as f32,
            })
        })
        .collect();

    let rare_list = rares
        .into_iter()
        .filter_map(|r| {
            let name = r.get("name")?.as_str()?.to_string();
            let hash = r.get("hash").and_then(|v| v.as_str().map(String::from));
            let prev = r.get("prev").and_then(|v| v.as_f64()).unwrap_or(0.0) as f32;
            let cmd = r.get("cmd").and_then(|v| v.as_str().map(String::from));
            let mut flags = Vec::new();
            if name.to_lowercase() == "rundll32.exe" || name.to_lowercase() == "certutil.exe" {
                flags.push("lolbin".to_string());
            }
            if prev < 5.0 {
                flags.push("rare".to_string());
            }
            Some(ProcessRare {
                name,
                hash,
                prev,
                cmd,
                flags,
            })
        })
        .collect();

    AssetProcessesSummary {
        unique,
        rare,
        unsigned: 0, // no signing field in logs today — surfaced as 0 until we add it
        from_office,
        top,
        rare_list,
    }
}

async fn query_network(
    ch: &clickhouse::Client,
    logs: &str,
    ident: &str,
    binds: &[String],
    start: &str,
    end: &str,
) -> AssetNetworkSummary {
    let scalar_sql = format!(
        r#"SELECT
            countIf(dest_ip != '' OR dest_host != '') AS total_conns,
            sum(bytes_in) AS bytes_in,
            sum(bytes_out) AS bytes_out,
            uniqExact(dest_ip) AS unique_dsts,
            uniqExactIf(dest_host, dest_host != '' AND prevalence_dest_domain < 5) AS new_domains
        FROM {logs}
        PREWHERE timestamp BETWEEN '{start}' AND '{end}' AND ({ident})"#
    );
    let top_sql = format!(
        r#"SELECT
            dest_host AS host,
            any(dest_ip) AS ip,
            any(enriched_dest_country_code) AS country,
            sum(bytes_in) + sum(bytes_out) AS bytes,
            count() AS conns,
            min(prevalence_dest_domain) AS prev
        FROM {logs}
        PREWHERE timestamp BETWEEN '{start}' AND '{end}' AND ({ident}) AND dest_host != ''
        GROUP BY dest_host
        ORDER BY bytes DESC
        LIMIT {TOP_LIMIT}"#
    );
    let country_sql = format!(
        r#"SELECT
            enriched_dest_country_code AS country,
            count() AS conns
        FROM {logs}
        PREWHERE timestamp BETWEEN '{start}' AND '{end}' AND ({ident})
            AND enriched_dest_country_code != ''
            AND enriched_dest_country_code NOT IN ('US','CA','GB','FR','DE','JP','AU','NL','IE','SG')
        GROUP BY enriched_dest_country_code
        ORDER BY conns DESC
        LIMIT 5"#
    );

    let (scalars, tops, countries) = tokio::join!(
        fetch_rows(apply_binds(ch.query(&scalar_sql), binds), "network_scalar"),
        fetch_rows(apply_binds(ch.query(&top_sql), binds), "network_top"),
        fetch_rows(apply_binds(ch.query(&country_sql), binds), "network_countries"),
    );

    let (total_conns, bytes_in, bytes_out, unique_dsts, new_domains) = scalars
        .into_iter()
        .next()
        .map(|r| {
            (
                r.get("total_conns").and_then(|v| v.as_u64()).unwrap_or(0),
                r.get("bytes_in").and_then(|v| v.as_u64()).unwrap_or(0),
                r.get("bytes_out").and_then(|v| v.as_u64()).unwrap_or(0),
                r.get("unique_dsts").and_then(|v| v.as_u64()).unwrap_or(0),
                r.get("new_domains").and_then(|v| v.as_u64()).unwrap_or(0),
            )
        })
        .unwrap_or((0, 0, 0, 0, 0));

    let top_dsts = tops
        .into_iter()
        .filter_map(|r| {
            let host = r.get("host")?.as_str()?.to_string();
            let prev = r.get("prev").and_then(|v| v.as_u64()).unwrap_or(9999);
            let rep = if prev < 5 {
                "new-domain"
            } else if prev < 50 {
                "unknown"
            } else {
                "known-good"
            };
            Some(NetworkDest {
                host,
                ip: r.get("ip").and_then(|v| v.as_str().map(String::from)),
                country: r.get("country").and_then(|v| v.as_str().map(String::from)),
                bytes: r.get("bytes").and_then(|v| v.as_u64()).unwrap_or(0),
                conns: r.get("conns").and_then(|v| v.as_u64()).unwrap_or(0),
                rep: rep.to_string(),
            })
        })
        .collect();

    let rare_countries = countries
        .into_iter()
        .filter_map(|r| {
            Some(NetworkRareCountry {
                country: r.get("country")?.as_str()?.to_string(),
                conns: r.get("conns").and_then(|v| v.as_u64()).unwrap_or(0),
            })
        })
        .collect();

    AssetNetworkSummary {
        total_conns,
        bytes_in,
        bytes_out,
        unique_dsts,
        new_domains,
        top_dsts,
        rare_countries,
    }
}

async fn query_auth(
    ch: &clickhouse::Client,
    logs: &str,
    ident: &str,
    binds: &[String],
    start: &str,
    end: &str,
) -> AssetAuthSummary {
    // Treat auth as events where auth_result != '' or action/source_type hints at logon.
    let auth_predicate = "(auth_result != '' OR lower(source_type) LIKE '%auth%' OR position(lower(action), 'logon') > 0 OR position(lower(action), 'login') > 0)";
    let interactive_predicate = "(lower(auth_type) = 'interactive' OR position(lower(action), 'interactive') > 0)";
    let network_predicate = "(lower(auth_type) = 'network' OR position(lower(action), 'network') > 0)";

    let scalar_sql = format!(
        r#"SELECT
            countIf({auth_predicate} AND lower(coalesce(nullIf(auth_result, ''), result)) IN ('success','succeeded','allow')) AS success,
            countIf({auth_predicate} AND lower(coalesce(nullIf(auth_result, ''), result)) IN ('failure','failed','denied','fail')) AS failure,
            countIf({auth_predicate} AND {interactive_predicate}) AS interactive,
            countIf({auth_predicate} AND {network_predicate}) AS network,
            0 AS lateral
        FROM {logs}
        PREWHERE timestamp BETWEEN '{start}' AND '{end}' AND ({ident})"#
    );
    let recent_sql = format!(
        r#"SELECT
            formatDateTime(timestamp, '%H:%i:%S') AS ts,
            coalesce(nullIf(auth_type, ''), 'other') AS auth_type,
            user,
            coalesce(nullIf(src_host, ''), src_ip) AS src,
            lower(coalesce(nullIf(auth_result, ''), result)) AS result_raw,
            action AS reason
        FROM {logs}
        PREWHERE timestamp BETWEEN '{start}' AND '{end}' AND ({ident}) AND {auth_predicate}
        ORDER BY timestamp DESC
        LIMIT {RECENT_LIMIT}"#
    );

    let (scalars, recents) = tokio::join!(
        fetch_rows(apply_binds(ch.query(&scalar_sql), binds), "auth_scalar"),
        fetch_rows(apply_binds(ch.query(&recent_sql), binds), "auth_recent"),
    );

    let (success, failure, interactive, network, lateral) = scalars
        .into_iter()
        .next()
        .map(|r| {
            (
                r.get("success").and_then(|v| v.as_u64()).unwrap_or(0),
                r.get("failure").and_then(|v| v.as_u64()).unwrap_or(0),
                r.get("interactive").and_then(|v| v.as_u64()).unwrap_or(0),
                r.get("network").and_then(|v| v.as_u64()).unwrap_or(0),
                r.get("lateral").and_then(|v| v.as_u64()).unwrap_or(0),
            )
        })
        .unwrap_or((0, 0, 0, 0, 0));

    let recent = recents
        .into_iter()
        .filter_map(|r| {
            let ts = r.get("ts")?.as_str()?.to_string();
            let result_raw = r
                .get("result_raw")
                .and_then(|v| v.as_str())
                .unwrap_or("success");
            let result = match result_raw {
                "failure" | "failed" | "denied" | "fail" => "failure",
                _ => "success",
            };
            Some(AuthRecent {
                ts,
                auth_type: r
                    .get("auth_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("other")
                    .to_string(),
                user: r.get("user").and_then(|v| v.as_str().map(String::from)),
                src: r.get("src").and_then(|v| v.as_str().map(String::from)),
                result: result.to_string(),
                reason: r.get("reason").and_then(|v| v.as_str().map(String::from)),
            })
        })
        .collect();

    AssetAuthSummary {
        success,
        failure,
        interactive,
        network,
        lateral,
        recent,
    }
}

async fn query_files(
    ch: &clickhouse::Client,
    logs: &str,
    ident: &str,
    binds: &[String],
    start: &str,
    end: &str,
) -> AssetFilesSummary {
    let scalar_sql = format!(
        r#"SELECT
            countIf(lower(file_action) IN ('create','write','modify','delete')) AS writes,
            countIf(file_path LIKE '%\\Documents\\%' OR file_path LIKE '%\\Desktop\\%' OR file_path LIKE '%payroll%' OR file_path LIKE '%secret%') AS sensitive,
            countIf(file_name LIKE '%.exe' OR file_name LIKE '%.dll' OR file_name LIKE '%.ps1' OR file_name LIKE '%.bat') AS exec_count
        FROM {logs}
        PREWHERE timestamp BETWEEN '{start}' AND '{end}' AND ({ident}) AND file_action != ''"#
    );
    let recent_sql = format!(
        r#"SELECT
            formatDateTime(timestamp, '%H:%i:%S') AS ts,
            file_path AS path,
            file_size AS size_bytes,
            file_action AS action,
            process_name AS proc
        FROM {logs}
        PREWHERE timestamp BETWEEN '{start}' AND '{end}' AND ({ident}) AND file_action != '' AND file_path != ''
        ORDER BY timestamp DESC
        LIMIT {RECENT_LIMIT}"#
    );

    let (scalars, recents) = tokio::join!(
        fetch_rows(apply_binds(ch.query(&scalar_sql), binds), "files_scalar"),
        fetch_rows(apply_binds(ch.query(&recent_sql), binds), "files_recent"),
    );

    let (writes, sensitive, exec) = scalars
        .into_iter()
        .next()
        .map(|r| {
            (
                r.get("writes").and_then(|v| v.as_u64()).unwrap_or(0),
                r.get("sensitive").and_then(|v| v.as_u64()).unwrap_or(0),
                r.get("exec_count").and_then(|v| v.as_u64()).unwrap_or(0),
            )
        })
        .unwrap_or((0, 0, 0));

    let recent = recents
        .into_iter()
        .filter_map(|r| {
            Some(FileRecent {
                ts: r.get("ts")?.as_str()?.to_string(),
                path: r.get("path")?.as_str()?.to_string(),
                size_bytes: r.get("size_bytes").and_then(|v| v.as_u64()).unwrap_or(0),
                action: r
                    .get("action")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                proc: r.get("proc").and_then(|v| v.as_str().map(String::from)),
            })
        })
        .collect();

    AssetFilesSummary {
        writes,
        sensitive,
        exec,
        recent,
    }
}

async fn query_dns(
    ch: &clickhouse::Client,
    logs: &str,
    ident: &str,
    binds: &[String],
    start: &str,
    end: &str,
) -> AssetDnsSummary {
    let scalar_sql = format!(
        r#"SELECT
            countIf(query != '') AS queries,
            uniqExactIf(query, query != '') AS unique,
            countIf(query != '' AND (answer = '' OR lower(answer) = 'nxdomain')) AS nx,
            uniqExactIf(query,
                query != ''
                AND position(query, '.') > 0
                AND arrayExists(x -> endsWith(lower(query), x),
                                ['.ru','.cn','.tk','.top','.xyz','.ro'])) AS rare_tlds
        FROM {logs}
        PREWHERE timestamp BETWEEN '{start}' AND '{end}' AND ({ident})"#
    );
    let top_sql = format!(
        r#"SELECT
            query AS domain,
            count() AS c,
            countIf(answer = '' OR lower(answer) = 'nxdomain') AS nx
        FROM {logs}
        PREWHERE timestamp BETWEEN '{start}' AND '{end}' AND ({ident}) AND query != ''
        GROUP BY query
        ORDER BY c DESC
        LIMIT {TOP_LIMIT}"#
    );

    let (scalars, tops) = tokio::join!(
        fetch_rows(apply_binds(ch.query(&scalar_sql), binds), "dns_scalar"),
        fetch_rows(apply_binds(ch.query(&top_sql), binds), "dns_top"),
    );

    let (queries, unique, nx, rare_tlds) = scalars
        .into_iter()
        .next()
        .map(|r| {
            (
                r.get("queries").and_then(|v| v.as_u64()).unwrap_or(0),
                r.get("unique").and_then(|v| v.as_u64()).unwrap_or(0),
                r.get("nx").and_then(|v| v.as_u64()).unwrap_or(0),
                r.get("rare_tlds").and_then(|v| v.as_u64()).unwrap_or(0),
            )
        })
        .unwrap_or((0, 0, 0, 0));

    let top = tops
        .into_iter()
        .filter_map(|r| {
            Some(DnsTop {
                domain: r.get("domain")?.as_str()?.to_string(),
                count: r.get("c").and_then(|v| v.as_u64()).unwrap_or(0),
                nx: r.get("nx").and_then(|v| v.as_u64()).unwrap_or(0),
            })
        })
        .collect();

    AssetDnsSummary {
        queries,
        unique,
        nx,
        rare_tlds,
        top,
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Bucket size (seconds) for the activity timeline. TIMELINE_BUCKETS buckets
/// always span the query range.
/// Is this identifier an IP literal (v4 or v6) rather than a hostname?
/// Used to decide whether we should try to derive a `domain` from the value.
fn looks_like_ip(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

fn bucket_seconds_for_range(range: &TimeRange) -> u32 {
    let span = (range.end - range.start).num_seconds().max(1) as u64;
    let per_bucket = (span / TIMELINE_BUCKETS as u64).max(1);
    // Cap at u32::MAX to be safe — anything over a century per bucket is nonsense
    per_bucket.min(u32::MAX as u64) as u32
}
