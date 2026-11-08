// SPDX-License-Identifier: AGPL-3.0-or-later

//! The IPinfo geo/ASN dictionaries (NAN-4957, ClickHouse migration 185).
//!
//! IP geo/ASN enrichment is two ClickHouse dictionaries:
//!
//! * [`IP_GEO_TRIE_DICT`]: `IP_TRIE`, network -> `geo_id` (UInt64), loaded
//!   from `nanosiem.ip_enrichment_dict_staging`.
//! * [`IP_GEO_ATTRS_DICT`]: `HASHED`, `geo_id` -> the seven attributes,
//!   loaded from the staging table UNION the combinations recorded in
//!   [`IP_GEO_HISTORY_TABLE`] (30-day TTL).
//!
//! `geo_id` is `cityHash64` of the seven attributes. The 4.38M IPinfo Lite
//! networks share 114k distinct attribute combinations, so this layout holds
//! ~250 MiB where the old single seven-attribute trie (`ip_enrichment_dict`)
//! held 1.32 GiB and needed as much again during every reload. That old
//! dictionary still exists for compatibility, but nano never reads or reloads
//! it: a reload would load the 1.32 GiB trie back into memory.
//!
//! ONE GENERATION (NAN-4957 review): both dictionaries have `LIFETIME(0)` and
//! are only reloaded together by [`reload_pair`], attrs first. Before the
//! reload the history view appends the staging combinations the trie is about
//! to load, so the attrs dictionary always covers BOTH the trie still serving
//! and the trie being loaded. A trie reload that fails after the attrs reload
//! therefore keeps the old trie fully resolvable (never empty geo); the next
//! [`reload_pair`] (or [`reload_if_stale`] on the platform feed reconcile tick)
//! retries it.
//!
//! Every reader must use [`geo_attr_expr`] (or the identical form in
//! `scripts/gen-ocsf-ddl.py` and migration 185), so on-demand lookups match
//! ingest-time enrichment exactly.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use clickhouse::Row;
use serde::Deserialize;

/// IP_TRIE: network -> geo_id.
pub const IP_GEO_TRIE_DICT: &str = "nanosiem.ip_geo_trie_dict";
/// HASHED: geo_id -> country, country_code, continent, continent_code, asn,
/// as_name, as_domain.
pub const IP_GEO_ATTRS_DICT: &str = "nanosiem.ip_geo_attrs_dict";
/// Attribute combinations of recent staging generations (30-day TTL).
pub const IP_GEO_HISTORY_TABLE: &str = "nanosiem.ip_geo_attrs_history";
/// APPEND refreshable view that records the staging combinations.
pub const IP_GEO_HISTORY_REFRESH: &str = "nanosiem.ip_geo_attrs_history_refresh";
/// The refreshable view that fills the staging table both dictionaries read.
pub const IP_STAGING_REFRESH: &str = "nanosiem.ip_enrichment_dict_refresh";

/// The dictionaries in reload order: attrs (the superset) before the trie.
pub const IP_GEO_DICTS: [&str; 2] = [IP_GEO_ATTRS_DICT, IP_GEO_TRIE_DICT];

/// Attempts per dictionary reload in [`reload_pair`].
const RELOAD_ATTEMPTS: u32 = 3;
/// Upper bound on waiting for a refreshable view.
const REFRESH_WAIT: Duration = Duration::from_secs(300);

/// The seven attributes [`IP_GEO_ATTRS_DICT`] serves.
pub const IP_GEO_ATTRIBUTES: [&str; 7] = [
    "country",
    "country_code",
    "continent",
    "continent_code",
    "asn",
    "as_name",
    "as_domain",
];

/// ClickHouse expression for one geo attribute of the IP in `ip` (a String
/// expression). Returns '' for an empty IP, an IP no network covers, or an
/// unknown geo_id, exactly like the former single `ip_enrichment_dict`
/// lookup. IPv4 and IPv6 are keyed separately, as before.
pub fn geo_attr_expr(attr: &str, ip: &str) -> String {
    format!(
        "if({ip} != '', dictGetOrDefault('{IP_GEO_ATTRS_DICT}', '{attr}', if(isIPv4String({ip}), \
         dictGetOrDefault('{IP_GEO_TRIE_DICT}', 'geo_id', toIPv4OrDefault({ip}), toUInt64(0)), \
         dictGetOrDefault('{IP_GEO_TRIE_DICT}', 'geo_id', toIPv6OrDefault({ip}), toUInt64(0))), ''), '')"
    )
}

/// `SYSTEM RELOAD DICTIONARY` statements for the geo dictionaries, in
/// [`IP_GEO_DICTS`] order. `on_cluster` is the caller's ` ON CLUSTER '…'`
/// clause, or empty on a single node.
pub fn reload_statements(on_cluster: &str) -> Vec<String> {
    IP_GEO_DICTS
        .iter()
        .map(|dict| format!("SYSTEM RELOAD DICTIONARY{on_cluster} {dict}"))
        .collect()
}

/// A node-local `SYSTEM REFRESH VIEW` statement for one qualified view.
///
/// ClickHouse does not accept `ON CLUSTER` for this command. Clustered callers
/// must execute this statement once per shard instead.
pub fn refresh_view_statement(view: &str) -> String {
    format!("SYSTEM REFRESH VIEW {view}")
}

fn refresh_endpoints(value: &str) -> Result<Vec<String>> {
    let mut endpoints = Vec::new();
    for endpoint in value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
            bail!("invalid ClickHouse shard HTTP endpoint")
        }
        if !endpoints.iter().any(|existing| existing == endpoint) {
            endpoints.push(endpoint.to_string());
        }
    }
    if endpoints.is_empty() {
        bail!("clustered view refresh requires ClickHouse shard HTTP endpoints")
    }
    Ok(endpoints)
}

fn clustered_refresh_clients(on_cluster: &str) -> Result<Option<Vec<clickhouse::Client>>> {
    if on_cluster.is_empty() {
        return Ok(None);
    }

    let endpoints = refresh_endpoints(
        &std::env::var("VECTOR_CLICKHOUSE_SHARD_ENDPOINTS")
            .context("VECTOR_CLICKHOUSE_SHARD_ENDPOINTS is required for clustered view refresh")?,
    )?;
    let runtime_user = std::env::var("CLICKHOUSE_USER").unwrap_or_else(|_| "nanosiem".into());
    let runtime_password = std::env::var("CLICKHOUSE_PASSWORD").unwrap_or_default();
    let (user, password) = match (
        std::env::var("CLICKHOUSE_ADMIN_USER").ok(),
        std::env::var("CLICKHOUSE_ADMIN_PASSWORD").ok(),
    ) {
        (Some(user), Some(password)) => (user, password),
        _ => (runtime_user, runtime_password),
    };
    let database = std::env::var("CLICKHOUSE_DATABASE").unwrap_or_else(|_| "nanosiem".into());
    Ok(Some(
        endpoints
            .into_iter()
            .map(|endpoint| {
                let mut client = crate::db::clickhouse_transport::client()
                    .with_url(endpoint)
                    .with_database(&database)
                    .with_user(&user);
                if !password.is_empty() {
                    client = client.with_password(&password);
                }
                client
            })
            .collect(),
    ))
}

#[derive(Debug, Row, Deserialize)]
struct RefreshRow {
    replicas: u64,
    done: u64,
    failed: u64,
    error: String,
}

/// `SYSTEM REFRESH VIEW` (ON CLUSTER when clustered) and wait until every
/// replica finished a refresh started after the trigger. `ch_admin` must hold
/// the REFRESH VIEW grant (the runtime user does not).
pub async fn refresh_view_and_wait(
    ch_admin: &clickhouse::Client,
    view: &str,
    on_cluster: &str,
) -> Result<()> {
    let started: u32 = ch_admin.query("SELECT toUInt32(now())").fetch_one().await?;
    let statement = refresh_view_statement(view);
    if let Some(clients) = clustered_refresh_clients(on_cluster)? {
        for client in clients {
            client
                .query(&statement)
                .execute()
                .await
                .with_context(|| format!("refreshing {view} on a ClickHouse shard"))?;
        }
    } else {
        ch_admin.query(&statement).execute().await?;
    }
    let source = crate::platform_enrichment::loader::refresh_status_source(
        std::env::var("CLICKHOUSE_CLUSTER").ok().as_deref(),
    );
    let (db, name) = view.split_once('.').context("qualified view name")?;
    let probe = crate::platform_enrichment::loader::refresh_probe_sql(&source, db, name);
    let deadline = tokio::time::Instant::now() + REFRESH_WAIT;
    loop {
        let row: RefreshRow = ch_admin
            .query(&probe)
            .bind(started)
            .bind(started)
            .fetch_one()
            .await?;
        if row.failed > 0 {
            bail!(
                "{view}: refresh failed on {} replica(s): {}",
                row.failed,
                row.error
            );
        }
        if row.replicas > 0 && row.done == row.replicas {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            bail!(
                "{view}: refresh did not finish within {}s",
                REFRESH_WAIT.as_secs()
            );
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

async fn reload_with_retry(ch: &clickhouse::Client, sql: &str) -> Result<()> {
    let mut last = None;
    for attempt in 1..=RELOAD_ATTEMPTS {
        match ch.query(sql).execute().await {
            Ok(()) => return Ok(()),
            Err(error) => {
                tracing::warn!(attempt, %error, sql, "IP geo dictionary reload failed");
                last = Some(error);
                if attempt < RELOAD_ATTEMPTS {
                    tokio::time::sleep(Duration::from_secs(2 * u64::from(attempt))).await;
                }
            }
        }
    }
    Err(last.expect("at least one attempt")).with_context(|| sql.to_string())
}

/// Reload both geo dictionaries as one generation: record the staging
/// combinations in the history table, reload the attrs dictionary (now a
/// superset of what the serving trie and the new trie need), then the trie.
/// Each reload is retried; a failure is returned, and leaves the pair
/// consistent (see the module docs). `ch_admin` runs the history refresh.
pub async fn reload_pair(
    ch_admin: &clickhouse::Client,
    ch: &clickhouse::Client,
    on_cluster: &str,
) -> Result<()> {
    refresh_view_and_wait(ch_admin, IP_GEO_HISTORY_REFRESH, on_cluster).await?;
    reload_pair_dictionaries(ch, on_cluster).await
}

/// Reload the already-refreshed geo dictionary generation without refreshing
/// either view again. Durable migration activation uses this after its refresh
/// phase so a reload-only retry cannot create a newer staging generation.
pub async fn reload_pair_dictionaries(ch: &clickhouse::Client, on_cluster: &str) -> Result<()> {
    for sql in reload_statements(on_cluster) {
        reload_with_retry(ch, &sql).await?;
    }
    Ok(())
}

#[derive(Debug, Row, Deserialize)]
struct StaleRow {
    trie_status: String,
    trie_exception: String,
    trie_loaded_at: u32,
    staging_refreshed_at: u32,
}

/// Node-local probe: whether the trie is loaded but older than the last
/// staging refresh, or carries a load error. A NOT_LOADED trie is left alone:
/// its first lookup loads it (and the attrs dictionary) from the current
/// staging, which is consistent by construction.
pub const STALE_PROBE_SQL: &str = "SELECT \
       anyIf(toString(status), name = 'ip_geo_trie_dict') AS trie_status, \
       anyIf(last_exception, name = 'ip_geo_trie_dict') AS trie_exception, \
       toUInt32(anyIf(last_successful_update_time, name = 'ip_geo_trie_dict')) AS trie_loaded_at, \
       toUInt32(ifNull((SELECT max(last_success_time) FROM system.view_refreshes \
                        WHERE database = 'nanosiem' AND view = 'ip_enrichment_dict_refresh'), 0)) AS staging_refreshed_at \
     FROM system.dictionaries WHERE database = 'nanosiem'";

/// Decide from a [`STALE_PROBE_SQL`] row whether the pair needs a reload.
pub fn needs_reload(
    trie_status: &str,
    trie_exception: &str,
    trie_loaded_at: u32,
    staging_refreshed_at: u32,
) -> bool {
    if trie_status.starts_with("NOT_LOADED") || trie_status.is_empty() {
        return false;
    }
    !trie_exception.is_empty()
        || trie_status.starts_with("FAILED")
        || staging_refreshed_at > trie_loaded_at
}

/// Reload the pair when the staging table changed after the trie loaded (the
/// dictionaries have no LIFETIME of their own) or the trie carries a load
/// error. Returns whether a reload ran. Called on the leader's platform feed
/// reconcile tick.
pub async fn reload_if_stale(
    ch_admin: &clickhouse::Client,
    ch: &clickhouse::Client,
    on_cluster: &str,
) -> Result<bool> {
    let row: StaleRow = ch_admin.query(STALE_PROBE_SQL).fetch_one().await?;
    if !needs_reload(
        &row.trie_status,
        &row.trie_exception,
        row.trie_loaded_at,
        row.staging_refreshed_at,
    ) {
        return Ok(false);
    }
    reload_pair(ch_admin, ch, on_cluster).await?;
    Ok(true)
}

#[cfg(test)]
#[path = "ip_geo_tests.rs"]
mod tests;
