// SPDX-License-Identifier: AGPL-3.0-or-later

//! Types and structs for the ClickHouse executor
//!
//! Contains the `ClickHouseLogReadRow` struct for typed query results,
//! the column list constant, and the `ClickHouseExecutor` struct definition.

use clickhouse::Row;
use serde::Deserialize;

/// Row type for reading log data from ClickHouse.
///
/// NAN-1034: the three time-column fields use `#[serde(rename = "..._micros")]` so the
/// SQL aliases (`ts_micros`, `ingest_time_micros`, `enrich_time_micros`) do NOT shadow
/// the underlying DateTime64 columns. When the alias matches the column name,
/// ClickHouse's optimizer substitutes the alias expression back into the WHERE clause
/// (`WHERE timestamp BETWEEN '...string...'` → `WHERE toUnixTimestamp64Micro(timestamp)
/// BETWEEN '...string...'` → Code 53 Int64-vs-String type mismatch). Rust field names
/// stay `timestamp`/`ingest_time`/`enrich_time` so `clickhouse_row_to_json` keeps the
/// same JSON output keys and downstream consumers don't notice.
#[derive(Debug, Clone, Row, Deserialize)]
pub struct ClickHouseLogReadRow {
    pub id: String,
    #[serde(rename = "ts_micros")]
    pub timestamp: i64, // Microseconds since epoch for DateTime64(6)
    pub message: String,
    pub metadata: String,
    pub source_type: String,
    pub src_ip: String,
    pub dest_ip: String,
    pub src_host: String,
    pub dest_host: String,
    pub src_port: u16,
    pub dest_port: u16,
    pub protocol: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub user: String,
    pub action: String,
    pub status: String,
    pub auth_type: String,
    pub auth_result: String,
    pub session_id: String,
    pub process_name: String,
    pub process_id: u32,
    /// Full command line (command_line = path + exe + args)
    pub command_line: String,
    /// Parent exe filename only
    pub parent_process_name: String,
    /// Full parent command line (parent_command_line = path + exe + args)
    pub parent_command_line: String,
    pub file_path: String,
    pub file_name: String,
    pub file_hash: String,
    pub file_action: String,
    pub user_agent: String,
    pub enriched_src_country: String,
    pub enriched_src_country_code: String,
    pub enriched_src_continent: String,
    pub enriched_src_continent_code: String,
    pub enriched_src_asn: String,
    pub enriched_src_as_name: String,
    pub enriched_src_as_domain: String,
    pub enriched_dest_country: String,
    pub enriched_dest_country_code: String,
    pub enriched_dest_continent: String,
    pub enriched_dest_continent_code: String,
    pub enriched_dest_asn: String,
    pub enriched_dest_as_name: String,
    pub enriched_dest_as_domain: String,
    #[serde(rename = "ingest_time_micros")]
    pub ingest_time: i64, // Microseconds since epoch for DateTime64(6)
    #[serde(rename = "enrich_time_micros")]
    pub enrich_time: i64, // 0 if not enriched, microseconds since epoch otherwise
    pub ext: String,      // JSON string containing extended fields (non-explicit UDM fields)
}

/// Columns to SELECT for ClickHouseLogReadRow struct.
/// Must match the struct fields exactly (including serde renames) to avoid deserialization errors.
///
/// NAN-1034: the three time aliases use `_micros` suffixes to avoid colliding with the
/// underlying column names. See `ClickHouseLogReadRow` docs for why.
pub(crate) const CLICKHOUSE_LOG_COLUMNS: &str = "id, toUnixTimestamp64Micro(timestamp) as ts_micros, message, metadata, source_type, \
    src_ip, dest_ip, src_host, dest_host, src_port, dest_port, protocol, bytes_in, bytes_out, \
    user, action, status, auth_type, auth_result, session_id, \
    process_name, process_id, command_line, parent_process_name, parent_command_line, \
    file_path, file_name, file_hash, file_action, user_agent, \
    enriched_src_country, enriched_src_country_code, enriched_src_continent, enriched_src_continent_code, \
    enriched_src_asn, enriched_src_as_name, enriched_src_as_domain, \
    enriched_dest_country, enriched_dest_country_code, enriched_dest_continent, enriched_dest_continent_code, \
    enriched_dest_asn, enriched_dest_as_name, enriched_dest_as_domain, \
    toUnixTimestamp64Micro(ingest_time) as ingest_time_micros, toUnixTimestamp64Micro(enrich_time) as enrich_time_micros, \
    toString(ext) as ext";

/// ClickHouse query executor
#[derive(Clone)]
pub struct ClickHouseExecutor {
    pub(crate) client: clickhouse::Client,
    /// NAN-5565: lift `max_query_size` for query text that needs it. Off by
    /// default (raw SQL and every other caller keep ClickHouse's default);
    /// on only for an executor from [`Self::for_generated_sql`].
    lift_max_query_size: bool,
    /// NAN-5565: the caller's answer to "is this an aggregation?" for the
    /// paginated paths, instead of sniffing the SQL text. Generated SQL can
    /// inline event-derived literals (prevalence rescue keys), and a literal
    /// such as `sum(` must not flip a raw query into the full-window
    /// `count(*) OVER ()` path.
    aggregation_override: Option<bool>,
    /// NAN-5793: the caller's lowercased source-scope deny list, bound on
    /// every query as the server-side `nano_source_deny` parameter that
    /// hand-built SQL from `source_scope_bound_predicate` references. `None`
    /// (the default) binds nothing.
    source_deny: Option<Vec<String>>,
}

impl ClickHouseExecutor {
    /// Create a new ClickHouse executor
    pub fn new(client: clickhouse::Client) -> Self {
        Self {
            client,
            lift_max_query_size: false,
            aggregation_override: None,
            source_deny: None,
        }
    }

    /// NAN-5565: this executor for SQL the application generated itself:
    /// `max_query_size` is lifted when the text needs it, and `aggregation`
    /// (decided by the caller on the literal-free SQL) replaces the text
    /// sniffing.
    pub(crate) fn for_generated_sql(&self, aggregation: bool) -> Self {
        Self {
            client: self.client.clone(),
            lift_max_query_size: true,
            aggregation_override: Some(aggregation),
            source_deny: self.source_deny.clone(),
        }
    }

    /// NAN-5793: this executor binding `deny_set` as the source-scope
    /// parameter on every query, for hand-built SQL carrying
    /// `source_scope_bound_predicate`. An empty set binds nothing.
    pub(crate) fn with_source_scope(&self, deny_set: &std::collections::BTreeSet<String>) -> Self {
        Self {
            source_deny: crate::search::service::source_scope_param_values(deny_set),
            ..self.clone()
        }
    }

    /// This executor with the caller's answer to "is this an aggregation?"
    /// (decided on the query AST) in place of sniffing the SQL text; every
    /// other setting is kept. NAN-5634: a `join` over a `stats` subsearch
    /// carries `count(` in its text but returns raw rows.
    pub(crate) fn with_aggregation(&self, aggregation: bool) -> Self {
        Self {
            aggregation_override: Some(aggregation),
            ..self.clone()
        }
    }

    /// Whether the paginated paths treat `sql` as an aggregation.
    pub(crate) fn is_aggregation(&self, sql: &str) -> bool {
        self.aggregation_override
            .unwrap_or_else(|| super::sql_helpers::is_aggregation_query(sql))
    }

    /// Start a query for `sql`. For a generated-SQL executor
    /// ([`Self::for_generated_sql`]) whose text needs it, the query carries a
    /// lifted `max_query_size` (NAN-5565).
    ///
    /// Every query the executor builds starts here (a source guard test pins
    /// that), so the data query, its count companion, the pagination wrappers
    /// and streaming all carry the same limit.
    pub(crate) fn sized_query(&self, sql: &str) -> clickhouse::query::Query {
        let mut query = self.client.query(sql);
        if let Some(deny) = &self.source_deny {
            query = query.param(crate::search::service::SOURCE_SCOPE_DENY_PARAM, deny);
        }
        if !self.lift_max_query_size {
            return query;
        }
        match max_query_size_for(sql.len()) {
            Some(limit) => query.with_setting("max_query_size", limit.to_string()),
            None => query,
        }
    }
}

/// ClickHouse's default `max_query_size`: the bytes of query TEXT its parser
/// accepts. The deploy profiles do not override or constrain it.
pub(crate) const CLICKHOUSE_DEFAULT_MAX_QUERY_SIZE: usize = 262_144;

/// Upper bound the executor lifts `max_query_size` to (NAN-5565). Generated
/// SQL inlines bounded literal sets (the prevalence rescue: at most
/// `PREVALENCE_RESCUE_MAX_ARTIFACTS` keys per entity type), which measured
/// under 20 MiB at their caps; anything larger fails with ClickHouse code 62,
/// which `parse_clickhouse_error` classifies as a size failure.
pub(crate) const MAX_QUERY_SIZE_CEILING: usize = 64 * 1024 * 1024;

/// The `max_query_size` to send for a query of `sql_len` bytes: `None` (send
/// nothing, the request stays byte-identical) while the text is safely under
/// the default, otherwise the length plus 64 KiB headroom, capped at
/// [`MAX_QUERY_SIZE_CEILING`]. `sql_len` is measured before the client crate
/// un-escapes `??`, so it never under-counts the text sent.
pub(crate) fn max_query_size_for(sql_len: usize) -> Option<usize> {
    if sql_len + MAX_QUERY_SIZE_HEADROOM <= CLICKHOUSE_DEFAULT_MAX_QUERY_SIZE {
        return None;
    }
    Some((sql_len + MAX_QUERY_SIZE_HEADROOM).min(MAX_QUERY_SIZE_CEILING))
}

/// Headroom the lift adds over the text length.
pub(crate) const MAX_QUERY_SIZE_HEADROOM: usize = 64 * 1024;

/// Apply an optional query_id and optional per-priority settings to a query
/// builder (NAN-1428).
///
/// Companion queries (count / histogram / field-stats) carry a query_id
/// derived from the data query's id so `KILL QUERY` can terminate the whole
/// fan-out, and the same resolved `ClickHouseQuerySettings` so they are
/// bounded by per-priority admission limits instead of only the CH profile.
pub(crate) fn with_query_options(
    mut query: clickhouse::query::Query,
    query_id: Option<&str>,
    settings: Option<&crate::search::admission::ClickHouseQuerySettings>,
) -> clickhouse::query::Query {
    if let Some(id) = query_id {
        query = query.with_setting("query_id", id);
    }
    if let Some(s) = settings {
        query = query
            .with_setting("max_execution_time", &s.max_execution_time.to_string())
            .with_setting("max_threads", &s.max_threads.to_string())
            .with_setting("priority", &s.priority.to_string())
            .with_setting("queue_max_wait_ms", &s.queue_max_wait_ms.to_string());
        if let Some(max_memory_usage_bytes) = s.max_memory_usage_bytes {
            query = query.with_setting(
                "max_memory_usage",
                &max_memory_usage_bytes.to_string(),
            );
        }
    }
    query
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NAN-1034: the SELECT-list aliases for the three time columns must NOT match the
    /// underlying column names, or ClickHouse's optimizer substitutes the alias
    /// expression back into the WHERE clause and breaks `WHERE timestamp BETWEEN
    /// '...string...'` with `Code: 53. Cannot convert string ... to type Int64`.
    /// The dynamic fallback masked this in production but every typed-path query was
    /// silently re-running. Renaming the aliases is what prevents the shadow.
    #[test]
    fn log_columns_aliases_do_not_shadow_underlying_column_names() {
        let cols = CLICKHOUSE_LOG_COLUMNS;
        // The shadowing forms that triggered NAN-1034 must not be present.
        // Trailing comma forces an exact-token match so `ingest_time_micros` doesn't
        // false-positive on `ingest_time`.
        for forbidden in [
            "toUnixTimestamp64Micro(timestamp) as timestamp,",
            "toUnixTimestamp64Micro(ingest_time) as ingest_time,",
            "toUnixTimestamp64Micro(enrich_time) as enrich_time,",
        ] {
            assert!(
                !cols.contains(forbidden),
                "CLICKHOUSE_LOG_COLUMNS reintroduces the alias-shadows-column bug \
                 (NAN-1034) with `{forbidden}` — pick a distinct alias like \
                 `ts_micros`/`ingest_time_micros`/`enrich_time_micros` instead."
            );
        }
        // Sanity: the distinct aliases the fix introduced are still present.
        for required in [
            "as ts_micros,",
            "as ingest_time_micros,",
            "as enrich_time_micros,",
        ] {
            assert!(
                cols.contains(required),
                "CLICKHOUSE_LOG_COLUMNS missing expected alias `{required}` — the \
                 typed-query path will return the wrong column name and fail to \
                 deserialize into ClickHouseLogReadRow."
            );
        }
    }
}
