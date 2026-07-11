// SPDX-License-Identifier: AGPL-3.0-or-later

//! Query management: cancellation, progress tracking, and quick counts
//!
//! Methods for monitoring and controlling running ClickHouse queries.

use tracing::{debug, info};

use super::sql_helpers::escape_question_marks_in_strings;
use super::types::ClickHouseExecutor;
use crate::db::dual_pool::on_cluster_clause;
use crate::search::{parse_clickhouse_error, SearchError};
use crate::sql_hygiene::escape_sql_string;

/// NAN-1728 (H2): the ClickHouse cluster name for `clusterAllReplicas(...)`
/// wrapping of `system.processes`, or `None` on single-node / open-core.
///
/// `KILL QUERY` and `system.processes` are **node-local** — they only see
/// queries initiated on the connected node. On a cluster the cancel/progress
/// connection is LB'd and can land on a different node than the search's
/// initiator, so the running-check finds 0 rows and progress reads `None`.
/// Reading env `CLICKHOUSE_CLUSTER` matches [`on_cluster_clause`]'s source (the
/// deploy sets it only on clustered ClickHouse); when unset/empty every query
/// below emits the exact pre-cluster `system.processes` SQL — a pure no-op.
fn cluster_name() -> Option<String> {
    std::env::var("CLICKHOUSE_CLUSTER")
        .ok()
        .map(|c| c.trim().to_string())
        .filter(|c| !c.is_empty())
}

/// The `system.processes` source expression: `clusterAllReplicas('<cluster>',
/// system.processes)` in cluster mode (sees every replica), plain
/// `system.processes` on single-node (byte-identical to the pre-cluster form).
fn processes_source() -> String {
    match cluster_name() {
        Some(c) => format!(
            "clusterAllReplicas('{}', system.processes)",
            escape_sql_string(&c)
        ),
        None => "system.processes".to_string(),
    }
}

impl ClickHouseExecutor {
    /// Cancel a running query by its query_id
    ///
    /// Returns true if a query was found and killed, false if no matching query was running.
    /// Uses KILL QUERY SYNC to wait for the query to actually stop.
    pub async fn cancel_query(&self, query_id: &str) -> Result<bool, SearchError> {
        let ids = [query_id.to_string()];
        self.cancel_queries(&ids).await
    }

    /// Cancel a set of running queries by their EXACT query_ids in one round trip.
    ///
    /// NAN-1428: one search fans out to a data query plus derived companions
    /// (`{id}-count` / `{id}-hist` / `{id}-fstats`); cancel must kill all of
    /// them. Exact-match `IN` is used deliberately instead of a
    /// `LIKE '{id}%'` pattern — client-provided request ids can legitimately
    /// contain `%`/`_`, which would wildcard a LIKE and kill unrelated queries.
    ///
    /// Returns true if at least one of the queries was found running and killed.
    pub async fn cancel_queries(&self, query_ids: &[String]) -> Result<bool, SearchError> {
        if query_ids.is_empty() {
            return Ok(false);
        }

        // Escape single quotes in each id to prevent SQL injection
        let id_list = query_ids
            .iter()
            .map(|id| format!("'{}'", escape_sql_string(id)))
            .collect::<Vec<_>>()
            .join(", ");

        // Check if any of the queries are still running. NAN-1728 (H2): read
        // cluster-wide so the check finds the query wherever its initiator
        // landed — otherwise a check on the wrong node returns 0 and the KILL
        // below is skipped, leaving a runaway hunt un-cancellable from the UI.
        let check_sql = format!(
            "SELECT count() as cnt FROM {} WHERE query_id IN ({})",
            processes_source(),
            id_list
        );

        debug!("Checking if queries are running: {}", check_sql);

        let mut cursor = self
            .client
            .query(&check_sql)
            .fetch_bytes("JSONEachRow")
            .map_err(|e| parse_clickhouse_error(&e.to_string()))?;

        let mut response_bytes = Vec::new();
        // Propagate a mid-stream Err instead of treating it as EOF — a failed
        // check would otherwise read as "not running" and silently skip the KILL.
        loop {
            match cursor.next().await {
                Ok(Some(chunk)) => response_bytes.extend_from_slice(&chunk),
                Ok(None) => break,
                Err(e) => return Err(parse_clickhouse_error(&e.to_string())),
            }
        }

        let response_str = String::from_utf8(response_bytes).map_err(|e| {
            SearchError::DatabaseError(sqlx::Error::Protocol(format!(
                "Invalid UTF-8 in cancel check response: {}",
                e
            )))
        })?;

        let running_count = response_str
            .lines()
            .next()
            .and_then(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .and_then(|v| v.get("cnt")?.as_u64())
            .unwrap_or(0);

        if running_count == 0 {
            debug!("None of the queries {:?} are running", query_ids);
            return Ok(false);
        }

        // Kill all matching queries synchronously. NAN-1728 (H2): `on_cluster_clause`
        // splices ` ON CLUSTER `<name>`` on a cluster so the kill fans out to every
        // node (the initiator may be a different node than this connection); it is
        // an empty string on single-node, so the emitted SQL is byte-identical to
        // the pre-cluster `KILL QUERY WHERE … SYNC`.
        let kill_sql = format!(
            "KILL QUERY{} WHERE query_id IN ({}) SYNC",
            on_cluster_clause(),
            id_list
        );
        info!("Killing {} running queries: {}", running_count, kill_sql);

        self.client
            .query(&kill_sql)
            .execute()
            .await
            .map_err(|e| parse_clickhouse_error(&e.to_string()))?;

        info!("Successfully killed queries {:?}", query_ids);
        Ok(true)
    }

    /// Get progress of a running query from system.processes
    ///
    /// Returns progress info if the query is found and running, None otherwise.
    pub async fn get_query_progress(
        &self,
        query_id: &str,
    ) -> Result<Option<crate::search::jobs::SearchJobProgress>, SearchError> {
        // Escape single quotes in the query_id to prevent SQL injection
        let escaped_id = escape_sql_string(query_id);

        // NAN-1728 (H2): read cluster-wide so progress is found regardless of
        // which node the search initiated on. `clusterAllReplicas` returns 0 rows
        // when the query isn't running anywhere (identical None semantics to the
        // single-node path, which reads plain `system.processes`); when it is
        // running, the initiator row carries the distributed query's aggregated
        // progress and is taken first below.
        let sql = format!(
            "SELECT read_rows, total_rows_approx, elapsed FROM {} WHERE query_id = '{}'",
            processes_source(),
            escaped_id
        );

        debug!("Getting query progress: {}", sql);

        let mut cursor = self
            .client
            .query(&sql)
            .fetch_bytes("JSONEachRow")
            .map_err(|e| parse_clickhouse_error(&e.to_string()))?;

        let mut response_bytes = Vec::new();
        while let Ok(Some(chunk)) = cursor.next().await {
            response_bytes.extend_from_slice(&chunk);
        }

        let response_str = String::from_utf8(response_bytes).map_err(|e| {
            SearchError::DatabaseError(sqlx::Error::Protocol(format!(
                "Invalid UTF-8 in progress response: {}",
                e
            )))
        })?;

        // Parse the first line of JSON response
        if let Some(line) = response_str.lines().next() {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                let rows_scanned = v.get("read_rows").and_then(|v| v.as_u64()).unwrap_or(0);
                let rows_total = v
                    .get("total_rows_approx")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let elapsed_secs = v.get("elapsed").and_then(|v| v.as_f64()).unwrap_or(0.0);

                // Calculate percentage (avoid division by zero)
                let percent = if rows_total > 0 {
                    ((rows_scanned as f64 / rows_total as f64) * 100.0).min(100.0) as u8
                } else {
                    0
                };

                return Ok(Some(crate::search::jobs::SearchJobProgress {
                    rows_scanned,
                    rows_total,
                    percent,
                    elapsed_ms: (elapsed_secs * 1000.0) as u64,
                }));
            }
        }

        // Query not found or no results
        Ok(None)
    }

    /// Quick count query to estimate dataset size for sampling decisions
    /// Returns approximate count, or 0 on error
    ///
    /// NAN-1428: `query_id` / `settings` tag the streaming path's count
    /// companion (`{request_id}-count`) so cancel kills it and per-priority
    /// limits bound it.
    pub async fn quick_count(
        &self,
        base_sql: &str,
        query_id: Option<&str>,
        settings: Option<&crate::search::admission::ClickHouseQuerySettings>,
    ) -> Result<u64, SearchError> {
        // NAN-1635 (finding 3.4): wrap structurally instead of regex-slicing
        // FROM/WHERE out of the SQL. The old slicing grabbed the first ` FROM `
        // (stage_0's, inside the WITH) for every piped/CTE streamable query and
        // emitted unbalanced-parenthesis SQL — ClickHouse Code 62 on every
        // `error | where …` stream — and the caller swallowed the error, so
        // total_count silently reported the delivered row count. Same fix as
        // NAN-1159/1160 on the paginated count path. The caller regenerates the
        // input with `limit: None` + `unordered`, so the wrap counts the full
        // match set with no top-N sort.
        let count_sql = super::sql_helpers::wrap_query_for_count(base_sql);
        debug!("Quick count SQL: {}", count_sql);

        let escaped_sql = escape_question_marks_in_strings(&count_sql);
        let result =
            super::types::with_query_options(self.client.query(&escaped_sql), query_id, settings)
                .fetch_one::<u64>()
                .await
                .map_err(|e| parse_clickhouse_error(&e.to_string()))?;

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_string_contains, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn exact_batch_cancellation_checks_and_kills_all_owned_ids() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_string_contains("SELECT count()"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw("{\"cnt\":2}\n", "application/json"),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(body_string_contains("KILL QUERY"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let executor = ClickHouseExecutor::new(
            clickhouse::Client::default()
                .with_url(server.uri())
                .with_compression(clickhouse::Compression::None),
        );
        let ids = vec![
            "tuning-validation-original-0".to_string(),
            "tuning-validation-proposed-0".to_string(),
        ];
        assert!(executor.cancel_queries(&ids).await.expect("cancel queries"));

        let requests = server.received_requests().await.expect("recorded requests");
        assert_eq!(
            requests.len(),
            2,
            "one running check and one synchronous kill"
        );
        let bodies = requests
            .iter()
            .map(|request| String::from_utf8_lossy(&request.body).to_string())
            .collect::<Vec<_>>()
            .join("\n");
        for id in ids {
            assert!(bodies.contains(&id), "missing exact query id {id}");
        }
        assert!(bodies.contains("KILL QUERY"));
        assert!(bodies.contains(" SYNC"));
    }
}
