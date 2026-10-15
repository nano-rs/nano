// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded internal nPL reads used by product views on the primary lake lane.
//!
//! Storage coordinates remain worker-side. Every call is tenant pinned,
//! snapshot fenced by the worker assignment, and carries the caller's source
//! deny-set. Callers must construct queries from exact canonical schema fields.

use super::*;
use crate::auth::ScopeSet;

const MAX_LAKE_VIEW_PAGE_ROWS: usize = 50_000;
const MAX_LEGACY_LAKE_VIEW_OFFSET: usize = 1_000_000;

fn cursor_value<'a>(row: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    row.get(path)
        .or_else(|| path.split('.').try_fold(row, |value, part| value.get(part)))
}

fn cursor_time(value: &str) -> Result<chrono::DateTime<chrono::Utc>, SearchError> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&chrono::Utc))
        .or_else(|_| {
            chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S%.f")
                .map(|value| value.and_utc())
        })
        .map_err(|_| {
            SearchError::SqlValidationError(
                "lake product page returned an invalid OCSF event time".to_string(),
            )
        })
}

pub(crate) fn lake_product_cursor(
    row: &serde_json::Value,
) -> Result<ProductViewCursor, SearchError> {
    let time = cursor_value(row, "time")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            SearchError::SqlValidationError(
                "lake product page cannot continue because an event has no OCSF time".to_string(),
            )
        })?;
    let event_uid = cursor_value(row, "metadata.uid")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            SearchError::SqlValidationError(
                "lake product page cannot continue because an event has no metadata.uid"
                    .to_string(),
            )
        })?;
    if event_uid.len() > 2_048 || event_uid.chars().any(char::is_control) {
        return Err(SearchError::SqlValidationError(
            "lake product page returned an invalid metadata.uid".to_string(),
        ));
    }
    Ok(ProductViewCursor {
        time: cursor_time(time)?,
        event_uid: event_uid.to_string(),
    })
}

impl SearchService {
    pub(crate) async fn execute_lake_view_query(
        &self,
        query: String,
        time_range: &TimeRange,
        scope: &ScopeSet,
        view: &str,
        limit: usize,
    ) -> Result<SearchResponse, SearchError> {
        self.execute_lake_view_query_page(query, time_range, scope, view, limit, 0)
            .await
    }

    pub(crate) async fn execute_lake_view_query_page(
        &self,
        query: String,
        time_range: &TimeRange,
        scope: &ScopeSet,
        view: &str,
        limit: usize,
        offset: usize,
    ) -> Result<SearchResponse, SearchError> {
        self.execute_lake_view_query_cursor_page(
            query, time_range, scope, view, limit, offset, None,
        )
        .await
    }

    pub(crate) async fn execute_lake_view_query_cursor_page(
        &self,
        query: String,
        time_range: &TimeRange,
        scope: &ScopeSet,
        view: &str,
        limit: usize,
        offset: usize,
        cursor: Option<&ProductViewCursor>,
    ) -> Result<SearchResponse, SearchError> {
        self.execute_lake_view_request(query, time_range, scope, view, limit, offset, cursor, false)
            .await
    }

    /// NAN-3094: a view page whose query names every column it needs (in an
    /// `eval`), requested with `table_view` so the lake projects exactly those
    /// columns while keeping the query's newest-first event order.
    pub(crate) async fn execute_lake_view_query_cursor_page_projected(
        &self,
        query: String,
        time_range: &TimeRange,
        scope: &ScopeSet,
        view: &str,
        limit: usize,
        offset: usize,
        cursor: Option<&ProductViewCursor>,
    ) -> Result<SearchResponse, SearchError> {
        self.execute_lake_view_request(query, time_range, scope, view, limit, offset, cursor, true)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_lake_view_request(
        &self,
        query: String,
        time_range: &TimeRange,
        scope: &ScopeSet,
        view: &str,
        limit: usize,
        offset: usize,
        cursor: Option<&ProductViewCursor>,
        table_view: bool,
    ) -> Result<SearchResponse, SearchError> {
        if limit == 0 || limit > MAX_LAKE_VIEW_PAGE_ROWS {
            return Err(SearchError::SqlValidationError(
                "internal lake view query limit must be between 1 and 50000".to_string(),
            ));
        }
        if offset.saturating_add(limit) > MAX_LEGACY_LAKE_VIEW_OFFSET {
            return Err(SearchError::ResourceExhausted(
                "legacy lake view offset exceeded 1000000 rows; use the stable continuation cursor"
                    .to_string(),
            ));
        }
        if view.is_empty()
            || view.len() > 32
            || !view
                .chars()
                .all(|character| character.is_ascii_lowercase() || character == '-')
        {
            return Err(SearchError::SqlValidationError(
                "internal lake view name is invalid".to_string(),
            ));
        }
        let client = self.lake_query.client.as_ref().ok_or_else(|| {
            SearchError::SqlValidationError(
                "lake query backend is enabled without a worker client".to_string(),
            )
        })?;
        let request_id = format!("{view}-{}", uuid::Uuid::now_v7());
        let request = SearchRequest {
            query,
            time_range: TimeRangeInput::new(time_range.start, time_range.end),
            limit: Some(limit),
            offset: Some(offset),
            include_sql: Some(false),
            skip_histogram: true,
            skip_field_stats: true,
            use_cache: true,
            table_view,
            request_id: Some(request_id.clone()),
            async_mode: false,
            priority: Some("interactive".to_string()),
            dataset: Some("logs".to_string()),
        };
        if let Some(cursor) = cursor {
            client
                .search_product_page(&request, &request_id, scope.deny_set(), cursor)
                .await
        } else {
            client
                .search(&request, &request_id, None, scope.deny_set())
                .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn product_cursor_round_trips_ocsf_time_and_uid() {
        let cursor = lake_product_cursor(&json!({
            "time": "2026-08-15 12:34:56.123456",
            "metadata.uid": "event-0002",
        }))
        .expect("valid cursor");
        assert_eq!(cursor.event_uid, "event-0002");

        let encoded = serde_json::to_value(&cursor).expect("serialize cursor");
        assert_eq!(encoded["time"], "2026-08-15T12:34:56.123456Z");
    }

    #[test]
    fn product_cursor_requires_the_canonical_event_uid() {
        let error = lake_product_cursor(&json!({
            "time": "2026-08-15T12:34:56Z",
            "metadata": {"uid": ""},
        }))
        .expect_err("empty uid cannot page exactly");
        assert!(error.to_string().contains("metadata.uid"));
    }
}
