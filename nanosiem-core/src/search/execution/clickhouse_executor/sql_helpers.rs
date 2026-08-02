// SPDX-License-Identifier: AGPL-3.0-or-later

//! SQL helper functions for ClickHouse query manipulation
//!
//! Free functions for SQL analysis and transformation: aggregation detection,
//! LIMIT/OFFSET injection, COUNT query building, and question mark escaping.

/// Check if a SQL query is an aggregation query that needs all data
///
/// NAN-1691: prevalence *decoration* (`host_count`/`is_rare`/`prevalence_score`
/// columns from `| prevalence enrich=true`) is 1:1 row output, NOT an
/// aggregation — matching those tokens here forced the blocking `count(*)
/// OVER()` full-window wrap in the executor and OOMed the shared pod. When the
/// enrich pipeline actually aggregates (`… | stats …`) the pushed-down GROUP
/// BY / agg keyword below still trips this, so enrich-then-aggregate keeps the
/// full-scan path; enrich-only now paginates as a raw-event query.
pub(crate) fn is_aggregation_query(sql: &str) -> bool {
    let sql_upper = sql.to_uppercase();
    sql_upper.contains("GROUP BY")
        || sql_upper.contains("COUNT(")
        || sql_upper.contains("SUM(")
        || sql_upper.contains("AVG(")
        || sql_upper.contains("MIN(")
        || sql_upper.contains("MAX(")
        || sql_upper.contains("UNIQ(")
        || sql_upper.contains("QUANTILE(")
        || sql_upper.contains("TOPK(")
        || sql_upper.contains("ARGMAX(")
        || sql_upper.contains("ARGMIN(")
        || sql_upper.contains("MEDIAN(")
}

/// Inject LIMIT and OFFSET into a SQL query before the SETTINGS clause
/// This allows ClickHouse to stop reading early for non-aggregation queries
pub fn inject_limit_offset(sql: &str, limit: usize, offset: usize) -> String {
    // If the query already carries a LIMIT anywhere (a user `| head N`, a
    // subsearch cap inside a CTE, …), paginate structurally by wrapping it in
    // a subquery instead. Returning the SQL unchanged here (the pre-NAN-1410
    // behavior) silently dropped the offset — every page re-served page 1 —
    // and string-replacing a trailing LIMIT would corrupt the semantics of a
    // user-level `head` (pages past the head cap must be empty, and a LIMIT
    // inside a subquery/CTE must never be touched). The outer LIMIT/OFFSET
    // slices *within* whatever the inner query yields, which preserves those
    // semantics in every case.
    let sql_upper = sql.to_uppercase();
    if sql_upper.contains(" LIMIT ") {
        return wrap_query_with_pagination(sql, limit, offset);
    }

    // Find SETTINGS clause position (case-insensitive)
    if let Some(settings_pos) = sql_upper.find(" SETTINGS ") {
        // Insert LIMIT/OFFSET before SETTINGS
        let (before, after) = sql.split_at(settings_pos);
        format!("{} LIMIT {} OFFSET {}{}", before, limit, offset, after)
    } else {
        // No SETTINGS clause, append at end
        format!("{} LIMIT {} OFFSET {}", sql, limit, offset)
    }
}

/// Wrap a raw SQL query in a subquery and apply pagination at the outer level.
///
/// This is used for untrusted raw SQL input so LIMIT/OFFSET enforcement is
/// structural rather than string-appended onto the user query body.
pub fn wrap_query_with_pagination(sql: &str, limit: usize, offset: usize) -> String {
    format!(
        "SELECT * FROM ({}) AS subquery LIMIT {} OFFSET {}",
        sql, limit, offset
    )
}

/// Wrap a raw SQL query in a subquery and count the resulting rows.
///
/// This avoids brittle clause extraction from arbitrary user SQL.
pub fn wrap_query_for_count(sql: &str) -> String {
    format!("SELECT count(*) AS cnt FROM ({}) AS subquery", sql)
}

/// NAN-2277: whether raw user SQL carries the scalar-Map pattern that wedges
/// the CH >=26.4 planner (NAN-2274, upstream ClickHouse#113003): bloom_filter
/// index analysis over a large scalar-subquery Map has no cancellation point,
/// so the query becomes an unkillable 100%-CPU thread that only a server
/// restart clears. Generated pipeline SQL already carries `use_skip_indexes=0`
/// when it emits the map construct; raw SQL bypasses codegen, so the executor
/// applies the same guard off this check. Substring match is deliberately
/// broad: a false positive only costs skip-index pruning on one query (results
/// are identical), a false negative wedges a core.
pub(crate) fn raw_sql_needs_skip_index_guard(sql: &str) -> bool {
    sql.to_ascii_lowercase().contains("mapfromarrays(")
}

/// Bounded input for the paginated count companion (NAN-1635, finding 2.3).
///
/// The consumer clamps the reported total at `SearchConfig.max_limit`
/// (core_search.rs `total_count.min(max_limit)`), so when the WHERE carries
/// per-row filters the count scan can stop at `max_limit + 1` matches instead
/// of scanning the full match set (Saturn: 9.5x read_rows / 8.5x read_bytes on
/// a broad keyword). The bound is CONDITIONAL: a filter-free count is served
/// from part metadata and the bounded row-reading form measured 12.8x MORE
/// expensive — callers only supply this for filtered queries.
///
/// `sql` must be REGENERATED with `QueryOptions.unordered` (and the same
/// `limit: None` pagination contract as the data SQL) rather than
/// string-stripped: a trailing ORDER BY under the inner LIMIT is a semantic
/// top-N that ClickHouse cannot elide (and string surgery truncates
/// mid-literal — NAN-1160).
pub(crate) struct BoundedCountInput<'a> {
    /// ORDER-BY-free data SQL regenerated from the query AST.
    pub sql: &'a str,
    /// `SearchConfig.max_limit + 1` — one past the clamp so the consumer can
    /// still distinguish "exactly max_limit" from "more than max_limit".
    pub limit: usize,
}

/// Build a COUNT query from a data query by wrapping it in a counting subquery.
pub(crate) fn build_count_query(sql: &str, bounded: Option<BoundedCountInput>) -> String {
    // Always wrap the full query in a counting subquery rather than regex-slicing the
    // FROM/WHERE out of it.
    //
    // The old extraction regex grabbed the first `FROM <tbl>` and a non-greedy `.*?` that
    // stopped at the first whitespace-bounded `ORDER BY`/`SETTINGS` keyword — INCLUDING one
    // inside a string literal (e.g. `message iLike '%alpha order by beta%'`). That truncated
    // the WHERE clause mid-literal into unbalanced-quote SQL, the count query errored, and
    // total_count silently read 0 while the data rows looked fine. CTE queries already wrapped
    // (NAN-1159); the single-FROM literal-truncation case is NAN-1160.
    //
    // Wrapping is literal-safe and correct for both CTE and single-FROM queries. `sql` carries
    // no pagination LIMIT here: the generator no longer bakes the page-size limit into
    // executor-paginated SQL (NAN-1410 — baking it capped this count at the page size), and
    // LIMIT/OFFSET is injected separately into the data query, not the count input (see
    // paginated.rs). Any LIMIT still present is query semantics — a user `| head N` or a
    // subsearch cap — which legitimately bounds the total, so counting the wrapped result
    // yields the correct pre-pagination total.
    //
    // NAN-1635 (finding 2.3): with a bounded input, count over a `SELECT 1`
    // wrap capped one past the consumer's clamp — ClickHouse stops reading at
    // `limit` matched rows, and the SELECT 1 projection lets the planner prune
    // every inner column. Both forms clamp to the same reported total.
    match bounded {
        Some(b) => format!(
            "SELECT count(*) AS cnt FROM (SELECT 1 FROM ({}) AS matched LIMIT {}) AS subquery",
            b.sql, b.limit
        ),
        None => wrap_query_for_count(sql),
    }
}

/// Escape `?` characters within SQL string literals for the clickhouse-rs crate.
/// The crate uses `?` as parameter placeholders, so literal `?` in strings (e.g., regex patterns)
/// need to be escaped as `??`.
pub fn escape_question_marks_in_strings(sql: &str) -> String {
    let mut result = String::with_capacity(sql.len());
    let mut in_string = false;
    let mut chars = sql.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\'' && !in_string {
            // Start of string literal
            in_string = true;
            result.push(c);
        } else if c == '\'' && in_string {
            // Check for escaped quote ('')
            if chars.peek() == Some(&'\'') {
                result.push(c);
                result.push(chars.next().unwrap());
            } else {
                // End of string literal
                in_string = false;
                result.push(c);
            }
        } else if c == '?' && in_string {
            // Escape ? as ?? inside string literals
            result.push('?');
            result.push('?');
        } else {
            result.push(c);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NAN-2277: the raw-SQL wedge guard must catch the scalar-Map pattern in
    /// any casing and leave ordinary hunts untouched.
    #[test]
    fn skip_index_guard_matches_scalar_map_pattern_only() {
        assert!(raw_sql_needs_skip_index_guard(
            "WITH (SELECT mapFromArrays(groupArray(k), groupArray(v)) FROM t) AS m SELECT 1"
        ));
        assert!(raw_sql_needs_skip_index_guard("select MAPFROMARRAYS(a, b)"));
        assert!(!raw_sql_needs_skip_index_guard(
            "SELECT count() FROM logs WHERE src_ip = '10.0.0.1'"
        ));
        assert!(!raw_sql_needs_skip_index_guard(
            "SELECT map('a', 1) FROM logs"
        ));
    }

    /// NAN-1691 (P1-B): enrich-only prevalence decoration (host_count / is_rare /
    /// prevalence_score columns, no real aggregation keyword) must NOT be treated as an
    /// aggregation, or the executor wraps it in a blocking `count(*) OVER()` full-window
    /// scan that OOMs the shared pod.
    #[test]
    fn enrich_only_prevalence_decoration_is_not_aggregation() {
        let enrich_sql = "SELECT l.*, \
            least(_dp_host_count, _ip_host_count, _hp_host_count) AS host_count, \
            true AS is_rare, 42 AS prevalence_score \
            FROM base_logs l ORDER BY l.timestamp DESC";
        assert!(
            !is_aggregation_query(enrich_sql),
            "enrich-only decoration must paginate as a raw-event query, got aggregation=true"
        );
    }

    /// Enrich-then-aggregate (`… | prevalence enrich=true | stats …`) pushes a real
    /// GROUP BY / count() into SQL, which MUST still route through the full-scan
    /// aggregation path (the `count(*) OVER()` then runs over the small grouped output).
    #[test]
    fn enrich_then_aggregate_is_still_aggregation() {
        let agg_sql = "WITH prevalence_results AS (SELECT l.*, \
            least(_dp_host_count) AS host_count FROM base_logs l) \
            SELECT prevalence_type, count(*) AS cnt FROM prevalence_results GROUP BY prevalence_type";
        assert!(
            is_aggregation_query(agg_sql),
            "a real GROUP BY / count() must keep the aggregation path"
        );
    }

    #[test]
    fn pagination_wrapper_enforces_outer_limit_offset() {
        let wrapped = wrap_query_with_pagination(
            "SELECT * FROM logs ORDER BY timestamp DESC -- not allowed at validation time",
            100,
            200,
        );

        assert_eq!(
            wrapped,
            "SELECT * FROM (SELECT * FROM logs ORDER BY timestamp DESC -- not allowed at validation time) AS subquery LIMIT 100 OFFSET 200"
        );
    }

    #[test]
    fn count_wrapper_counts_wrapped_results() {
        let wrapped = wrap_query_for_count("SELECT user, count(*) FROM logs GROUP BY user");

        assert_eq!(
            wrapped,
            "SELECT count(*) AS cnt FROM (SELECT user, count(*) FROM logs GROUP BY user) AS subquery"
        );
    }

    /// NAN-1159: CTE/multi-stage queries (every `| where`/`| stats` pipe) must be
    /// subquery-wrapped for count. The FROM-extraction regex grabs the inner
    /// `FROM logs` of stage_0 and emits malformed SQL → count errors → total_count
    /// silently 0.
    #[test]
    fn count_query_wraps_cte_multistage() {
        let cte = "WITH stage_0 AS (SELECT * FROM logs WHERE source_type = 'x') \
                   SELECT * FROM stage_0 WHERE toString(process_path) iLike '%c:%' ORDER BY timestamp";
        let count = build_count_query(cte, None);
        assert!(
            count.starts_with("SELECT count(*) AS cnt FROM (WITH stage_0"),
            "CTE query must be subquery-wrapped, got: {count}"
        );
    }

    /// NAN-1160: a simple single-FROM query is now subquery-wrapped too (no more regex
    /// extraction), so literal-safe counting applies uniformly.
    #[test]
    fn count_query_wraps_simple_single_from() {
        let simple = "SELECT * FROM logs PREWHERE timestamp >= '2026-01-01' WHERE source_type = 'x'";
        let count = build_count_query(simple, None);
        assert!(
            count.starts_with("SELECT count(*) AS cnt FROM (SELECT * FROM logs"),
            "simple query should be subquery-wrapped, got: {count}"
        );
    }

    /// NAN-1410: pagination must actually be applied — page 2's SQL must
    /// differ from page 1's and carry the requested OFFSET. The pre-fix code
    /// returned the SQL unchanged whenever it already contained a LIMIT, so
    /// every page re-served page 1's rows.
    #[test]
    fn inject_applies_offset_on_limit_free_sql() {
        let sql = "SELECT * FROM logs PREWHERE timestamp >= '2026-01-01' \
                   WHERE (lower(message) iLike '%error%') ORDER BY timestamp DESC \
                   SETTINGS max_threads=16";
        let page1 = inject_limit_offset(sql, 5, 0);
        let page2 = inject_limit_offset(sql, 5, 5);
        assert_ne!(page1, page2, "page 2 SQL must differ from page 1");
        assert!(
            page1.contains(" LIMIT 5 OFFSET 0 SETTINGS "),
            "page 1 must inject before SETTINGS, got: {page1}"
        );
        assert!(
            page2.contains(" LIMIT 5 OFFSET 5 SETTINGS "),
            "page 2 must carry its offset, got: {page2}"
        );
    }

    /// NAN-1410: SQL that already carries a LIMIT (a user `| head N`, a
    /// subsearch cap inside a CTE) must be wrapped structurally — never
    /// returned unchanged (offset silently dropped) and never string-edited
    /// (an inner LIMIT would be corrupted). The outer slice preserves `head`
    /// semantics: a page past the head cap yields no rows.
    #[test]
    fn inject_wraps_sql_that_carries_its_own_limit() {
        let head_sql = "SELECT * FROM logs WHERE (lower(message) iLike '%error%') \
                        ORDER BY timestamp DESC LIMIT 10 SETTINGS max_threads=16";
        let page1 = inject_limit_offset(head_sql, 5, 0);
        let page3 = inject_limit_offset(head_sql, 5, 10);
        assert_ne!(page1, page3);
        assert_eq!(
            page1,
            format!("SELECT * FROM ({}) AS subquery LIMIT 5 OFFSET 0", head_sql),
            "must wrap, preserving the inner head LIMIT untouched"
        );
        assert!(
            page3.ends_with("LIMIT 5 OFFSET 10"),
            "page past the head cap keeps the outer offset (yields 0 rows), got: {page3}"
        );
        assert!(
            page3.contains("LIMIT 10 SETTINGS"),
            "inner head cap must survive the wrap, got: {page3}"
        );
    }

    /// NAN-1410: an inner subsearch LIMIT inside a CTE must trigger the same
    /// structural wrap (the old `.contains(" LIMIT ")` no-op skipped pagination
    /// entirely for these queries).
    #[test]
    fn inject_wraps_cte_with_inner_subsearch_limit() {
        let cte = "WITH stage_0 AS (SELECT * FROM logs WHERE user IN \
                   (SELECT user FROM logs LIMIT 10000)) \
                   SELECT * FROM stage_0 ORDER BY timestamp DESC SETTINGS max_threads=16";
        let paginated = inject_limit_offset(cte, 100, 200);
        assert!(
            paginated.starts_with("SELECT * FROM (WITH stage_0"),
            "CTE with inner LIMIT must be wrapped, got: {paginated}"
        );
        assert!(paginated.ends_with("LIMIT 100 OFFSET 200"));
        assert!(
            paginated.contains("LIMIT 10000"),
            "inner subsearch LIMIT must be untouched, got: {paginated}"
        );
    }

    /// NAN-1410: the count companion's input is LIMIT-free for raw paginated
    /// queries (the generator no longer bakes the page size), so the count
    /// query must carry no LIMIT and return the true total.
    #[test]
    fn count_query_over_paginated_raw_sql_has_no_limit() {
        let sql = "SELECT * FROM logs PREWHERE timestamp >= '2026-01-01' \
                   WHERE (lower(message) iLike '%error%') ORDER BY timestamp DESC \
                   SETTINGS max_threads=16";
        let count = build_count_query(sql, None);
        assert!(
            !count.to_uppercase().contains(" LIMIT "),
            "count query must not be LIMIT-capped, got: {count}"
        );
        assert!(count.starts_with("SELECT count(*) AS cnt FROM ("));
    }

    /// NAN-1160: a string literal containing a whitespace-bounded ` order by` / ` settings`
    /// keyword must NOT truncate the count query. The old extraction regex cut the WHERE clause
    /// mid-literal into unbalanced-quote SQL, so the count errored and total_count silently
    /// read 0 while the data rows looked fine.
    #[test]
    fn count_query_preserves_in_literal_keywords() {
        let sql = "SELECT * FROM logs WHERE lower(message) iLike '%alpha order by beta%' \
                   ORDER BY timestamp DESC SETTINGS max_threads=16";
        let count = build_count_query(sql, None);
        assert!(
            count.contains("alpha order by beta"),
            "in-literal `order by` must be preserved, got: {count}"
        );
        assert!(
            count.contains("SETTINGS max_threads=16"),
            "trailing clauses must be preserved inside the wrap, got: {count}"
        );
    }

    /// NAN-1635 (finding 2.3): with a bounded input (filtered raw search), the
    /// count wraps the REGENERATED ORDER-BY-free SQL in a `SELECT 1 … LIMIT
    /// max_limit+1` shell — ClickHouse stops reading one past the consumer
    /// clamp instead of scanning the full match set. The data SQL (which
    /// carries the ORDER BY) must NOT be used: a top-N sort under the inner
    /// LIMIT defeats early termination.
    #[test]
    fn count_query_bounded_uses_select_one_with_conditional_limit() {
        let data_sql = "SELECT * FROM logs WHERE (lower(message) iLike '%error%') \
                        ORDER BY timestamp DESC SETTINGS max_threads=16";
        let count_input_sql = "SELECT * FROM logs WHERE (lower(message) iLike '%error%') \
                               SETTINGS max_threads=16";
        let count = build_count_query(
            data_sql,
            Some(BoundedCountInput {
                sql: count_input_sql,
                limit: 1_000_001,
            }),
        );
        assert_eq!(
            count,
            format!(
                "SELECT count(*) AS cnt FROM (SELECT 1 FROM ({}) AS matched LIMIT 1000001) AS subquery",
                count_input_sql
            ),
        );
        assert!(
            !count.contains("ORDER BY"),
            "bounded count must wrap the unordered regeneration (ORDER BY + LIMIT = top-N), got: {count}"
        );
    }

    /// NAN-1635 (finding 3.4): the streaming quick_count wraps REGENERATED
    /// (limit-free, unordered) SQL in the shared count shell. For a piped
    /// query that regeneration is a CTE chain — the wrap must be structural
    /// (the old FROM/WHERE regex slicing emitted unbalanced-parenthesis SQL,
    /// ClickHouse Code 62, and the caller swallowed the error so total_count
    /// silently reported delivered rows).
    #[test]
    fn quick_count_wrap_over_piped_regeneration_is_structural() {
        use crate::query::{parse_query, ClickHouseSqlGenerator, QueryOptions, TimeRange};
        let gen = ClickHouseSqlGenerator::new();
        let time_range = TimeRange {
            start: "2024-01-01T00:00:00Z".parse().unwrap(),
            end: "2024-01-02T00:00:00Z".parse().unwrap(),
        };
        let options = QueryOptions {
            limit: None,
            unordered: true,
            ..Default::default()
        };
        let regenerated = gen
            .generate_with_options(
                &parse_query("error | where status_code=500").unwrap(),
                &time_range,
                &options,
            )
            .unwrap();
        let count = wrap_query_for_count(&regenerated);
        assert!(
            count.starts_with("SELECT count(*) AS cnt FROM (WITH "),
            "piped count must wrap the whole CTE chain, got:\n{count}"
        );
        assert!(
            !count.to_uppercase().contains(" LIMIT "),
            "count input must be limit-free (streaming bakes the page size \
             into the data SQL only), got:\n{count}"
        );
        // Balanced parens — the Code 62 failure mode was an unbalanced slice.
        let open = count.matches('(').count();
        let close = count.matches(')').count();
        assert_eq!(open, close, "unbalanced parentheses in:\n{count}");
    }

    /// NAN-1635 (finding 2.3): the bound is CONDITIONAL — without a bounded
    /// input (filter-free `*` browse) the unbounded wrap is kept, because
    /// ClickHouse serves that count from part metadata and the bounded
    /// SELECT-1 form measured 12.8x MORE expensive there.
    #[test]
    fn count_query_without_bounded_input_stays_unbounded() {
        let sql = "SELECT * FROM logs WHERE (1) ORDER BY timestamp DESC SETTINGS max_threads=16";
        let count = build_count_query(sql, None);
        assert_eq!(count, wrap_query_for_count(sql));
        assert!(!count.to_uppercase().contains(" LIMIT "));
    }

    // === NAN-1848: a grouped query's keys must survive empty-value pruning ===

    #[test]
    fn grouped_rows_keep_an_empty_group_key() {
        use crate::search::execution::ClickHouseExecutor;

        // The line ClickHouse actually emits for `stats count by relevance`, where
        // `relevance` exists nowhere: one bucket, empty key. (Verified against local
        // ClickHouse — it returns {"relevance":"","count":634}.)
        let line = r#"{"relevance":"","count":634}"#;

        // Pruned, this row becomes a bare `{"count":634}` — which reads as a grand
        // total, so a meaningless query answers with a confident number.
        let pruned = ClickHouseExecutor::parse_and_postprocess_row(line, true).unwrap();
        assert_eq!(
            pruned,
            serde_json::json!({"count": 634}),
            "documents the bug being fixed: the grouping dimension vanishes"
        );

        // Kept, the bucket is honest about what it is.
        let kept = ClickHouseExecutor::parse_and_postprocess_row(line, false).unwrap();
        assert_eq!(kept, serde_json::json!({"relevance": "", "count": 634}));
    }

    #[test]
    fn raw_event_rows_are_still_pruned() {
        use crate::search::execution::ClickHouseExecutor;

        // The payload optimization must survive for raw events: a wide row with
        // mostly-empty UDM columns still comes back trimmed.
        let line = r#"{"id":"1","message":"hello","src_ip":"","dest_ip":"","user":"","bytes_in":0}"#;
        let row = ClickHouseExecutor::parse_and_postprocess_row(line, true).unwrap();

        let obj = row.as_object().unwrap();
        assert!(!obj.contains_key("src_ip"), "empty columns should still be pruned");
        assert!(!obj.contains_key("user"));
        assert_eq!(obj.get("message").unwrap(), "hello");
    }
}
