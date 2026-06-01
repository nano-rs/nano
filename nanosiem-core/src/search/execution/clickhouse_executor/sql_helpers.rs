// SPDX-License-Identifier: AGPL-3.0-or-later

//! SQL helper functions for ClickHouse query manipulation
//!
//! Free functions for SQL analysis and transformation: aggregation detection,
//! LIMIT/OFFSET injection, COUNT query building, and question mark escaping.

/// Check if a SQL query is an aggregation query that needs all data
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
        // Prevalence queries need all data
        || sql_upper.contains("DOMAIN_PREV")
        || sql_upper.contains("HASH_PREV")
        || sql_upper.contains("HOST_COUNT")
        || sql_upper.contains("IS_RARE")
        || sql_upper.contains("PREVALENCE_SCORE")
}

/// Inject LIMIT and OFFSET into a SQL query before the SETTINGS clause
/// This allows ClickHouse to stop reading early for non-aggregation queries
pub fn inject_limit_offset(sql: &str, limit: usize, offset: usize) -> String {
    // Check if query already has LIMIT (case-insensitive)
    let sql_upper = sql.to_uppercase();
    if sql_upper.contains(" LIMIT ") {
        return sql.to_string();
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

/// Build a COUNT query from a data query by wrapping it in a counting subquery.
pub(crate) fn build_count_query(sql: &str) -> String {
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
    // no user pagination LIMIT here (LIMIT/OFFSET is injected separately into the data query,
    // not the count input — see paginated.rs), so counting the wrapped result yields the true
    // pre-pagination total (bounded only by the base query's default safety limit).
    wrap_query_for_count(sql)
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
        let count = build_count_query(cte);
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
        let count = build_count_query(simple);
        assert!(
            count.starts_with("SELECT count(*) AS cnt FROM (SELECT * FROM logs"),
            "simple query should be subquery-wrapped, got: {count}"
        );
    }

    /// NAN-1160: a string literal containing a whitespace-bounded ` order by` / ` settings`
    /// keyword must NOT truncate the count query. The old extraction regex cut the WHERE clause
    /// mid-literal into unbalanced-quote SQL, so the count errored and total_count silently
    /// read 0 while the data rows looked fine.
    #[test]
    fn count_query_preserves_in_literal_keywords() {
        let sql = "SELECT * FROM logs WHERE lower(message) iLike '%alpha order by beta%' \
                   ORDER BY timestamp DESC SETTINGS max_threads=16";
        let count = build_count_query(sql);
        assert!(
            count.contains("alpha order by beta"),
            "in-literal `order by` must be preserved, got: {count}"
        );
        assert!(
            count.contains("SETTINGS max_threads=16"),
            "trailing clauses must be preserved inside the wrap, got: {count}"
        );
    }
}
