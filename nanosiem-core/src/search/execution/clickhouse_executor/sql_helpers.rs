// SPDX-License-Identifier: AGPL-3.0-or-later

//! SQL helper functions for ClickHouse query manipulation
//!
//! Free functions for SQL analysis and transformation: aggregation detection,
//! LIMIT/OFFSET injection, COUNT query building, and question mark escaping.

use regex::Regex;

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

/// Build a COUNT query from a data query by extracting the FROM/PREWHERE/WHERE clauses
pub(crate) fn build_count_query(sql: &str) -> String {
    // Use regex to extract the FROM clause and conditions, excluding ORDER BY and SETTINGS
    let re = Regex::new(r"(?is)FROM\s+(\S+)(.*?)(?:\s+ORDER\s+BY|\s+SETTINGS|\s*$)").unwrap();

    if let Some(caps) = re.captures(sql) {
        let table = caps.get(1).map_or("logs", |m| m.as_str());
        let conditions = caps.get(2).map_or("", |m| m.as_str());
        format!("SELECT count(*) as cnt FROM {}{}", table, conditions)
    } else {
        // Fallback: wrap in subquery (less efficient but always works)
        let sql_no_settings = sql.split(" SETTINGS ").next().unwrap_or(sql);
        let sql_no_order = Regex::new(r"(?is)\s+ORDER\s+BY\s+.*$")
            .unwrap()
            .replace(sql_no_settings, "");
        format!("SELECT count(*) as cnt FROM ({}) as subquery", sql_no_order)
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
}
