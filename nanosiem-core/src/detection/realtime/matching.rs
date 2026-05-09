// SPDX-License-Identifier: AGPL-3.0-or-later

//! Query-to-event matching for real-time evaluation.
//!
//! Contains pure functions that evaluate parsed nPL queries against
//! individual JSON log events in memory.

use crate::query::{Command, Comparator, Query, SearchExpr, Value};

/// Evaluate a parsed query against a single event
pub(crate) fn evaluate_query_against_event(query: &Query, event: &serde_json::Value) -> bool {
    match query {
        Query::Search(expr) => evaluate_search_expr(expr, event),
        Query::Piped { source, command } => {
            // For piped queries, we only evaluate the search part
            // Commands like stats, sort, etc. don't apply to single events
            let source_matches = evaluate_query_against_event(source, event);

            // Apply where command if present
            match command {
                Command::Where { condition } => {
                    source_matches && evaluate_search_expr(condition, event)
                }
                _ => source_matches,
            }
        }
    }
}

/// Evaluate a search expression against an event
fn evaluate_search_expr(expr: &SearchExpr, event: &serde_json::Value) -> bool {
    match expr {
        SearchExpr::Keyword(keyword) => {
            // Search for keyword in all string values
            search_keyword_in_value(keyword, event)
        }
        SearchExpr::FieldFilter { field, op, value } => {
            evaluate_field_filter(field, op, value, event)
        }
        SearchExpr::FunctionFilter {
            function: _,
            op: _,
            value: _,
        } => {
            // For now, we'll evaluate the function and compare with the value
            // This is a simplified implementation - in a full implementation,
            // we'd need to evaluate the function call properly
            // For now, return false to avoid breaking existing functionality
            false
        }
        SearchExpr::BooleanFunction(_) => {
            // Standalone boolean function predicate (e.g., isnull(field))
            // Simplified implementation - would need full eval engine for real-time evaluation
            false
        }
        SearchExpr::FieldFunctionFilter {
            field: _,
            op: _,
            function: _,
        } => {
            // For now, we'll evaluate field op function(args)
            // This is a simplified implementation - in a full implementation,
            // we'd need to evaluate the function call properly
            // For now, return false to avoid breaking existing functionality
            false
        }
        SearchExpr::InList {
            field,
            values,
            negated,
        } => evaluate_in_list_filter(field, values, *negated, event),
        SearchExpr::And(left, right) => {
            evaluate_search_expr(left, event) && evaluate_search_expr(right, event)
        }
        SearchExpr::Or(left, right) => {
            evaluate_search_expr(left, event) || evaluate_search_expr(right, event)
        }
        SearchExpr::Not(inner) => !evaluate_search_expr(inner, event),
        SearchExpr::Group(inner) => evaluate_search_expr(inner, event),
        SearchExpr::LiteralComparison { left, op, right } => {
            // Compare two literal strings - used for parameter expansion checks
            // e.g., "$user"="*" where both sides are literal values
            let right_str = match right {
                crate::query::Value::String(s) => s.as_str(),
                _ => return false,
            };
            match op {
                crate::query::Comparator::Eq => left == right_str,
                crate::query::Comparator::Ne => left != right_str,
                _ => false, // Other operators not typically used for literal comparisons
            }
        }
        SearchExpr::InSubsearch { .. } => {
            // Subsearch IN cannot be evaluated in real-time matching
            false
        }
    }
}

/// Evaluate an IN list filter against an event
fn evaluate_in_list_filter(
    field: &str,
    values: &[Value],
    negated: bool,
    event: &serde_json::Value,
) -> bool {
    let event_value = get_field_value(field, event);

    match event_value {
        Some(ev) => {
            let matches = values.iter().any(|v| values_equal(&ev, v));
            if negated {
                !matches
            } else {
                matches
            }
        }
        None => negated, // If field doesn't exist, NOT IN returns true, IN returns false
    }
}

/// Search for a keyword in a JSON value (recursive)
fn search_keyword_in_value(keyword: &str, value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(s) => s.to_lowercase().contains(&keyword.to_lowercase()),
        serde_json::Value::Object(map) => map.values().any(|v| search_keyword_in_value(keyword, v)),
        serde_json::Value::Array(arr) => arr.iter().any(|v| search_keyword_in_value(keyword, v)),
        _ => {
            // Convert to string and search
            value
                .to_string()
                .to_lowercase()
                .contains(&keyword.to_lowercase())
        }
    }
}

/// Evaluate a field filter against an event
fn evaluate_field_filter(
    field: &str,
    op: &Comparator,
    filter_value: &Value,
    event: &serde_json::Value,
) -> bool {
    // Get the field value from the event (supports dot notation)
    let event_value = get_field_value(field, event);

    match event_value {
        Some(ev) => compare_values(op, &ev, filter_value),
        None => false,
    }
}

/// Get a field value from a JSON object (supports dot notation)
fn get_field_value(field: &str, value: &serde_json::Value) -> Option<serde_json::Value> {
    let parts: Vec<&str> = field.split('.').collect();
    let mut current = value;

    for part in parts {
        match current {
            serde_json::Value::Object(map) => {
                current = map.get(part)?;
            }
            _ => return None,
        }
    }

    Some(current.clone())
}

/// Compare a JSON value with a filter value using the given operator
fn compare_values(op: &Comparator, event_value: &serde_json::Value, filter_value: &Value) -> bool {
    match op {
        Comparator::Eq => values_equal(event_value, filter_value),
        Comparator::Ne => !values_equal(event_value, filter_value),
        Comparator::Gt => compare_numeric(event_value, filter_value, |a, b| a > b),
        Comparator::Lt => compare_numeric(event_value, filter_value, |a, b| a < b),
        Comparator::Gte => compare_numeric(event_value, filter_value, |a, b| a >= b),
        Comparator::Lte => compare_numeric(event_value, filter_value, |a, b| a <= b),
        Comparator::Regex => {
            let pattern = match filter_value {
                Value::Regex(p) => p,
                Value::String(p) => p,
                _ => return false,
            };
            if let serde_json::Value::String(s) = event_value {
                regex::Regex::new(pattern)
                    .map(|re| re.is_match(s))
                    .unwrap_or(false)
            } else {
                false
            }
        }
        Comparator::NotRegex => {
            let pattern = match filter_value {
                Value::Regex(p) => p,
                Value::String(p) => p,
                _ => return false,
            };
            if let serde_json::Value::String(s) = event_value {
                regex::Regex::new(pattern)
                    .map(|re| !re.is_match(s))
                    .unwrap_or(true)
            } else {
                true
            }
        }
        Comparator::Like => {
            // LIKE pattern matching (SQL-style with % and _)
            let pattern = match filter_value {
                Value::String(p) => p,
                _ => return false,
            };
            if let serde_json::Value::String(s) = event_value {
                sql_like_match(s, pattern)
            } else {
                false
            }
        }
        Comparator::NotLike => {
            let pattern = match filter_value {
                Value::String(p) => p,
                _ => return false,
            };
            if let serde_json::Value::String(s) = event_value {
                !sql_like_match(s, pattern)
            } else {
                true
            }
        }
        Comparator::Contains => {
            let substring = match filter_value {
                Value::String(s) => s,
                _ => return false,
            };
            if let serde_json::Value::String(s) = event_value {
                s.to_lowercase().contains(&substring.to_lowercase())
            } else {
                false
            }
        }
        Comparator::NotContains => {
            let substring = match filter_value {
                Value::String(s) => s,
                _ => return false,
            };
            if let serde_json::Value::String(s) = event_value {
                !s.to_lowercase().contains(&substring.to_lowercase())
            } else {
                true
            }
        }
        Comparator::StartsWith => {
            let prefix = match filter_value {
                Value::String(s) => s,
                _ => return false,
            };
            if let serde_json::Value::String(s) = event_value {
                s.to_lowercase().starts_with(&prefix.to_lowercase())
            } else {
                false
            }
        }
        Comparator::NotStartsWith => {
            let prefix = match filter_value {
                Value::String(s) => s,
                _ => return false,
            };
            if let serde_json::Value::String(s) = event_value {
                !s.to_lowercase().starts_with(&prefix.to_lowercase())
            } else {
                true
            }
        }
        Comparator::EndsWith => {
            let suffix = match filter_value {
                Value::String(s) => s,
                _ => return false,
            };
            if let serde_json::Value::String(s) = event_value {
                s.to_lowercase().ends_with(&suffix.to_lowercase())
            } else {
                false
            }
        }
        Comparator::NotEndsWith => {
            let suffix = match filter_value {
                Value::String(s) => s,
                _ => return false,
            };
            if let serde_json::Value::String(s) = event_value {
                !s.to_lowercase().ends_with(&suffix.to_lowercase())
            } else {
                true
            }
        }
    }
}

/// SQL LIKE pattern matching (case-insensitive)
/// % matches any sequence of characters
/// _ matches any single character
fn sql_like_match(value: &str, pattern: &str) -> bool {
    // Convert SQL LIKE pattern to regex
    let mut regex_pattern = String::from("(?i)^");
    for c in pattern.chars() {
        match c {
            '%' => regex_pattern.push_str(".*"),
            '_' => regex_pattern.push('.'),
            '.' | '*' | '+' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '^' | '$' | '\\' => {
                regex_pattern.push('\\');
                regex_pattern.push(c);
            }
            _ => regex_pattern.push(c),
        }
    }
    regex_pattern.push('$');

    regex::Regex::new(&regex_pattern)
        .map(|re| re.is_match(value))
        .unwrap_or(false)
}

/// Check if two values are equal
fn values_equal(event_value: &serde_json::Value, filter_value: &Value) -> bool {
    match (event_value, filter_value) {
        (serde_json::Value::String(s), Value::String(fs)) => s.to_lowercase() == fs.to_lowercase(),
        (serde_json::Value::Number(n), Value::Number(fn_)) => n
            .as_f64()
            .map(|v| (v - fn_).abs() < f64::EPSILON)
            .unwrap_or(false),
        (serde_json::Value::Bool(b), Value::Bool(fb)) => b == fb,
        (serde_json::Value::String(s), Value::Ip(ip)) => s == &ip.to_string(),
        (serde_json::Value::Number(n), Value::String(s)) => {
            // Try to compare number with string representation
            n.to_string() == *s
        }
        (serde_json::Value::String(s), Value::Number(n)) => {
            // Try to parse string as number
            s.parse::<f64>()
                .map(|v| (v - n).abs() < f64::EPSILON)
                .unwrap_or(false)
        }
        _ => false,
    }
}

/// Compare numeric values
fn compare_numeric<F>(event_value: &serde_json::Value, filter_value: &Value, cmp: F) -> bool
where
    F: Fn(f64, f64) -> bool,
{
    let event_num = match event_value {
        serde_json::Value::Number(n) => n.as_f64(),
        serde_json::Value::String(s) => s.parse::<f64>().ok(),
        _ => None,
    };

    let filter_num = match filter_value {
        Value::Number(n) => Some(*n),
        Value::String(s) => s.parse::<f64>().ok(),
        _ => None,
    };

    match (event_num, filter_num) {
        (Some(ev), Some(fv)) => cmp(ev, fv),
        _ => false,
    }
}

#[cfg(test)]
pub(crate) use test_helpers::*;

#[cfg(test)]
mod test_helpers {
    use super::*;

    // Re-export for tests in sibling modules
    pub(crate) fn test_search_keyword_in_value(keyword: &str, value: &serde_json::Value) -> bool {
        search_keyword_in_value(keyword, value)
    }

    pub(crate) fn test_get_field_value(
        field: &str,
        value: &serde_json::Value,
    ) -> Option<serde_json::Value> {
        get_field_value(field, value)
    }

    pub(crate) fn test_values_equal(event_value: &serde_json::Value, filter_value: &Value) -> bool {
        values_equal(event_value, filter_value)
    }

    pub(crate) fn test_compare_numeric<F>(
        event_value: &serde_json::Value,
        filter_value: &Value,
        cmp: F,
    ) -> bool
    where
        F: Fn(f64, f64) -> bool,
    {
        compare_numeric(event_value, filter_value, cmp)
    }

    pub(crate) fn test_evaluate_field_filter(
        field: &str,
        op: &Comparator,
        filter_value: &Value,
        event: &serde_json::Value,
    ) -> bool {
        evaluate_field_filter(field, op, filter_value, event)
    }

    pub(crate) fn test_evaluate_search_expr(expr: &SearchExpr, event: &serde_json::Value) -> bool {
        evaluate_search_expr(expr, event)
    }

    pub(crate) fn test_evaluate_query_against_event(
        query: &Query,
        event: &serde_json::Value,
    ) -> bool {
        evaluate_query_against_event(query, event)
    }
}
