// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tests for real-time rule evaluation.

#[cfg(test)]
mod tests {
    use super::super::matching::{
        test_compare_numeric as compare_numeric,
        test_evaluate_field_filter as evaluate_field_filter,
        test_evaluate_query_against_event as evaluate_query_against_event,
        test_evaluate_search_expr as evaluate_search_expr, test_get_field_value as get_field_value,
        test_search_keyword_in_value as search_keyword_in_value, test_values_equal as values_equal,
    };
    use crate::query::{parse_query, Comparator, SearchExpr, Value};
    use serde_json::json;

    #[test]
    fn test_search_keyword_in_value() {
        let event = json!({
            "message": "Error occurred in application",
            "level": "error",
            "nested": {
                "field": "contains error too"
            }
        });

        assert!(search_keyword_in_value("error", &event));
        assert!(search_keyword_in_value("Error", &event));
        assert!(search_keyword_in_value("application", &event));
        assert!(!search_keyword_in_value("warning", &event));
    }

    #[test]
    fn test_get_field_value() {
        let event = json!({
            "src_ip": "192.168.1.1",
            "status": 500,
            "nested": {
                "field": "value"
            }
        });

        assert_eq!(
            get_field_value("src_ip", &event),
            Some(json!("192.168.1.1"))
        );
        assert_eq!(get_field_value("status", &event), Some(json!(500)));
        assert_eq!(
            get_field_value("nested.field", &event),
            Some(json!("value"))
        );
        assert_eq!(get_field_value("nonexistent", &event), None);
    }

    #[test]
    fn test_values_equal() {
        // String comparison
        assert!(values_equal(
            &json!("hello"),
            &Value::String("hello".to_string())
        ));
        assert!(values_equal(
            &json!("Hello"),
            &Value::String("hello".to_string())
        )); // Case insensitive

        // Number comparison
        assert!(values_equal(&json!(500), &Value::Number(500.0)));
        assert!(!values_equal(&json!(500), &Value::Number(404.0)));

        // Bool comparison
        assert!(values_equal(&json!(true), &Value::Bool(true)));
        assert!(!values_equal(&json!(true), &Value::Bool(false)));

        // IP comparison
        assert!(values_equal(
            &json!("192.168.1.1"),
            &Value::Ip("192.168.1.1".parse().unwrap())
        ));
    }

    #[test]
    fn test_compare_numeric() {
        assert!(compare_numeric(
            &json!(500),
            &Value::Number(400.0),
            |a, b| a > b
        ));
        assert!(compare_numeric(
            &json!(500),
            &Value::Number(600.0),
            |a, b| a < b
        ));
        assert!(compare_numeric(
            &json!(500),
            &Value::Number(500.0),
            |a, b| a >= b
        ));
        assert!(compare_numeric(
            &json!(500),
            &Value::Number(500.0),
            |a, b| a <= b
        ));
    }

    #[test]
    fn test_evaluate_field_filter() {
        let event = json!({
            "status": 500,
            "src_ip": "192.168.1.1",
            "message": "error"
        });

        // Equality
        assert!(evaluate_field_filter(
            "status",
            &Comparator::Eq,
            &Value::Number(500.0),
            &event
        ));

        // Not equal
        assert!(evaluate_field_filter(
            "status",
            &Comparator::Ne,
            &Value::Number(200.0),
            &event
        ));

        // Greater than
        assert!(evaluate_field_filter(
            "status",
            &Comparator::Gt,
            &Value::Number(400.0),
            &event
        ));

        // IP comparison
        assert!(evaluate_field_filter(
            "src_ip",
            &Comparator::Eq,
            &Value::Ip("192.168.1.1".parse().unwrap()),
            &event
        ));
    }

    #[test]
    fn test_evaluate_search_expr() {
        let event = json!({
            "status": 500,
            "message": "Error occurred",
            "src_ip": "192.168.1.1"
        });

        // Keyword search
        let keyword_expr = SearchExpr::Keyword("error".to_string());
        assert!(evaluate_search_expr(&keyword_expr, &event));

        // Field filter
        let filter_expr = SearchExpr::FieldFilter {
            field: "status".to_string(),
            op: Comparator::Eq,
            value: Value::Number(500.0),
        };
        assert!(evaluate_search_expr(&filter_expr, &event));

        // AND expression
        let and_expr = SearchExpr::And(
            Box::new(SearchExpr::Keyword("error".to_string())),
            Box::new(SearchExpr::FieldFilter {
                field: "status".to_string(),
                op: Comparator::Eq,
                value: Value::Number(500.0),
            }),
        );
        assert!(evaluate_search_expr(&and_expr, &event));

        // OR expression
        let or_expr = SearchExpr::Or(
            Box::new(SearchExpr::Keyword("warning".to_string())),
            Box::new(SearchExpr::Keyword("error".to_string())),
        );
        assert!(evaluate_search_expr(&or_expr, &event));

        // NOT expression
        let not_expr = SearchExpr::Not(Box::new(SearchExpr::Keyword("warning".to_string())));
        assert!(evaluate_search_expr(&not_expr, &event));
    }

    #[test]
    fn test_evaluate_query_against_event() {
        let event = json!({
            "status": 500,
            "message": "Error occurred",
            "src_ip": "192.168.1.1"
        });

        // Simple search
        let query = parse_query("error").unwrap();
        assert!(evaluate_query_against_event(&query, &event));

        // Field filter
        let query = parse_query("status=500").unwrap();
        assert!(evaluate_query_against_event(&query, &event));

        // Combined
        let query = parse_query("error status=500").unwrap();
        assert!(evaluate_query_against_event(&query, &event));

        // Non-matching
        let query = parse_query("warning").unwrap();
        assert!(!evaluate_query_against_event(&query, &event));
    }
}
