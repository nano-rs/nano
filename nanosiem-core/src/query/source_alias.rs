// SPDX-License-Identifier: AGPL-3.0-or-later

//! Query-time source aliases (NAN-3224).
//!
//! Findings are the risk index: there is no separate risk store. The `risk`
//! source is a query-time alias for the findings that added risk:
//!
//! ```text
//! metadata.log_source=risk  ==>  (metadata.log_source="findings" AND risk_score>0)
//! ```
//!
//! The same holds for the `source_type` / `sourcetype` spellings, `!=`, and
//! `IN` / `NOT IN` lists. (nPL has no `index=` selector.)
//!
//! The expansion happens in the parser, so every consumer of a parsed query
//! sees only the real `findings` source: SQL generation (ClickHouse and the
//! lake compiler), source-family candidate hints, the count-rollup router (a
//! literal `log_source='risk'` would count zero rows there), and above all the
//! source-visibility gates. A caller whose deny set contains `findings` gets
//! nothing from `risk` either, because the gate's `NOT IN (findings)` and the
//! expanded `log_source="findings"` can never both hold. Nothing is stored
//! twice and no row ever carries `log_source=risk`.

use crate::query::{Comparator, RhsSyntax, SearchExpr, Value};

/// The alias analysts type.
pub const RISK_SOURCE_ALIAS: &str = "risk";
/// The real source the alias selects from.
pub const FINDINGS_SOURCE: &str = "findings";
/// The finding attribute that marks a finding as having added risk.
pub const RISK_SCORE_FIELD: &str = "risk_score";

/// Fields that name a row's log source in nPL (all schema profiles).
fn is_source_field(field: &str) -> bool {
    matches!(field, "metadata.log_source" | "source_type" | "sourcetype")
}

fn is_risk_alias(value: &Value) -> bool {
    matches!(value, Value::String(text) if text.trim().eq_ignore_ascii_case(RISK_SOURCE_ALIAS))
}

/// `(<field>="findings" AND risk_score>0)`, keeping the analyst's spelling of
/// the source field so profile resolution is unchanged.
fn risk_findings(field: &str) -> SearchExpr {
    SearchExpr::Group(Box::new(SearchExpr::And(
        Box::new(SearchExpr::FieldFilter {
            field: field.to_string(),
            op: Comparator::Eq,
            value: Value::String(FINDINGS_SOURCE.to_string()),
            rhs: RhsSyntax::Literal,
        }),
        Box::new(SearchExpr::FieldFilter {
            field: RISK_SCORE_FIELD.to_string(),
            op: Comparator::Gt,
            value: Value::Number(0.0),
            rhs: RhsSyntax::Literal,
        }),
    )))
}

/// Expand the `risk` source alias in one freshly parsed leaf. Any other
/// expression is returned unchanged.
pub(crate) fn expand_source_alias(expression: SearchExpr) -> SearchExpr {
    match expression {
        SearchExpr::FieldFilter {
            field,
            op: Comparator::Eq,
            value,
            ..
        } if is_source_field(&field) && is_risk_alias(&value) => risk_findings(&field),
        SearchExpr::FieldFilter {
            field,
            op: Comparator::Ne,
            value,
            ..
        } if is_source_field(&field) && is_risk_alias(&value) => {
            SearchExpr::Not(Box::new(risk_findings(&field)))
        }
        SearchExpr::InList {
            field,
            values,
            negated,
        } if is_source_field(&field) && values.iter().any(is_risk_alias) => {
            let rest = values
                .into_iter()
                .filter(|value| !is_risk_alias(value))
                .collect::<Vec<_>>();
            let risk = risk_findings(&field);
            let expanded = match (negated, rest.is_empty()) {
                // `IN (risk)` is exactly `=risk` (already a group).
                (false, true) => return risk,
                (false, false) => SearchExpr::Or(
                    Box::new(SearchExpr::InList {
                        field,
                        values: rest,
                        negated: false,
                    }),
                    Box::new(risk),
                ),
                (true, true) => SearchExpr::Not(Box::new(risk)),
                (true, false) => SearchExpr::And(
                    Box::new(SearchExpr::InList {
                        field,
                        values: rest,
                        negated: true,
                    }),
                    Box::new(SearchExpr::Not(Box::new(risk))),
                ),
            };
            SearchExpr::Group(Box::new(expanded))
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use crate::query::{parse_query, Query};
    use crate::search::evaluate_condition_on_json;
    use serde_json::json;

    fn base(query: &Query) -> &crate::query::SearchExpr {
        match query {
            Query::Search(expression) => expression,
            Query::Piped { source, .. } => base(source),
        }
    }

    fn matches(query: &str, row: &serde_json::Value) -> bool {
        let parsed = parse_query(query).unwrap_or_else(|e| panic!("{query}: {e}"));
        evaluate_condition_on_json(base(&parsed), row)
    }

    #[test]
    fn risk_alias_selects_findings_that_added_risk() {
        // The JSON evaluator resolves each source field literally, so each
        // spelling is checked against rows carrying that field.
        let row = |field: &str, source: &str, score: i64| {
            if field == "metadata.log_source" {
                json!({"metadata": {"log_source": source}, "risk_score": score})
            } else {
                json!({field: source, "risk_score": score})
            }
        };
        for (field, spelling) in [
            ("metadata.log_source", "metadata.log_source=risk"),
            ("metadata.log_source", "metadata.log_source=\"risk\""),
            ("metadata.log_source", "metadata.log_source=RISK"),
            ("source_type", "source_type=risk"),
            ("sourcetype", "sourcetype=risk"),
            ("metadata.log_source", "metadata.log_source IN (risk)"),
        ] {
            assert!(matches(spelling, &row(field, "findings", 40)), "{spelling}");
            assert!(!matches(spelling, &row(field, "findings", 0)), "{spelling}");
            // Query-time only: a row literally labelled `risk` is not selected.
            assert!(!matches(spelling, &row(field, "risk", 90)), "{spelling}");
            assert!(!matches(spelling, &row(field, "apache", 90)), "{spelling}");
        }
        let scored = row("metadata.log_source", "findings", 40);
        let unscored = row("metadata.log_source", "findings", 0);
        let apache = row("metadata.log_source", "apache", 90);
        assert!(matches("metadata.log_source IN (risk, apache)", &apache));
        assert!(matches("metadata.log_source IN (risk, apache)", &scored));
        assert!(!matches("metadata.log_source IN (risk, apache)", &unscored));
        assert!(matches("metadata.log_source!=risk", &unscored));
        assert!(!matches("metadata.log_source!=risk", &scored));
        assert!(!matches(
            "metadata.log_source NOT IN (risk, apache)",
            &apache
        ));
        assert!(!matches(
            "metadata.log_source NOT IN (risk, apache)",
            &scored
        ));
        assert!(matches(
            "metadata.log_source NOT IN (risk, apache)",
            &unscored
        ));
        // OR precedence is preserved by the group.
        assert!(matches(
            "metadata.log_source=apache OR metadata.log_source=risk",
            &scored
        ));
        // Wildcards and other fields are untouched.
        assert!(!matches("metadata.log_source=ris*", &scored));
        assert!(matches(
            "user.name=risk",
            &json!({"user": {"name": "risk"}})
        ));
    }

    #[test]
    fn risk_alias_expansion_round_trips_through_the_printer() {
        use crate::query::PrettyPrint;
        let parsed =
            parse_query("metadata.log_source=apache OR metadata.log_source=risk | stats count()")
                .unwrap();
        let printed = parsed.pretty_print();
        assert!(printed.contains("findings"), "{printed}");
        assert!(!printed.to_ascii_lowercase().contains("=risk"), "{printed}");
        let reparsed = parse_query(&printed).unwrap();
        assert_eq!(reparsed, parsed, "{printed}");
    }
}
