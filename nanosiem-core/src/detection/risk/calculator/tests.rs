// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unit tests for `ScoreCalculator` query-score detection (audit D10).

use super::*;
use serde_json::json;

#[test]
fn has_query_risk_score_treats_null_as_absent() {
    // Audit D10: a JSON null `raw_risk_score` must count as ABSENT so a
    // null-scored `| risk` batch falls back to rule-level scoring instead of
    // being dropped and suppressing the whole alert.
    assert!(ScoreCalculator::has_query_risk_score(
        &json!({"raw_risk_score": 42})
    ));
    assert!(ScoreCalculator::has_query_risk_score(
        &json!({"raw_risk_score": 0})
    ));
    assert!(!ScoreCalculator::has_query_risk_score(
        &json!({"raw_risk_score": null})
    ));
    assert!(!ScoreCalculator::has_query_risk_score(
        &json!({"other": 1})
    ));
}
