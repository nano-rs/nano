// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5339: client-side dc() / estdc() must agree with the SQL path
//! (`clickhouse_sql_gen/dc_missing_value_tests.rs`): a missing value is not a
//! distinct value.

use super::stats::compute_aggregation;
use crate::query::{AggFunc, Aggregation};

/// The Rust post-processing path must agree with the SQL path: absent keys,
/// JSON null and '' are not distinct values; 0 is.
#[test]
fn post_processing_dc_ignores_missing_values() {
    let rows = [
        serde_json::json!({}),
        serde_json::json!({"f": null}),
        serde_json::json!({"f": ""}),
        serde_json::json!({"f": 0}),
        serde_json::json!({"f": "a"}),
        serde_json::json!({"f": "a"}),
    ];
    let refs: Vec<&serde_json::Value> = rows.iter().collect();
    for func in [AggFunc::Dc, AggFunc::EstDc] {
        let agg = Aggregation::new(func.clone(), Some("f".to_string()));
        assert_eq!(compute_aggregation(&refs, &agg), serde_json::json!(2), "{func:?}");
    }

    let only_missing = [serde_json::json!({}), serde_json::json!({"f": ""})];
    let refs: Vec<&serde_json::Value> = only_missing.iter().collect();
    let agg = Aggregation::new(AggFunc::Dc, Some("f".to_string()));
    assert_eq!(compute_aggregation(&refs, &agg), serde_json::json!(0));
}
