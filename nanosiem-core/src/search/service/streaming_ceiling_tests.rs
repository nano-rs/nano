// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4957 review: streaming searches honor the per-query memory ceiling.

use super::streaming_ch_settings;
use crate::search::admission::QueryPriority;
use crate::search::service::sql_execution::raw_sql_memory_split;

/// 40% of a 4G compose box's 3.2 GiB limit.
const CEILING: u64 = 1_374_389_520;

#[test]
fn interactive_streaming_is_clamped_to_the_ceiling() {
    let s = streaming_ch_settings(QueryPriority::Interactive, Some(CEILING));
    assert_eq!(s.max_memory_usage_bytes, Some(CEILING));
}

#[test]
fn analytics_streaming_is_clamped_to_the_ceiling() {
    let s = streaming_ch_settings(QueryPriority::Analytics, Some(CEILING));
    assert_eq!(s.max_memory_usage_bytes, Some(CEILING));
    // Everything but memory keeps the analytics tier.
    assert_eq!(s.max_execution_time, QueryPriority::Analytics.to_ch_settings().max_execution_time);
}

#[test]
fn streaming_without_a_ceiling_leaves_the_profile_in_control() {
    assert_eq!(streaming_ch_settings(QueryPriority::Analytics, None).max_memory_usage_bytes, None);
}

#[test]
fn raw_sql_rows_and_count_share_one_budget() {
    let (rows, count) = raw_sql_memory_split(Some(CEILING)).unwrap();
    assert!(rows + count <= CEILING);
    assert!(rows > count);
    assert_eq!(raw_sql_memory_split(None), None);
    assert_eq!(
        crate::search::service::sql_execution::raw_sql_memory_settings(1000),
        vec![
            "max_memory_usage = 1000".to_string(),
            "max_bytes_before_external_group_by = 500".to_string(),
            "max_bytes_before_external_sort = 500".to_string(),
        ]
    );
}
