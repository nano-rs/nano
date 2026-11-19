// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5636: a query stopped by the ClickHouse spill caps
//! (`max_temporary_data_on_disk_size`, `_for_query`, `_for_user`) maps to a
//! resource-limit error that says so, not to "too many rows".

use super::*;

/// Verbatim from ClickHouse 26.10.4.207 (a GROUP BY over the per-query cap
/// and an ORDER BY over the server cap, both observed on a throwaway server).
const GROUP_BY_OVER_QUERY_CAP: &str = "Code: 396. DB::Exception: Limit for temporary files size exceeded \
     (would consume 1678858 / 1048576 bytes). (TOO_MANY_ROWS_OR_BYTES) (version 26.10.4.207 (official build))";
const ORDER_BY_OVER_SERVER_CAP: &str = "Code: 396. DB::Exception: Limit for temporary files size exceeded \
     (would consume 4244558 / 4194304 bytes). (TOO_MANY_ROWS_OR_BYTES) (version 26.10.4.207 (official build))";

fn resource_limit_message(err: SearchError) -> String {
    match err {
        SearchError::ResourceLimit(message) => message,
        other => panic!("expected ResourceLimit, got {other:?}"),
    }
}

#[test]
fn spill_cap_errors_name_the_temporary_disk_limit() {
    for raw in [GROUP_BY_OVER_QUERY_CAP, ORDER_BY_OVER_SERVER_CAP] {
        let message = resource_limit_message(parse_clickhouse_error(raw));
        assert_eq!(message, TEMPORARY_DATA_LIMIT_MESSAGE, "{raw}");
        assert!(!message.contains("too many rows"), "{message}");
    }
}

#[test]
fn result_size_396_keeps_the_too_many_rows_message() {
    let raw = "Code: 396. DB::Exception: Limit for result exceeded, max rows: 1.00 million, \
               current rows: 1.05 million. (TOO_MANY_ROWS_OR_BYTES) (version 26.10.4.207 (official build))";
    let message = resource_limit_message(parse_clickhouse_error(raw));
    assert!(message.starts_with("Query returned too many rows"), "{message}");
}

#[test]
fn spill_wording_inside_quoted_data_does_not_classify() {
    // NAN-5424: text after the first quote can echo event data.
    let raw = "Code: 396. DB::Exception: Limit for result exceeded at 'Limit for temporary files size exceeded'. \
               (TOO_MANY_ROWS_OR_BYTES)";
    let message = resource_limit_message(parse_clickhouse_error(raw));
    assert_ne!(message, TEMPORARY_DATA_LIMIT_MESSAGE);
}
