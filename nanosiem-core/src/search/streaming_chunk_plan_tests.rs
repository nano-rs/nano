// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5693 / NAN-5701: which streamed queries may be split into daily chunks.
//!
//! Daily chunks are concatenated newest first, so only row-local pipelines in
//! the default order may chunk. Everything that looks across rows must run as
//! one query over the whole window, or the page shows N rows per day.

use super::*;

fn parse(q: &str) -> crate::query::Query {
    crate::query::parse_query(q).unwrap_or_else(|e| panic!("parse {q}: {e}"))
}

fn plan(q: &str) -> ChunkPlan {
    chunk_plan(&parse(q), "timestamp")
}

#[test]
fn row_local_pipelines_chunk_by_day() {
    for q in [
        "error",
        "src_ip=\"10.0.0.1\" | where dest_port > 1024",
        "* | eval kb=bytes_out/1024 | rename user as who | table who, kb",
        "* | table timestamp, user",
        "* | fields src_ip, user | fillnull value=0 bytes_out",
        "* | sort -timestamp",
        "* | sort -_time",
        "* | rex field=message \"user=(?<u>\\w+)\"",
        "* | spath input=message output=k path=a.b",
        "* | fields - message",
    ] {
        assert_eq!(plan(q), ChunkPlan::Daily { row_cap: None }, "{q}");
    }
}

/// The NAN-5693 repro: a global sort on another field plus head must be one
/// ordered query, never chunked (it returned 3 rows per day).
#[test]
fn a_global_sort_runs_as_one_query() {
    for q in [
        "* | sort -traffic.bytes_out | head 3 | table device.hostname, traffic.bytes_out",
        "* | sort bytes_out",
        "* | sort -timestamp, user",
        "* | sort +timestamp",
    ] {
        assert_eq!(plan(q), ChunkPlan::Single, "{q}");
    }
}

/// `head N` in the default order stays chunked, with a global cap of N across
/// all chunks (the caller stops after N rows in total).
#[test]
fn head_in_default_order_caps_rows_across_chunks() {
    assert_eq!(plan("* | head 25"), ChunkPlan::Daily { row_cap: Some(25) });
    assert_eq!(
        plan("* | table a, b, c | head 25"),
        ChunkPlan::Daily { row_cap: Some(25) }
    );
    assert_eq!(
        plan("* | head 25 | eval x=1 | head 10"),
        ChunkPlan::Daily { row_cap: Some(10) }
    );
    assert_eq!(
        plan("* | where user=\"bob\" | head 5 | table user"),
        ChunkPlan::Daily { row_cap: Some(5) }
    );
}

/// A row filter or row expansion AFTER a global head needs the global first N
/// rows first, so it cannot run per day.
#[test]
fn filtering_after_head_runs_as_one_query() {
    assert_eq!(plan("* | head 3 | where user=\"bob\""), ChunkPlan::Single);
}

#[test]
fn cross_row_commands_run_as_one_query() {
    for q in [
        "* | dedup user",
        "* | tail 5",
        "* | reverse",
        "* | join src_ip [search user=\"bob\" | stats count by src_ip]",
        "* | append [search user=\"bob\"]",
        "* | eventstats count by user",
        "src_ip IN [search user=\"bob\" | table src_ip]",
    ] {
        assert_eq!(plan(q), ChunkPlan::Single, "{q}");
    }
}

/// Reassigning the time column changes what the per-chunk ORDER BY sorts on,
/// whichever command does it, in any case, and on the dataset's own key.
#[test]
fn rewriting_the_time_column_runs_as_one_query() {
    for q in [
        "* | eval timestamp=now()",
        "* | eval TIMESTAMP=now()",
        "* | eval _Time=now()",
        "* | rename bytes_out as timestamp",
        "* | rename bytes_out as Timestamp",
        "* | rename timestamp as t",
        "* | table bytes_out as timestamp",
        "* | rex \"(?<timestamp>\\d+)\"",
        "* | rex field=timestamp mode=sed \"s/2026/2025/\"",
        "* | spath input=message output=timestamp path=ts",
        "* | spath input=message",
        "* | fillnull value=0 timestamp",
        "* | fillnull value=0",
        "* | fields - timestamp",
    ] {
        assert_eq!(plan(q), ChunkPlan::Single, "{q}");
    }
}

/// Spans order by `start_time`: rewriting it, or sorting on anything else,
/// cannot chunk; `sort -start_time` is their default order.
#[test]
fn the_dataset_time_column_is_the_key() {
    let spans = |q: &str| chunk_plan(&parse(q), "start_time");
    assert_eq!(spans("* | eval start_time=end_time"), ChunkPlan::Single);
    assert_eq!(spans("* | rename end_time as start_time"), ChunkPlan::Single);
    assert_eq!(spans("* | table end_time as start_time"), ChunkPlan::Single);
    assert_eq!(spans("* | sort -start_time"), ChunkPlan::Daily { row_cap: None });
}

/// Review P1: window-derived or self-capping arguments are not row-local.
/// `bin bins=N` derives its span from each chunk's window, `hop=` multiplies
/// rows, and `mvexpand` always carries a LIMIT that would apply per day.
#[test]
fn bin_and_mvexpand_run_as_one_query() {
    for q in [
        "* | bin span=1h",
        "* | bin bins=10",
        "* | bin span=1h hop=15m",
        "* | bin span=1h as timestamp",
        "* | mvexpand tags",
        "* | mvexpand tags limit=5",
        "* | mvexpand tags limit=5 | head 10",
    ] {
        assert_eq!(plan(q), ChunkPlan::Single, "{q}");
    }
}

#[test]
fn only_a_terminal_timechart_is_presented_whole() {
    let parse = |q: &str| crate::query::parse_query(q).unwrap();
    assert!(ends_in_timechart(&parse("* | timechart span=1h count")));
    assert!(!ends_in_timechart(&parse("* | stats count by user")));
    assert!(!ends_in_timechart(&parse("* | timechart span=1h count | where count > 1")));
}
