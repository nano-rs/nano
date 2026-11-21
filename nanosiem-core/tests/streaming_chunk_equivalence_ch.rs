// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5693 (review P1): daily chunking must never change a streamed answer.
//!
//! For every pipeline `streaming::chunk_plan` lets the stream split by day,
//! run it the way the stream does (one query per `compute_daily_chunks` day,
//! newest first, concatenated and cut at the page / `head` cap) and as ONE
//! query over the whole window on a disposable ClickHouse, and require the
//! same rows in the same order. Negative controls (a global sort + head,
//! `dedup`, `mvexpand limit=`) show the comparison catches the NAN-5693 class:
//! they differ when chunked, and `chunk_plan` sends them to a single query.
//!
//! ```text
//! NANOSIEM_TEST_CLICKHOUSE_URL=http://127.0.0.1:8123 NANOSIEM_TEST_CLICKHOUSE_USER=default \
//!   cargo test -p nanosiem-core --test streaming_chunk_equivalence_ch
//! ```
//! Without `NANOSIEM_TEST_CLICKHOUSE_URL` every test returns early.
#[path = "npl_wrong_answer_ch/harness.rs"]
mod harness;

use chrono::{DateTime, Duration, TimeZone, Utc};
use harness::{Ch, Profile};
use nanosiem_core::query::{parse_query, TimeRange};
use nanosiem_core::search::streaming::{chunk_plan, compute_daily_chunks, ChunkPlan};
use serde_json::{json, Value};

const SOURCE: &str = "chunked";

/// Window over four calendar days with partial first and last days:
/// 2026-10-03 06:00 .. 2026-10-06 03:00 UTC.
fn window() -> TimeRange {
    let start = Utc.with_ymd_and_hms(2026, 10, 3, 6, 0, 0).unwrap();
    TimeRange { start, end: start + Duration::hours(69) }
}

/// Events every 157 minutes from 05:00 on day 1 (one before the window) to
/// past the end (one after), each on a unique timestamp. Users and byte
/// counts repeat across days, so per-day `dedup` / top-N differ from global.
fn rows() -> Vec<String> {
    let first = Utc.with_ymd_and_hms(2026, 10, 3, 5, 0, 0).unwrap();
    let users = ["alice", "bob", "carol", "dave"];
    (0..28)
        .map(|i| {
            let ts: DateTime<Utc> = first + Duration::minutes(157 * i);
            let user = users[(i as usize * 3) % users.len()];
            let bytes_in = 100 + (i * 37) % 900;
            let tags: Vec<String> = (0..(i % 3) + 1).map(|t| format!("t{t}")).collect();
            json!({
                "timestamp": ts.format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
                "source_type": SOURCE,
                "class_uid": 4001,
                "metadata.uid": format!("chunk-{i:02}"),
                "actor.user.name": user,
                "traffic.bytes_in": bytes_in,
                "resources.type": tags,
                "resources.uid": tags.iter().map(|t| format!("r-{t}")).collect::<Vec<_>>(),
                "resources.name": tags.iter().map(|t| format!("n-{t}")).collect::<Vec<_>>(),
                "message": format!("{{\"k\":\"v{i}\",\"user\":\"{user}\"}}"),
                "device.hostname": format!("ws-{}", i % 5),
            })
            .to_string()
        })
        .collect()
}

async fn fixture(tag: &str) -> Option<Ch> {
    let ch = Ch::connect(tag).await?;
    ch.insert(Profile::Ocsf, &rows()).await;
    Some(ch)
}

/// The stream's per-day execution: newest day first, concatenated, cut at
/// `cap` (the page size, or the pipeline's global head N).
async fn chunked(ch: &Ch, q: &str, cap: usize) -> Vec<Value> {
    let range = window();
    let mut out = Vec::new();
    for (start, end) in compute_daily_chunks(range.start, range.end) {
        if out.len() >= cap {
            break;
        }
        let rows = ch
            .run(Profile::Ocsf, q, &TimeRange { start, end })
            .await
            .unwrap_or_else(|e| panic!("chunk `{q}`: {e}"));
        out.extend(rows);
    }
    out.truncate(cap);
    out
}

async fn single(ch: &Ch, q: &str, cap: usize) -> Vec<Value> {
    let mut rows = ch.run(Profile::Ocsf, q, &window()).await.unwrap_or_else(|e| panic!("single `{q}`: {e}"));
    rows.truncate(cap);
    rows
}

/// The first differing row, reduced to the keys that differ.
fn first_difference(a: &[Value], b: &[Value]) -> String {
    if a.len() != b.len() {
        return format!("{} rows chunked vs {} rows whole", a.len(), b.len());
    }
    for (i, (x, y)) in a.iter().zip(b).enumerate() {
        if x != y {
            let (Some(x), Some(y)) = (x.as_object(), y.as_object()) else {
                return format!("row {i}: {x} vs {y}");
            };
            let keys: Vec<String> = x
                .keys()
                .chain(y.keys())
                .filter(|k| x.get(*k) != y.get(*k))
                .map(|k| format!("{k}: {:?} vs {:?}", x.get(k), y.get(k)))
                .collect();
            return format!("row {i}: {}", keys.join("; "));
        }
    }
    "identical".into()
}

fn q(pipeline: &str) -> String {
    format!("source_type=\"{SOURCE}\"{pipeline}")
}

/// Every allowlisted command, with its argument variants, returns exactly the
/// single-query rows when chunked by day, for a full page and a short page.
#[tokio::test]
async fn every_chunkable_pipeline_matches_the_single_query() {
    let Some(ch) = fixture("chunk_equiv").await else { return };
    let cases = [
        "",
        " | where traffic.bytes_in > 300",
        " | where actor.user.name=\"bob\" OR traffic.bytes_in < 200",
        " | eval kb=traffic.bytes_in/1024, who=upper(actor.user.name)",
        " | rename actor.user.name as who",
        " | rename actor.user.name as who, device.hostname as host",
        " | table timestamp, actor.user.name, traffic.bytes_in",
        " | table actor.user.name, traffic.bytes_in",
        " | table actor.user.name as who, traffic.bytes_in",
        " | fields actor.user.name, traffic.bytes_in",
        " | fields - message",
        " | rex field=message \"user.:.(?<u>[a-z]+)\"",
        " | spath input=message output=k path=k",
        " | fillnull value=none device.hostname",
        " | sort -timestamp",
        " | sort -_time",
        " | head 7",
        " | head 7 | head 4",
        " | where traffic.bytes_in > 100 | head 4 | table actor.user.name",
        " | eval dbl=traffic.bytes_in*2 | rename dbl as twice | head 5 | fields twice",
        " | sort -timestamp | head 6 | eval x=1",
    ];
    for pipeline in cases {
        let query = q(pipeline);
        let plan = chunk_plan(&parse_query(&query).unwrap(), "timestamp");
        let ChunkPlan::Daily { row_cap } = plan else {
            panic!("`{query}` should be chunkable, got {plan:?}");
        };
        for page in [1000usize, 5] {
            let cap = row_cap.map_or(page, |n| n.min(page));
            let (by_day, whole) = (chunked(&ch, &query, cap).await, single(&ch, &query, cap).await);
            assert!(!whole.is_empty(), "`{query}`: the fixture must match something");
            assert!(by_day == whole, "`{query}` (page {page}): chunked by day != one query: {}", first_difference(&by_day, &whole));
        }
    }
    ch.drop().await;
}

/// Negative controls: these differ when chunked, which is why `chunk_plan`
/// runs them as one query.
#[tokio::test]
async fn cross_row_pipelines_differ_when_chunked_and_run_whole() {
    let Some(ch) = fixture("chunk_neg").await else { return };
    for pipeline in [
        " | sort -traffic.bytes_in | head 3",
        " | dedup actor.user.name",
        " | mvexpand resources.type limit=2",
    ] {
        let query = q(pipeline);
        assert_eq!(chunk_plan(&parse_query(&query).unwrap(), "timestamp"), ChunkPlan::Single, "`{query}`");
        let (by_day, whole) = (chunked(&ch, &query, 1000).await, single(&ch, &query, 1000).await);
        assert_ne!(by_day, whole, "`{query}`: the control should expose per-day evaluation");
    }
    ch.drop().await;
}
