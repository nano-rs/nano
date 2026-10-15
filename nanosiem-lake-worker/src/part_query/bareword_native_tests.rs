// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3162, native: bareword entity pivots end-to-end (real compiler,
//! planner, parts, chDB) on the NAN-3158 density fixture. An unquoted value
//! (`src_endpoint.hostname=web1.corp.local`, `src_ip=10.7.7.7`,
//! `src_host=web1.corp.local`) must run the same plan as its quoted spelling
//! and return hash-identical rows, equal to the `* | where` form and to
//! fixture truth -- in a 23 h window and in a 7 d window, which now pages
//! progressively too (the lake keeps the event-UID tie-break past 24 h).
//!
//! ```sh
//! export NANO_CHDB_LIBRARY_PATH=... NANO_CHDB_LIBRARY_SHA256=... NANO_LAKE_COMPILER=...
//! cargo test -p nanosiem-lake-worker --lib part_query::density::bareword_native -- --ignored --nocapture --test-threads=1
//! ```

use super::native::{
    digest, engine, envelope, ingest, ordered_uids, request, rows_of, src_ip, statements, DENSE_HOST, DENSE_IP, ROWS,
    SPARSE_IP,
};
use chrono::{Duration, Utc};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn bareword_pivots_match_quoted_and_where_in_short_and_long_windows() {
    std::env::remove_var("NANO_LAKE_PART_RESULT_CACHE");
    let root = tempfile::tempdir().unwrap();
    let now = Utc::now();
    ingest(root.path(), now).await;
    let engine = engine(root.path()).await;
    let truth = |keep: &dyn Fn(usize) -> bool, n: usize| {
        (0..ROWS).filter(|i| keep(*i)).take(n).map(|i| format!("uid-{i:08}")).collect::<Vec<_>>()
    };
    let sparse_ip = |i: usize| src_ip(i) == SPARSE_IP;
    let dense_ip = |i: usize| src_ip(i) == DENSE_IP;
    // Odd rows carry `WEB1.Corp.Local`, lowercased at admission.
    let dense_host = |i: usize| i % 2 == 1;
    let cases: Vec<(String, String, &dyn Fn(usize) -> bool)> = vec![
        (format!("src_endpoint.hostname={DENSE_HOST}"), format!("src_endpoint.hostname=\"{DENSE_HOST}\""), &dense_host),
        // A product alias: resolves to `src_endpoint.ip`.
        (format!("src_ip={SPARSE_IP}"), format!("src_ip=\"{SPARSE_IP}\""), &sparse_ip),
        (format!("src_ip={DENSE_IP}"), format!("src_ip=\"{DENSE_IP}\""), &dense_ip),
        // A class-split alias: `if(src_endpoint.hostname != '', …, device.hostname)`.
        (format!("src_host={DENSE_HOST}"), format!("src_host=\"{DENSE_HOST}\""), &dense_host),
    ];
    for hours in [23_i64, 24 * 7] {
        let window = |query: &str, limit: usize| {
            let mut step = request(query, now, limit);
            step.start = (now - Duration::hours(hours)).to_rfc3339();
            step
        };
        for (bare, quoted, keep) in &cases {
            for (shape, head) in [("| head 20", 20_usize), ("| sort -time | head 50", 50)] {
                let bare_answer = envelope(&engine, &window(&format!("{bare} {shape}"), 200)).await;
                let quoted_answer = envelope(&engine, &window(&format!("{quoted} {shape}"), 200)).await;
                let (bare_rows, quoted_rows) = (rows_of(&bare_answer), rows_of(&quoted_answer));
                let label = format!("{bare} {shape} ({hours} h)");
                assert_eq!(ordered_uids(&bare_rows), truth(*keep, head), "{label}: truth");
                assert_eq!(digest(&bare_rows), digest(&quoted_rows), "{label}: rows hash-identical to quoted");
                assert_eq!(bare_answer["result"]["page_has_more"], quoted_answer["result"]["page_has_more"], "{label}");
                let (bare_plan, quoted_plan) = (&bare_answer["planner"], &quoted_answer["planner"]);
                assert_eq!(bare_plan["kind"], quoted_plan["kind"], "{label}: same plan");
                assert_eq!(
                    bare_plan["kind"], "progressive_newest_first",
                    "{label}: a head-N timeline pages newest first in every window: {bare_plan}"
                );
                assert_eq!(statements(&bare_answer), statements(&quoted_answer), "{label}: same statements");
                assert_eq!(bare_plan["chunks_executed"], quoted_plan["chunks_executed"], "{label}");
                assert_eq!(bare_plan["fetched_files"], quoted_plan["fetched_files"], "{label}: same pruning");
                // The same density decision (`fetched_parts` and timing differ:
                // the second run reads the first's memoized partials).
                for key in ["dense"] {
                    assert_eq!(bare_plan["density"][key], quoted_plan["density"][key], "{label}: density {key}");
                }
                for key in ["events", "rows", "consulted_parts", "window_parts", "complete"] {
                    assert_eq!(
                        bare_plan["density"]["estimate"][key], quoted_plan["density"]["estimate"][key],
                        "{label}: density estimate {key}"
                    );
                }
                let reference = rows_of(
                    &envelope(&engine, &window(&format!("* | where {quoted} | sort -time | head {head}"), 200)).await,
                );
                assert_eq!(ordered_uids(&bare_rows), ordered_uids(&reference), "{label} vs | where");
                println!(
                    "NAN3162 {label}: statements={} chunks={} fetched_files={} density={}",
                    statements(&bare_answer), bare_plan["chunks_executed"], bare_plan["fetched_files"], bare_plan["density"],
                );
            }
        }
        // Cursor paging (infinite scroll) over a bareword pivot continues the
        // result exactly in both windows.
        let query = format!("src_ip={DENSE_IP} | sort -time | head 50");
        let mut pages = Vec::new();
        let mut step = window(&query, 10);
        for _ in 0..3 {
            let page = envelope(&engine, &step).await;
            let rows = rows_of(&page);
            assert_eq!(rows.len(), 10, "{query} ({hours} h): {page}");
            let last = rows.last().unwrap();
            let time = last["time"].as_str().unwrap().replace(' ', "T");
            step.cursor_time = Some(if time.ends_with('Z') { time } else { format!("{time}Z") });
            step.cursor_event_uid = Some(last["metadata.uid"].as_str().unwrap().to_string());
            pages.extend(rows);
        }
        assert_eq!(ordered_uids(&pages), truth(&dense_ip, 30), "{query} ({hours} h): cursor pages continue exactly");
    }
}
