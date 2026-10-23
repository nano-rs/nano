// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4311 keyword-count parity and latency (lab only; local files).
//!
//! ```text
//! lake_part_query_lab keyword-count-parity <work> <queries.txt> <end> <windows> > report.json
//!     every query (one per line) per window (e.g. `24h,6h`) ending at
//!     `end`, through the production broad-search path, alternately with the
//!     v3 keyword counts on and off (probe knob `keyword_counts`), twice
//!     each: rows in page order must be identical; wall and planner evidence
//!     of each run.
//! ```

use super::*;
use nanosiem_lake_worker::perf_overrides::{self, Parsed, Probe};

fn probe(counts: bool) -> Option<Arc<Parsed>> {
    Some(Arc::new(Parsed {
        probe: Some(Probe { knobs: BTreeMap::from([("keyword_counts", u64::from(counts))]), settings: Vec::new() }),
        ..Parsed::default()
    }))
}

pub(super) async fn keyword_count_parity(work: &Path, queries_path: &Path, end: &str, windows: &[String]) -> Result<Value> {
    let cache_dir = work.join(format!("cache-kwcount-{}", std::process::id()));
    let lab = open_lab(work, &cache_dir, false).await?;
    let queries = std::fs::read_to_string(queries_path)?
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .collect::<Vec<_>>();
    let end_at = chrono::DateTime::parse_from_rfc3339(end)?;
    let (mut results, mut mismatches) = (Vec::new(), 0);
    for window in windows {
        let hours = window.trim_end_matches('h').parse::<i64>().context("window is <hours>h")?;
        let start = (end_at - chrono::Duration::hours(hours)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        for query in &queries {
            let mut runs = Vec::new();
            let mut digests = BTreeMap::new();
            for (round, counts) in [(1, true), (1, false), (2, true), (2, false)] {
                let request = request("kwcount", query, &start, end, 100, true);
                let outcome = perf_overrides::scoped(probe(counts), parts_rows(&lab, &request)).await;
                let run = match outcome {
                    Ok((rows, more, seconds, planner)) => {
                        let ordered = rows.iter().map(Value::to_string).collect::<Vec<_>>().join("\n");
                        digests.entry(counts).or_insert_with(Vec::new).push((ordered.clone(), more));
                        json!({"counts": counts, "round": round, "s": seconds, "rows": rows.len(), "more": more,
                            "count_groups": planner["count_groups"], "count_rows": planner["count_rows"],
                            "first_rows": rows.iter().take(5).cloned().collect::<Vec<_>>()})
                    }
                    Err(error) => {
                        digests.entry(counts).or_insert_with(Vec::new).push((format!("error: {error:#}"), false));
                        json!({"counts": counts, "round": round, "error": format!("{error:#}")})
                    }
                };
                eprintln!("{window} {query:?} counts={counts} round={round} s={:?} rows={:?} groups={:?} err={:?}",
                    run["s"], run["rows"], run["count_groups"], run.get("error"));
                runs.push(run);
            }
            let all = digests.values().flatten().collect::<Vec<_>>();
            let identical = all.windows(2).all(|pair| pair[0] == pair[1]);
            if !identical {
                mismatches += 1;
            }
            let best = |counts: bool| runs.iter().filter(|run| run["counts"] == counts).filter_map(|run| run["s"].as_f64()).fold(f64::INFINITY, f64::min);
            results.push(json!({"window": window, "query": query, "identical": identical,
                "on_s": best(true), "off_s": best(false), "runs": runs}));
        }
    }
    let _ = std::fs::remove_dir_all(&cache_dir);
    Ok(json!({"mismatches": mismatches, "results": results}))
}
