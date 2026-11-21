// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5718: a plain `| prevalence enrich=true` decorates the rows it returns
//! with the same real-time truth the filter form and `POST /api/prevalence/bulk`
//! read, while every other prevalence shape (filter forms, rarity rules) keeps
//! its NAN-1705 behavior byte-for-byte.

use super::npl_golden_corpus_tests::{render, sql_only_service};
use super::prevalence_page_rescue::{
    apply_page_rescue, build_miss_probe_sql, collect_miss_keys, page_rescue_applies,
    page_rescue_partial_message, parse_probe_rows, report_page_rescue_overflow,
    residual_miss_keys, MissKind,
};
use super::prevalence_processing::{decorated_filter_rescue_threshold, RescuedArtifact};
use super::prevalence_scan::ResultWindow;
use super::*;
use crate::auth::ScopeSet;
use crate::prevalence::PrevalenceRepository;
use serde_json::{json, Value};
use std::collections::HashMap;

const PIVOT: &str = r#"source_type="soc_proc" process.name="rare.exe" | prevalence enrich=true window=24h"#;
const RARITY_RULE: &str = r#"source_type="soc_proc" | prevalence enrich=true window=30d | where host_count < 3"#;
const SHA: &str = "5f0c0d1e2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5";
const EPOCH: &str = "1970-01-01 00:00:00.000000";
const RESCUE_NOTE: &str = "-- Note: at execute time, artifacts the prevalence dict";

fn commands(q: &str) -> (Query, Vec<PrevalenceCommandInfo>, Vec<Command>) {
    let parsed = crate::query::parse_query(q).expect("query parses");
    let (parsed, _) = crate::search::query_processing::apply_auto_sort(parsed);
    let prevalence = extract_prevalence_commands(&parsed);
    let post = extract_post_prevalence_commands(&parsed).commands;
    (parsed, prevalence, post)
}

fn applies(svc: &SearchService, q: &str) -> bool {
    let (query, prevalence, post) = commands(q);
    let scan = svc.prevalence_scan_plan(&query, &prevalence, &post, Some(ResultWindow { limit: 100, offset: 0 }));
    page_rescue_applies(&prevalence, &post, &scan, 3)
}

/// A pushdown row as ClickHouse returns it: per-dimension dict columns plus
/// the decorations. `(host_count, last_seen)` per dimension; `None` lookup =
/// no artifact of that kind on the row.
fn row(dp: (u64, &str), ip: (u64, &str), hp: (u64, &str), keys: [Option<&str>; 3]) -> Value {
    let mut o = serde_json::Map::new();
    for ((p, (hc, ls)), (col, key)) in [("_dp", dp), ("_ip", ip), ("_hp", hp)]
        .into_iter()
        .zip(["_domain_lookup", "_ip_lookup", "_hash_lookup"].into_iter().zip(keys))
    {
        o.insert(format!("{p}_host_count"), json!(hc));
        o.insert(format!("{p}_first_seen"), json!(ls));
        o.insert(format!("{p}_last_seen"), json!(ls));
        o.insert(format!("{p}_total_occurrences"), json!(if hc < 9999 { 3 } else { 0 }));
        o.insert(col.into(), key.map_or(Value::Null, |k| json!(k)));
    }
    redecorate_for_test(&mut o);
    Value::Object(o)
}

fn redecorate_for_test(o: &mut serde_json::Map<String, Value>) {
    o.insert("is_rare".into(), json!(0));
    super::prevalence_page_rescue::redecorate(o, 3);
}

fn miss() -> (u64, &'static str) {
    (9999, EPOCH)
}

fn rescued(artifact: &str, host_count: u64) -> RescuedArtifact {
    RescuedArtifact {
        artifact: artifact.to_string(),
        host_count,
        first_seen_us: 1_794_830_400_000_000,
        last_seen_us: 1_794_830_460_000_000,
        total_occurrences: 2,
    }
}

// ---------------------------------------------------------------- P1-1 scope

/// The rarity rule shape keeps the NAN-1705 in-SQL rescue, bounded by its own
/// `host_count < 3` (no `< 1000` superset, no bloated SQL, no false PARTIAL),
/// and gets NO page rescue: no extra probe on any scheduled tick.
#[tokio::test]
async fn rarity_rule_keeps_its_bounded_rescue_and_runs_no_page_probe() {
    let svc = sql_only_service("ocsf");
    let (_, _, post) = commands(RARITY_RULE);
    assert_eq!(decorated_filter_rescue_threshold(&post, 3), Some(3));
    assert!(!applies(&svc, RARITY_RULE));
    for q in [
        r#"source_type="soc_proc" | prevalence hash_prevalence < 5"#,
        r#"source_type="soc_proc" | prevalence hash_prevalence < 5 enrich=true"#,
        r#"source_type="soc_proc" | prevalence enrich=true | where is_rare=true"#,
        r#"source_type="soc_proc" | prevalence enrich=true | where host_count > 5"#,
        r#"source_type="soc_proc" | prevalence enrich=true | eval r=(host_count < 3)"#,
        r#"source_type="soc_proc" | prevalence enrich=true | stats count by host_count"#,
        r#"source_type="soc_proc" | stats count by process.name"#,
    ] {
        assert!(!applies(&svc, q), "{q} must keep its previous path");
    }
}

#[tokio::test]
async fn plain_decorating_enrich_gets_the_page_rescue() {
    let svc = sql_only_service("ocsf");
    for q in [
        PIVOT,
        r#"source_type="soc_proc" | prevalence enrich=true"#,
        r#"source_type="soc_proc" | prevalence enrich=true | head 20"#,
        r#"source_type="soc_proc" | prevalence enrich=true | sort -host_count"#,
    ] {
        assert!(applies(&svc, q), "{q}");
    }
}

/// Inspect SQL for a rarity rule and a plain enrich is unchanged: the rule
/// keeps its NAN-1705 note, a plain enrich carries no in-SQL rescue.
#[tokio::test]
async fn explain_is_unchanged_for_both_shapes() {
    let svc = sql_only_service("ocsf");
    let rule = render(&svc, RARITY_RULE, &ScopeSet::unrestricted()).await;
    assert!(rule.contains(RESCUE_NOTE), "{rule}");
    let pivot = render(&svc, PIVOT, &ScopeSet::unrestricted()).await;
    assert!(!pivot.starts_with("ERR:") && !pivot.contains(RESCUE_NOTE), "{pivot}");
    assert!(!pivot.contains("_rescue_idx"), "{pivot}");
}

// ------------------------------------------------- P1-2/P1-4 misses, then cap

/// Dict hits and dict-cached common artifacts (sentinel host count but a
/// real `last_seen`) never count against the cap: the one true miss at the
/// end of 60k rows is still probed.
#[test]
fn a_rare_key_survives_past_the_cap() {
    let common = (9999, "2026-11-19 10:00:00.000000");
    let mut rows: Vec<Value> = (0..60_000)
        .map(|i| {
            let hash = format!("{:064x}", i);
            let dim = if i % 2 == 0 { (12, "2026-11-19 10:00:00.000000") } else { common };
            row(miss(), miss(), dim, [None, None, Some(&hash)])
        })
        .collect();
    rows.push(row(miss(), miss(), miss(), [None, None, Some(SHA)]));
    let misses = collect_miss_keys(&rows, 50_000);
    assert_eq!(misses.keys, vec![(MissKind::Hash, SHA.to_string())]);
    assert_eq!(misses.dropped, 0);
}

/// Past the cap the misses are COUNTED (dropped > 0), reported as a PARTIAL
/// run, never silently lost.
#[tokio::test]
async fn misses_past_the_cap_flag_the_run_partial() {
    let rows: Vec<Value> = (0..5)
        .map(|i| row(miss(), miss(), miss(), [None, None, Some(&format!("{:064x}", i + 1))]))
        .collect();
    let misses = collect_miss_keys(&rows, 3);
    assert_eq!(misses.keys.len(), 3);
    assert_eq!(misses.dropped, 2);
    // The overflow path is live: it records the PARTIAL note the scheduler
    // reads for the rule run.
    let ((), notes) =
        crate::search::partial_run::collect(async { report_page_rescue_overflow(misses.dropped) })
            .await;
    assert_eq!(notes, vec![page_rescue_partial_message(2)]);
}

#[test]
fn only_keys_a_summary_can_hold_are_probed() {
    assert_eq!(MissKind::Hash.rescuable_key(&SHA.to_uppercase()), Some(SHA.to_string()));
    assert_eq!(MissKind::Hash.rescuable_key("ws-01"), None);
    assert_eq!(MissKind::Hash.rescuable_key("DC01"), None);
    assert_eq!(MissKind::Domain.rescuable_key("C2.BadExample.net"), Some("c2.badexample.net".into()));
    assert_eq!(MissKind::Domain.rescuable_key("ws-01"), None);
    assert_eq!(MissKind::Ip.rescuable_key("203.0.113.7"), Some("203.0.113.7".into()));
    assert_eq!(MissKind::Ip.rescuable_key("10.1.2.3"), None);
    assert_eq!(MissKind::Ip.rescuable_key("192.168.0.4"), None);
}

// ----------------------------------------------------------- P1-3 one probe

/// Every kind's keys go into ONE statement over the three summaries'
/// primary keys: no base-table scan, no per-kind round trips.
#[test]
fn one_probe_for_every_kind() {
    let keys = vec![
        (MissKind::Hash, SHA.to_string()),
        (MissKind::Domain, "c2.badexample.net".to_string()),
        (MissKind::Ip, "203.0.113.7".to_string()),
    ];
    let sql = build_miss_probe_sql(&keys, |k| format!("nanosiem.{}", k.summary_table()), "now() - INTERVAL 1 DAY", false)
        .expect("probe");
    assert_eq!(sql.matches("UNION ALL").count(), 2, "{sql}");
    assert_eq!(sql.matches("SELECT '").count(), 3, "{sql}");
    for (table, key) in [
        ("nanosiem.hash_prevalence_summary", SHA),
        ("nanosiem.domain_prevalence_summary", "c2.badexample.net"),
        ("nanosiem.ip_prevalence_summary", "203.0.113.7"),
    ] {
        assert!(sql.contains(&format!("FROM {table} ")), "{sql}");
        assert!(sql.contains(&format!("'{key}'")), "{sql}");
    }
    assert!(sql.contains("is_private = 0 AND ip IN ("), "{sql}");
    assert!(!sql.contains("logs"), "the probe must not scan the event table: {sql}");
    assert!(!sql.contains("PREWHERE"), "{sql}");
    assert!(!sql.contains("dictGet"), "the page path knows its misses already: {sql}");

    // The residual path cannot see the dict's last_seen: it re-checks the dict
    // BEFORE the GROUP BY, so a common artifact never reaches uniqMerge.
    let guarded = build_miss_probe_sql(&keys[..1], |k| k.summary_table().to_string(), "toDateTime64(0, 6)", true)
        .expect("probe");
    assert!(guarded.contains(
        "file_hash IN ('5f0c0d1e2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5') AND dictGetOrDefault('nanosiem.hash_prevalence_dict', 'last_seen', file_hash, toDateTime64(0, 6)) = toDateTime64(0, 6) GROUP BY"
    ), "{guarded}");
    assert!(!guarded.contains("UNION ALL"));
    assert!(build_miss_probe_sql(&[], |k| k.summary_table().to_string(), "x", false).is_none());
}

// ---------------------------------------------- decoration = Prevalence API

/// The UI pivot's row: the hash is a true dict miss, the domain is a dict hit
/// on 24 hosts. After the rescue the hash (1 host) wins exactly as the
/// pushdown CASEs and the Prevalence API say: 1 host, rare, score 7.
#[test]
fn a_rescued_hash_redecorates_the_row_like_the_api() {
    let mut rows = vec![row(
        (24, "2026-11-19 10:00:00.000000"),
        miss(),
        miss(),
        [Some("github.com"), None, Some(SHA)],
    )];
    assert_eq!(rows[0]["host_count"], json!(24));
    assert_eq!(rows[0]["prevalence_type"], json!("domain"));

    let found = parse_probe_rows(vec![json!({
        "kind": "hash", "artifact": SHA, "host_count": "1",
        "fs_us": "1794830400000000", "ls_us": "1794830460000000", "total_occurrences": "2"
    })]);
    assert_eq!(apply_page_rescue(&mut rows, &found, 3), 1);
    let r = &rows[0];
    assert_eq!(r["host_count"], json!(1));
    assert_eq!(r["is_rare"], json!(1));
    assert_eq!(r["prevalence_score"], json!(PrevalenceRepository::calculate_prevalence_score(1, 3)));
    assert_eq!(r["prevalence_score"], json!(7));
    assert_eq!(r["prevalence_type"], json!("hash"));
    assert_eq!(r["prevalence_artifact"], json!(SHA));
    assert_eq!(r["total_occurrences"], json!(2));
    assert_eq!(r["prevalence_first_seen"], json!("2026-11-16 12:00:00.000000"));
    assert_eq!(r["prevalence_last_seen"], json!("2026-11-16 12:01:00.000000"));
}

/// Rows whose misses the summary does not hold (or rows with no misses) are
/// left exactly as the dict decorated them.
#[test]
fn rows_without_a_resolved_miss_are_untouched() {
    let mut rows = vec![
        row(miss(), miss(), miss(), [None, None, Some(SHA)]),
        row((5, "2026-11-19 10:00:00.000000"), miss(), miss(), [Some("a.example.com"), None, None]),
    ];
    let before = rows.clone();
    let mut found = HashMap::new();
    found.insert((MissKind::Hash, "0".repeat(64)), rescued(&"0".repeat(64), 1));
    assert_eq!(apply_page_rescue(&mut rows, &found, 3), 0);
    assert_eq!(rows, before);
}

/// Ties keep the pushdown's domain → ip → hash order; scores round halves
/// away from zero like the Prevalence API (8 hosts at threshold 3: 52.5 → 53).
#[test]
fn ties_and_half_scores_match_the_pushdown_and_the_api() {
    let mut rows = vec![row(
        (8, "2026-11-19 10:00:00.000000"),
        miss(),
        miss(),
        [Some("cdn.example.com"), Some("203.0.113.9"), None],
    )];
    let mut found = HashMap::new();
    found.insert((MissKind::Ip, "203.0.113.9".to_string()), rescued("203.0.113.9", 8));
    assert_eq!(apply_page_rescue(&mut rows, &found, 3), 1);
    assert_eq!(rows[0]["prevalence_type"], json!("domain"));
    assert_eq!(rows[0]["host_count"], json!(8));
    assert_eq!(rows[0]["prevalence_score"], json!(53));
    assert_eq!(PrevalenceRepository::calculate_prevalence_score(8, 3), 53);
}

/// The in-SQL score uses the same rounding (ClickHouse `round` is
/// half-to-even and gave 52).
#[tokio::test]
async fn pushdown_score_rounds_halves_away_from_zero() {
    let pivot = render(&sql_only_service("ocsf"), PIVOT, &ScopeSet::unrestricted()).await;
    assert!(pivot.contains("toUInt8(floor(0.5 + 50 + "), "{pivot}");
    assert!(!pivot.contains("toUInt8(round("), "{pivot}");
}

// ------------------------------------------------------- residual (P2-6)

/// The residual path probes only kinds a summary can hold and only what the
/// dict did not resolve; a cached `PrevalenceData::empty` is a miss.
#[test]
fn residual_misses_skip_resolved_private_and_single_label_keys() {
    let mut hash_map: HashMap<String, PrevalenceData> = HashMap::new();
    let known = "a".repeat(64);
    hash_map.insert(
        known.clone(),
        PrevalenceData {
            artifact: known.clone(),
            artifact_type: crate::prevalence::ArtifactType::HashSha256,
            host_count: Some(4),
            total_occurrences: 9,
            first_seen: chrono::Utc::now(),
            last_seen: chrono::Utc::now(),
            is_rare: false,
            prevalence_score: 30,
        },
    );
    let placeholder = crate::prevalence::PrevalenceData::empty(SHA.to_string(), crate::prevalence::ArtifactType::HashSha256);
    assert!(placeholder.is_miss(), "a cached placeholder must be re-checked, not trusted");
    let empty = HashMap::new();
    let hashes = vec![known, SHA.to_string(), "WS-01".to_string()];
    let domains = vec!["ws-01".to_string(), "c2.badexample.net".to_string()];
    let ips = vec!["10.0.0.4".to_string(), "203.0.113.7".to_string()];
    let misses = residual_miss_keys(
        [
            (MissKind::Hash, &hashes, &hash_map),
            (MissKind::Domain, &domains, &empty),
            (MissKind::Ip, &ips, &empty),
        ],
        50_000,
    );
    assert_eq!(
        misses.keys,
        vec![
            (MissKind::Hash, SHA.to_string()),
            (MissKind::Domain, "c2.badexample.net".to_string()),
            (MissKind::Ip, "203.0.113.7".to_string()),
        ]
    );
    assert_eq!(misses.dropped, 0);
}
