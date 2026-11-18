// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5565: the prevalence pushdown with a FULL NAN-1705 rescue evaluates
//! EVERY rescued artifact and is sent with a `max_query_size` that fits it.
//!
//! The rule that failed every run on the v2.0.31 rehearsal box
//! (`newly_seen_rare_process_execution`) rescues every dict-blind artifact:
//! its `prevalence_first_seen` filter pins the rescue threshold to 999. The
//! NAN-1705 `transform` form wrote each key list four times (~392 B per
//! sha256) and crossed ClickHouse's 256 KiB default at 669 hashes. These tests
//! render the REAL pushdown SQL (the builder the execute path uses), check that
//! every key is present exactly once with its values, and check the
//! `max_query_size` the executor sends for it, including the pagination and
//! count wrappers.

use super::npl_golden_corpus_tests::sql_only_service;
use super::prevalence_processing::{
    PrevalenceRescue, RescuedArtifact, CLICKHOUSE_DEFAULT_MAX_QUERY_SIZE,
    PREVALENCE_RESCUE_KEY_BYTE_CAP, PREVALENCE_RESCUE_MAX_ARTIFACTS,
};
use super::*;
use crate::search::execution::clickhouse_executor::{
    escape_question_marks_in_strings, inject_limit_offset, max_query_size_for,
    wrap_query_for_count, MAX_QUERY_SIZE_CEILING,
};

/// `newly_seen_rare_process_execution` (rules repo, execution-ocsf/).
const RULE: &str = r#"metadata.log_source="windows_sysmon" | where class_uid=1007 AND activity_id=1 | prevalence process.file.hashes.value window=30d | where host_count < 5 AND prevalence_first_seen > now() - INTERVAL 24 HOUR | eval esc_very_rare_hash=(host_count < 3) | table time, process.name"#;

fn artifact(key: String, i: usize) -> RescuedArtifact {
    RescuedArtifact {
        artifact: key,
        host_count: 1 + (i as u64 % 4),
        // Realistic 16-digit epoch-µs values (2026-11-16 / 2026-11-17).
        first_seen_us: 1_794_830_400_000_000 + i as i64 * 1_000_003,
        last_seen_us: 1_794_916_800_000_000 + i as i64 * 1_000_007,
        total_occurrences: 3 + i as u64,
    }
}

fn sha256(i: usize) -> String {
    format!("{:064x}", (i as u128 + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15_f39c_c060_5ced_c834))
}

fn hashes(n: usize) -> Vec<RescuedArtifact> {
    (0..n).map(|i| artifact(sha256(i), i)).collect()
}

fn ips(n: usize) -> Vec<RescuedArtifact> {
    (0..n)
        .map(|i| artifact(format!("203.{}.{}.{}", 100 + i / 65536 % 100, i / 256 % 256, i % 256), i))
        .collect()
}

fn domains(n: usize) -> Vec<RescuedArtifact> {
    (0..n)
        .map(|i| artifact(format!("host{i}.updates.example-cdn-delivery.com"), i))
        .collect()
}

fn render_rule(rescue: &PrevalenceRescue) -> String {
    render_rule_shape(rescue).expect("pushdown renders").0
}

fn render_rule_shape(rescue: &PrevalenceRescue) -> Result<(String, usize, bool), SearchError> {
    let svc = sql_only_service("ocsf");
    let parsed = crate::query::parse_query(RULE).expect("rule parses");
    let (parsed, _) = crate::search::query_processing::apply_auto_sort(parsed);
    let post = extract_post_prevalence_commands(&parsed);
    let prevalence_commands = extract_prevalence_commands(&parsed);
    let start = chrono::DateTime::parse_from_rfc3339("2026-11-16T00:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let tr = TimeRange::new(start, start + chrono::Duration::hours(24));
    svc.generate_prevalence_pushdown_sql_with_shape(
        &parsed,
        &prevalence_commands,
        &post.commands,
        &tr,
        3,
        rescue,
    )
}

/// Every text the executor sends for this SQL (paged data query, count
/// companion), as the executor escapes it before `sized_query`.
fn executed_texts(sql: &str) -> Vec<String> {
    vec![
        escape_question_marks_in_strings(&inject_limit_offset(sql, 100, 0)),
        escape_question_marks_in_strings(&wrap_query_for_count(sql)),
    ]
}

/// Each executed text fits the `max_query_size` the executor sends with it.
fn assert_every_executed_text_fits(sql: &str) -> Option<usize> {
    let mut lifted = None;
    for text in executed_texts(sql) {
        let limit = max_query_size_for(text.len()).unwrap_or(CLICKHOUSE_DEFAULT_MAX_QUERY_SIZE);
        assert!(
            text.len() < limit,
            "{} B sent with max_query_size {limit}",
            text.len()
        );
        lifted = lifted.max(max_query_size_for(text.len()));
    }
    lifted
}

/// Every rescued artifact's key appears EXACTLY once (its entity's index
/// list), and its values sit at the same position in every value array.
fn assert_every_artifact_is_inlined(sql: &str, rescue: &PrevalenceRescue) {
    for (alias, set) in [
        ("_hp_rescue_idx", &rescue.hashes),
        ("_dp_rescue_idx", &rescue.domains),
        ("_ip_rescue_idx", &rescue.ips),
    ] {
        if set.is_empty() {
            assert!(!sql.contains(alias), "{alias} without a rescue");
            continue;
        }
        let def = sql
            .find(&format!(", range(1, {}), 0) AS {alias}", set.len() + 1))
            .unwrap_or_else(|| panic!("{alias} must number all {} keys", set.len()));
        let keys_start = sql[..def].rfind(", [").unwrap() + 3;
        let keys: Vec<&str> = sql[keys_start..def - 1]
            .split(", ")
            .map(|k| k.trim_matches('\''))
            .collect();
        assert_eq!(keys.len(), set.len(), "{alias}: every artifact inlined");
        for (p, r) in set.iter().enumerate() {
            assert_eq!(keys[p], r.artifact, "{alias} position {p}");
        }
        // Written once, never per projection (sampled: a full scan per key is
        // quadratic at the hard cap).
        for r in set.iter().step_by((set.len() / 50).max(1)) {
            assert_eq!(sql.matches(&format!("'{}'", r.artifact)).count(), 1, "{}", r.artifact);
        }
        // The host_count array carries every value at the same positions.
        let hc_prefix = "arrayElement(CAST([";
        let hc_suffix = format!("], 'Array(UInt16)'), {alias})");
        let hc_end = sql.find(&hc_suffix).expect("host_count array");
        let hc_start = sql[..hc_end].rfind(&hc_prefix).unwrap() + hc_prefix.len();
        let hcs: Vec<&str> = sql[hc_start..hc_end].split(", ").collect();
        assert_eq!(hcs.len(), set.len());
        for (p, r) in set.iter().enumerate() {
            assert_eq!(hcs[p], r.host_count.to_string(), "{alias} host_count {p}");
        }
    }
}

/// The acceptance case: 1000 sha256 + 1000 IPv4 + 1000 domains. Every key
/// gets its fresh values; the executor sends a `max_query_size` that fits.
#[tokio::test]
async fn thousand_of_each_entity_type_are_all_evaluated() {
    let rescue = PrevalenceRescue {
        hashes: hashes(1000),
        domains: domains(1000),
        ips: ips(1000),
        ..Default::default()
    };
    let empty = render_rule(&PrevalenceRescue::default());
    let sql = render_rule(&rescue);
    assert_every_artifact_is_inlined(&sql, &rescue);
    let lifted = assert_every_executed_text_fits(&sql);
    eprintln!(
        "NAN-5565 MEASURE 3x1000: empty-rescue SQL={} B, rescued SQL={} B, max_query_size sent={lifted:?} (default {CLICKHOUSE_DEFAULT_MAX_QUERY_SIZE})",
        empty.len(),
        sql.len(),
    );
    assert!(sql.contains("SELECT * EXCEPT (_dp_rescue_idx, _ip_rescue_idx, _hp_rescue_idx),"));
    assert!(!sql.contains("indexOf("), "indexOf scans per row; the index is a transform");
}

/// The rehearsal-box shape (hashes only) at 1000: below the default limit,
/// so the request carries no `max_query_size` at all.
#[tokio::test]
async fn thousand_sha256_rescues_need_no_lifted_limit() {
    let rescue = PrevalenceRescue {
        hashes: hashes(1000),
        ..Default::default()
    };
    let sql = render_rule(&rescue);
    assert_every_artifact_is_inlined(&sql, &rescue);
    let lifted = assert_every_executed_text_fits(&sql);
    eprintln!("NAN-5565 MEASURE 1x1000 sha256: SQL={} B, max_query_size sent={lifted:?}", sql.len());
    assert_eq!(lifted, None);
    assert!(sql.contains("SELECT * EXCEPT (_hp_rescue_idx),"));
}

/// Above the old 1000 cap (10,000 per type): still every artifact.
#[tokio::test]
async fn ten_thousand_of_each_entity_type_are_all_evaluated() {
    let rescue = PrevalenceRescue {
        hashes: hashes(10_000),
        domains: domains(10_000),
        ips: ips(10_000),
        ..Default::default()
    };
    let sql = render_rule(&rescue);
    assert_every_artifact_is_inlined(&sql, &rescue);
    let lifted = assert_every_executed_text_fits(&sql);
    eprintln!("NAN-5565 MEASURE 3x10000: SQL={} B, max_query_size sent={lifted:?}", sql.len());
    assert!(lifted.is_some());
}

/// The hard count cap on all three types, with maximal 253-byte domains:
/// past the inlined-key byte cap, so the LEAST-rare artifacts are left out
/// and counted for the PARTIAL report; every kept artifact is inlined, and
/// the text stays under the executor's ceiling.
#[tokio::test]
async fn hard_cap_with_maximal_domains_is_cut_loudly_and_stays_under_the_ceiling() {
    let n = PREVALENCE_RESCUE_MAX_ARTIFACTS;
    let long = |i: usize| format!("{}{i:06}.example.com", "a".repeat(234));
    let mut rescue = PrevalenceRescue {
        hashes: hashes(n),
        domains: (0..n).map(|i| artifact(long(i), i)).collect(),
        ips: ips(n),
        ..Default::default()
    };
    let requested = rescue.len();
    let dropped = rescue.cap_key_bytes(PREVALENCE_RESCUE_KEY_BYTE_CAP);
    assert!(dropped > 0, "this set is over the key cap");
    assert_eq!(rescue.dropped, dropped);
    assert!(rescue.key_bytes() <= PREVALENCE_RESCUE_KEY_BYTE_CAP);
    let sql = render_rule(&rescue);
    assert_every_artifact_is_inlined(&sql, &rescue);
    let lifted = assert_every_executed_text_fits(&sql).expect("lifted");
    eprintln!(
        "NAN-5565 MEASURE 3x{n} (253 B domains): requested={requested} kept={} dropped={dropped}, SQL={} B, max_query_size sent={lifted}",
        rescue.len(),
        sql.len()
    );
    assert!(lifted < MAX_QUERY_SIZE_CEILING);
}

/// A full count cap of ordinary keys (sha256, IPv4, short domains) fits the
/// key-byte cap: nothing is left out.
#[test]
fn full_count_cap_of_ordinary_keys_is_not_cut() {
    let n = PREVALENCE_RESCUE_MAX_ARTIFACTS;
    let mut rescue = PrevalenceRescue {
        hashes: hashes(n),
        domains: domains(n),
        ips: ips(n),
        ..Default::default()
    };
    assert_eq!(rescue.cap_key_bytes(PREVALENCE_RESCUE_KEY_BYTE_CAP), 0);
}

#[test]
fn max_query_size_is_only_sent_when_the_text_needs_it() {
    assert_eq!(max_query_size_for(0), None);
    assert_eq!(max_query_size_for(150_000), None);
    assert_eq!(max_query_size_for(200_000), Some(200_000 + 65_536));
    assert_eq!(max_query_size_for(1_000_000), Some(1_065_536));
    assert_eq!(max_query_size_for(usize::MAX / 2), Some(MAX_QUERY_SIZE_CEILING));
}

/// An empty rescue leaves no trace of NAN-5565 in the SQL.
#[tokio::test]
async fn empty_rescue_renders_no_rescue_shape() {
    let sql = render_rule(&PrevalenceRescue::default());
    assert!(!sql.contains("rescue_idx"));
    assert!(!sql.contains("EXCEPT"));
    assert!(sql.contains("base_logs AS (\n    SELECT *,\n"));
}

/// Manual check aid: `NAN5565_SQL_DUMP=<path>` writes the rule's pushdown SQL
/// with a small mixed rescue (two hashes, one domain, one IP) to `<path>`, to
/// run against mock tables and dictionaries in `clickhouse local`, and the
/// 3x1000 rescue to `<path>.full`.
#[tokio::test]
async fn dump_small_rescue_sql_when_requested() {
    let Ok(path) = std::env::var("NAN5565_SQL_DUMP") else {
        return;
    };
    let mut small = hashes(2);
    small[0].host_count = 2;
    let rescue = PrevalenceRescue {
        hashes: small,
        domains: domains(1),
        ips: ips(1),
        ..Default::default()
    };
    std::fs::write(&path, render_rule(&rescue)).expect("write dump");
    let full = PrevalenceRescue {
        hashes: hashes(1000),
        domains: domains(1000),
        ips: ips(1000),
        ..Default::default()
    };
    std::fs::write(format!("{path}.full"), render_rule(&full)).expect("write full dump");
}

/// The golden corpus hashes SQL without the rescue note; its prefix must be
/// the one the harness strips.
#[test]
fn the_golden_harness_strips_the_real_rescue_note() {
    let note = super::sql_execution::prevalence_rescue_explain_note();
    assert!(note.starts_with("\n\n-- Note: at execute time, artifacts the prevalence dict"));
}

/// NAN-5565 (b): when the rendered text would not fit the executor's
/// `max_query_size` ceiling, the least-rare rescued artifacts are left out
/// until it does, and the run is reported PARTIAL (the note the scheduler
/// records as `[partial] …` last_error), never truncated silently.
#[tokio::test]
async fn above_the_query_size_ceiling_the_run_is_partial_and_loud() {
    use super::prevalence_join::{render_within_query_size_ceiling, report_partial_rescue};
    let ceiling = 1_000_000;
    let mut rescue = PrevalenceRescue {
        hashes: hashes(10_000),
        domains: domains(10_000),
        ips: ips(10_000),
        ..Default::default()
    };
    let requested = rescue.len();
    let (out, notes) = crate::search::partial_run::collect(async {
        let out = render_within_query_size_ceiling(&mut rescue, ceiling, render_rule_shape);
        report_partial_rescue(&rescue);
        out
    })
    .await;
    let (sql, _, aggregation) = out.unwrap();
    assert!(!aggregation);
    assert!(max_query_size_for(sql.len()).unwrap() <= ceiling, "{} B", sql.len());
    assert!(rescue.dropped > 0 && !rescue.is_empty());
    assert_eq!(rescue.len() + rescue.dropped, requested);
    assert_every_artifact_is_inlined(&sql, &rescue);
    let message = crate::search::partial_run::partial_run_message(&notes).expect("PARTIAL note");
    assert!(message.starts_with("[partial] prevalence rescue left out "), "{message}");
    assert!(message.contains(&rescue.dropped.to_string()), "{message}");
    eprintln!(
        "NAN-5565 MEASURE ceiling {ceiling}: requested={requested} kept={} dropped={}, SQL={} B",
        rescue.len(),
        rescue.dropped,
        sql.len()
    );
}

/// If even the rescue-free query is over the ceiling, every rescued artifact
/// is reported left out and the query goes as is: ClickHouse then refuses it
/// with code 62, classified as a size failure (loud, never silent).
#[tokio::test]
async fn a_query_over_the_ceiling_without_any_rescue_drops_the_whole_rescue_loudly() {
    use super::prevalence_join::render_within_query_size_ceiling;
    let mut rescue = PrevalenceRescue {
        hashes: hashes(100),
        ..Default::default()
    };
    let (sql, _, _) = render_within_query_size_ceiling(&mut rescue, 1_000, render_rule_shape).unwrap();
    assert!(rescue.is_empty());
    assert_eq!(rescue.dropped, 100);
    assert!(!sql.contains("rescue_idx"));
}
