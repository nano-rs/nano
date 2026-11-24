// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5660: the prevalence pushdown's base scan. `* | prevalence <field>`
//! used to sort the newest 1M full-width rows (`raw_logs` = `SELECT *` +
//! `ORDER BY timestamp DESC LIMIT 1000000`) and hit Code 241 on OCSF. The SQL
//! is rendered through the real `explain` path (first page of a default
//! search, limit 100) under both profiles; `e2e`-style execution against a
//! throwaway ClickHouse is in the PR notes.

use super::*;
use crate::auth::ScopeSet;
use crate::query::parse_query;
use crate::schema::{OcsfProfile, UdmProfile};
use crate::search::query_processing::{
    extract_post_prevalence_commands, extract_prevalence_commands, oom_admission, prevalence_scan_site,
    OomRisk,
};
use crate::search::service::npl_golden_corpus_tests::{render, sql_only_service};

async fn sql(profile: &str, query: &str) -> String {
    let sql = render(&sql_only_service(profile), query, &ScopeSet::unrestricted()).await;
    assert!(!sql.starts_with("ERR:"), "{profile}: {query} -> {sql}");
    assert!(sql.contains("WITH raw_logs AS"), "{profile}: not the pushdown: {query}\n{sql}");
    // CLAUDE.md ClickHouse rules hold on every shape.
    assert!(!sql.to_uppercase().contains("PREWHERE"), "{profile}: explicit PREWHERE:\n{sql}");
    assert!(!sql.contains("JSONExtract"), "{profile}: JSONExtract:\n{sql}");
    sql
}

/// The `raw_logs` CTE: from its head to the `logs_with_keys` CTE.
fn raw_logs(sql: &str) -> &str {
    let start = sql.find("WITH raw_logs AS").unwrap();
    let end = sql.find("logs_with_keys AS").unwrap();
    &sql[start..end]
}

/// The final SELECT's row columns, before the first decoration.
fn output_rows(sql: &str) -> &str {
    let start = sql.find("FROM logs_with_keys").unwrap();
    let end = sql[start..].find("AS host_count").unwrap() + start;
    &sql[start..end]
}

/// `raw_logs` bounds its wrapper with `ORDER BY timestamp DESC LIMIT n`.
fn bound(raw: &str, n: usize) -> bool {
    raw.contains(&format!("    ORDER BY timestamp DESC\n    LIMIT {n}\n),"))
}

/// The base itself ends in the window (the top-N runs on the table) and the
/// wrapper adds no bound of its own.
fn windowed(raw: &str, n: usize) -> bool {
    raw.contains(&format!("ORDER BY timestamp DESC LIMIT {n}\n    )\n),"))
        && !raw.contains("    ORDER BY timestamp DESC\n    LIMIT")
}

#[tokio::test]
async fn enrich_only_pushes_the_page_into_raw_logs() {
    for profile in ["ocsf", "udm"] {
        let (src, dst) = if profile == "ocsf" {
            ("src_endpoint.ip", "dst_endpoint.ip")
        } else {
            ("src_ip", "dest_ip")
        };
        let cases = [
            // prevalence alone
            format!("* | prevalence {src}"),
            format!("* | prevalence enrich=true"),
            // chained
            format!("* | prevalence {src} | prevalence {dst}"),
            // followed by row-wise stages
            format!("* | prevalence {src} | eval risky=if(host_count < 3, 1, 0) | table timestamp, {src}, host_count, risky"),
            format!("* | prevalence {src} | fields {src}, host_count | rename host_count as hc"),
        ];
        for q in &cases {
            let s = sql(profile, q).await;
            let raw = raw_logs(&s);
            assert!(windowed(raw, 100), "{profile}: {q}: page not pushed:\n{raw}");
            assert!(!raw.contains("LIMIT 1000000"), "{profile}: {q}: still the 1M bound:\n{raw}");
        }
    }
}

#[tokio::test]
async fn a_head_after_prevalence_narrows_the_pushed_window() {
    let s = sql("ocsf", "* | prevalence src_endpoint.ip | head 7").await;
    assert!(windowed(raw_logs(&s), 7), "{}", raw_logs(&s));
    // A head larger than the page keeps the page.
    let s = sql("ocsf", "* | prevalence src_endpoint.ip | head 5000").await;
    assert!(windowed(raw_logs(&s), 100), "{}", raw_logs(&s));
}

#[tokio::test]
async fn filters_and_aggregates_after_prevalence_do_not_push() {
    for q in [
        "* | prevalence dst_endpoint.ip | where host_count < 5",
        "* | prevalence dst_endpoint.ip | sort src_endpoint.ip",
        "* | prevalence dst_endpoint.ip | dedup src_endpoint.ip",
        "* | prevalence dst_endpoint.ip | tail 5",
    ] {
        let s = sql("ocsf", q).await;
        let raw = raw_logs(&s);
        assert!(bound(raw, 1_000_000), "{q}: expected the 1M safety bound:\n{raw}");
        assert!(output_rows(&s).contains("l.*"), "{q}: unprunable output must keep l.*:\n{s}");
    }
    // Aggregations keep the unbounded base (they need every row).
    for q in [
        "* | prevalence dst_endpoint.ip | stats count by src_endpoint.ip",
        "* | prevalence dst_endpoint.ip | timechart span=1h count()",
    ] {
        let s = sql("ocsf", q).await;
        let raw = raw_logs(&s);
        assert!(!raw.contains("ORDER BY timestamp DESC"), "{q}: aggregation input was bounded:\n{raw}");
    }
    // The filter form keeps the full window (NAN-1691).
    let s = sql("ocsf", "* | prevalence hash_prevalence < 5").await;
    assert!(!raw_logs(&s).contains("ORDER BY timestamp DESC"), "{}", raw_logs(&s));
}

#[tokio::test]
async fn an_ordered_or_limited_base_does_not_push() {
    for q in [
        "* | sort src_endpoint.ip | prevalence dst_endpoint.ip",
        "* | head 10 | prevalence dst_endpoint.ip",
        "* | reverse | prevalence dst_endpoint.ip",
    ] {
        let s = sql("ocsf", q).await;
        assert!(bound(raw_logs(&s), 1_000_000), "{q}: expected the unpushed plan:\n{}", raw_logs(&s));
    }
    // Row-wise stages before prevalence still push.
    let s = sql("ocsf", "* | eval x=1 | where src_endpoint.port > 0 | prevalence dst_endpoint.ip").await;
    assert!(windowed(raw_logs(&s), 100), "{}", raw_logs(&s));
}

#[tokio::test]
async fn a_table_of_promoted_columns_projects_the_output() {
    let q = "* | prevalence dst_endpoint.ip | where host_count < 5 \
             | eval risky=if(host_count < 3, 1, 0) | table timestamp, dst_endpoint.ip, src_endpoint.ip, host_count, risky";
    let s = sql("ocsf", q).await;
    assert!(raw_logs(&s).contains("LIMIT 1000000"), "{}", raw_logs(&s));
    let rows = output_rows(&s);
    assert!(!rows.contains("l.*"), "projected output still reads l.*:\n{rows}");
    for col in ["timestamp", "dst_endpoint.ip", "src_endpoint.ip"] {
        assert!(rows.contains(&format!("l.{col} AS ")), "missing {col}:\n{rows}");
    }
    // The filter and the eval still read `l` in ClickHouse.
    assert!(s.contains("risky"), "{s}");
    // A table field that is not a promoted column (an `event` JSON path)
    // keeps the full row.
    // Every row key the post-processing reads must be a column of that exact
    // name in the base, or the output keeps `l.*`: a JSON path, a UDM name the
    // OCSF profile maps to another column (`table` reads the row by the name
    // as written), and a base already narrowed before prevalence.
    for q in [
        "* | prevalence dst_endpoint.ip | where host_count < 5 | table dst_endpoint.ip, unmapped.foo",
        "* | prevalence dst_endpoint.ip | where host_count < 5 | table src_ip, host_count",
        "* | fields dst_endpoint.ip | prevalence dst_endpoint.ip | where host_count < 5 | table dst_endpoint.ip",
        "* | prevalence dst_endpoint.ip | where host_count < 5 | rename dst_endpoint.ip as d | table d",
        // This `where` runs in Rust on the row and reads src_endpoint.port.
        "* | prevalence dst_endpoint.ip | where _prevalence.host_count < 5 AND src_endpoint.port=443 \
         | table dst_endpoint.ip, host_count",
    ] {
        let s = sql("ocsf", q).await;
        assert!(output_rows(&s).contains("l.*"), "{q}:\n{s}");
    }
}

fn plan_for(query: &str, window: Option<ResultWindow>) -> PrevalenceScanPlan {
    let parsed = parse_query(query).unwrap();
    plan_prevalence_scan(
        &parsed,
        &extract_prevalence_commands(&parsed),
        &extract_post_prevalence_commands(&parsed).commands,
        window,
        &OcsfProfile::new(),
    )
}

#[test]
fn the_pushed_window_covers_offset_plus_page() {
    let w = |limit, offset| Some(ResultWindow { limit, offset });
    let p = plan_for("* | prevalence src_endpoint.ip", w(50, 200));
    assert_eq!((p.raw_logs_limit, p.window_pushed), (Some(250), true));
    let p = plan_for("* | prevalence src_endpoint.ip | head 20", w(50, 200));
    assert_eq!(p.raw_logs_limit, Some(220));
    // Never above the safety cap.
    let p = plan_for("* | prevalence src_endpoint.ip", w(50, 2_000_000));
    assert_eq!(p.raw_logs_limit, Some(ClickHouseSqlGenerator::DEFAULT_RESULT_LIMIT));
    // No window (internal callers): the safety cap, as before.
    let p = plan_for("* | prevalence src_endpoint.ip", None);
    assert_eq!((p.raw_logs_limit, p.window_pushed), (Some(1_000_000), false));
    assert!(p.is_wide_newest_scan());
}

#[test]
fn only_the_unpushed_unprojected_scan_is_gated() {
    let w = Some(ResultWindow { limit: 50, offset: 0 });
    assert!(!plan_for("* | prevalence src_endpoint.ip", w).is_wide_newest_scan());
    assert!(plan_for("* | prevalence src_endpoint.ip | where host_count < 5", w).is_wide_newest_scan());
    assert!(!plan_for(
        "* | prevalence src_endpoint.ip | where host_count < 5 | table src_endpoint.ip, host_count",
        w
    )
    .is_wide_newest_scan());
    assert!(!plan_for("* | prevalence src_endpoint.ip | stats count by src_endpoint.ip", w).is_wide_newest_scan());
    assert!(!plan_for("* | prevalence hash_prevalence < 5", w).is_wide_newest_scan());
    // UDM resolves its own promoted columns.
    let parsed = parse_query("* | prevalence src_ip | where host_count < 5 | table src_ip, dest_ip").unwrap();
    let plan = plan_prevalence_scan(
        &parsed,
        &extract_prevalence_commands(&parsed),
        &extract_post_prevalence_commands(&parsed).commands,
        w,
        &UdmProfile::new(),
    );
    assert_eq!(
        plan.output_columns,
        Some(vec!["dest_ip".to_string(), "src_ip".to_string(), "timestamp".to_string()])
    );
}

#[test]
fn the_guard_site_follows_the_unfiltered_rule() {
    let q = parse_query("* | prevalence dst_endpoint.ip | where host_count < 5").unwrap();
    let site = prevalence_scan_site(&q).expect("unfiltered search is a candidate");
    assert_eq!(site.risk, OomRisk::UnboundedPrevalenceScan);
    assert_eq!(
        oom_admission::admission_class(&site),
        oom_admission::AdmissionClass::CostGated {
            bytes_per_row: oom_admission::ROW_PRESERVING_BYTES_PER_ROW
        }
    );
    // The estimate is the search the prevalence stage reads.
    assert!(oom_admission::estimate_query(&site).is_some());
    for filtered in [
        "class_uid=4001 | prevalence dst_endpoint.ip | where host_count < 5",
        "* | head 1000 | prevalence dst_endpoint.ip | where host_count < 5",
    ] {
        assert!(prevalence_scan_site(&parse_query(filtered).unwrap()).is_none(), "{filtered}");
    }
}

#[test]
fn the_refusal_names_the_event_count() {
    let budget_rows = oom_admission::row_budget(
        oom_admission::ROW_PRESERVING_BYTES_PER_ROW,
        oom_admission::resolve_budget_bytes(None, Some(2_748_779_069), None),
    );
    let err = oom_admission::decide(&OomRisk::UnboundedPrevalenceScan, 1_000_000, false, budget_rows)
        .expect_err("1M wide rows exceed a 2.56 GiB ceiling's budget");
    assert!(err.starts_with("prevalence on an unfiltered search that cannot stop at the page"), "{err}");
    assert!(err.contains("would feed ~1,000,000 events"), "{err}");
    assert!(oom_admission::decide(&OomRisk::UnboundedPrevalenceScan, 1_000, false, budget_rows).is_ok());
}

/// With the window pushed the data SQL holds only the page, so page 1's total
/// comes from the base: the same rows the unpushed `raw_logs` kept (base
/// count capped at 1M). Filter-free counts stay metadata-served; filtered ones
/// stop one row past the cap.
#[tokio::test]
async fn the_pushed_total_counts_the_base_under_the_old_cap() {
    let svc = sql_only_service("ocsf");
    let start = chrono::DateTime::parse_from_rfc3339("2026-11-11T00:00:00Z").unwrap().with_timezone(&chrono::Utc);
    let tr = crate::query::TimeRange::new(start, start + chrono::Duration::days(7));
    let count = |q: &str| svc.prevalence_base_count_sql(&parse_query(q).unwrap(), &tr, crate::query::GeneratorScope::unrestricted()).unwrap();

    let unfiltered = count("* | prevalence src_endpoint.ip | head 10");
    assert!(unfiltered.starts_with("SELECT count(*) AS cnt FROM (SELECT"), "{unfiltered}");
    assert!(!unfiltered.contains("LIMIT"), "a filter-free count must stay unbounded:\n{unfiltered}");
    assert!(!unfiltered.contains("ORDER BY"), "{unfiltered}");
    assert!(!unfiltered.contains("dictGet"), "the count must not decorate:\n{unfiltered}");

    let filtered = count("class_uid=4001 | prevalence src_endpoint.ip");
    assert!(filtered.contains("AS matched LIMIT 1000000) AS subquery"), "{filtered}");
}
