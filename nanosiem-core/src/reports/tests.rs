// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unit tests for report rendering + type parsing (NAN-1793). Pure — no DB.

use super::render::*;
use super::service::validate_cron_interval;
use super::types::*;
use serde_json::json;

#[test]
fn cron_interval_rejects_schedules_faster_than_the_floor() {
    // Every minute / every 2 minutes fire far more often than a report run can
    // complete — reject at definition time rather than melt the cluster.
    assert!(
        validate_cron_interval("* * * * *").is_err(),
        "every-minute cron must be rejected"
    );
    assert!(
        validate_cron_interval("*/2 * * * *").is_err(),
        "every-2-minute cron must be rejected"
    );
}

#[test]
fn cron_interval_accepts_reasonable_schedules() {
    // At/above the 300s floor.
    assert!(validate_cron_interval("*/5 * * * *").is_ok(), "every 5 min");
    assert!(validate_cron_interval("0 * * * *").is_ok(), "hourly");
    assert!(validate_cron_interval("0 8 * * *").is_ok(), "daily 08:00");
    assert!(validate_cron_interval("0 8 * * 1").is_ok(), "weekly Mon 08:00");
}

fn rows_two_col() -> Vec<serde_json::Value> {
    vec![
        json!({"src_ip": "10.0.0.1", "count": 5}),
        json!({"src_ip": "10.0.0.2", "count": 12}),
        json!({"src_ip": "quote\"comma,val", "count": 1}),
    ]
}

#[test]
fn source_type_roundtrip() {
    assert_eq!(ReportSourceType::from_str("search"), Some(ReportSourceType::Search));
    assert_eq!(
        ReportSourceType::from_str("dashboard"),
        Some(ReportSourceType::Dashboard)
    );
    assert_eq!(ReportSourceType::from_str("bogus"), None);
    assert_eq!(ReportSourceType::Search.as_str(), "search");
    assert_eq!(ReportSourceType::Dashboard.as_str(), "dashboard");
}

#[test]
fn run_status_strings() {
    assert_eq!(ReportRunStatus::Running.as_str(), "running");
    assert_eq!(ReportRunStatus::Success.as_str(), "success");
    assert_eq!(ReportRunStatus::Failed.as_str(), "failed");
}

#[test]
fn html_escape_covers_all_metacharacters() {
    let out = html_escape(r#"<b>&"'</b>"#);
    assert_eq!(out, "&lt;b&gt;&amp;&quot;&#39;&lt;/b&gt;");
}

#[test]
fn csv_escapes_commas_and_quotes_rfc4180() {
    let cols = vec!["src_ip".to_string(), "count".to_string()];
    let (bytes, truncated) = render_csv(&rows_two_col(), &cols, 10_000);
    let text = String::from_utf8(bytes).unwrap();
    assert!(!truncated);
    // Header + CRLF line endings.
    assert!(text.starts_with("src_ip,count\r\n"));
    // A field with a comma and a quote must be quoted and its quotes doubled.
    assert!(
        text.contains("\"quote\"\"comma,val\",1\r\n"),
        "got: {text}"
    );
}

#[test]
fn csv_truncates_at_byte_cap_and_flags() {
    // A cap smaller than the full body forces truncation after the header.
    let cols = vec!["src_ip".to_string(), "count".to_string()];
    let (bytes, truncated) = render_csv(&rows_two_col(), &cols, 20);
    assert!(truncated, "tiny cap must truncate");
    let text = String::from_utf8(bytes).unwrap();
    // Header always fits; body rows are dropped.
    assert!(text.starts_with("src_ip,count\r\n"));
}

#[test]
fn csv_neutralizes_spreadsheet_formula_injection() {
    // Attacker-controlled log data must not execute when the analyst opens the
    // exported CSV. Cells leading with = + - @ (incl. leading tab/CR) are
    // formulas in Excel/Sheets/LibreOffice — the classic CSV-injection / DDE
    // vector for a SIEM export.
    let rows = vec![
        json!({"user": "=cmd|'/c calc'!A0", "n": 1}),
        json!({"user": "@SUM(1+9)*cmd", "n": 2}),
        json!({"user": "+1+1", "n": 3}),
        json!({"user": "\t=1+1", "n": 4}),
    ];
    let cols = vec!["user".to_string(), "n".to_string()];
    let (bytes, _) = render_csv(&rows, &cols, 100_000);
    let text = String::from_utf8(bytes).unwrap();

    // Every formula-leading cell is prefixed with ' (treat-as-text marker).
    // No RFC-4180 quoting here: these fields carry no comma/double-quote/newline.
    assert!(text.contains("'=cmd|'/c calc'!A0"), "got: {text}");
    assert!(text.contains("'@SUM(1+9)*cmd"), "got: {text}");
    assert!(text.contains("'+1+1"), "got: {text}");
    // A formula behind leading whitespace is still neutralized.
    assert!(text.contains("'\t=1+1"), "got: {text}");
    // No raw formula survives at the start of a field.
    assert!(!text.contains(",=cmd"), "raw formula must not be emitted");
}

#[test]
fn csv_preserves_genuine_negative_numbers() {
    // `-` also leads formulas, but real negative numbers are DATA and must stay
    // numeric — neutralizing them would corrupt every numeric column.
    let rows = vec![
        json!({"delta": -5, "ratio": "-1.25"}),
        json!({"delta": "-5+3", "ratio": "0"}),
    ];
    let cols = vec!["delta".to_string(), "ratio".to_string()];
    let (bytes, _) = render_csv(&rows, &cols, 100_000);
    let text = String::from_utf8(bytes).unwrap();

    assert!(text.contains("-5,-1.25"), "negative numbers stay numeric: {text}");
    // `-5+3` is a formula, not a number → neutralized.
    assert!(text.contains("'-5+3"), "formula-shaped value neutralized: {text}");
}

#[test]
fn resolve_columns_prefers_explicit_then_union() {
    let explicit = vec!["b".to_string(), "a".to_string()];
    let rows = vec![json!({"a": 1, "b": 2})];
    assert_eq!(resolve_columns(&explicit, &rows), explicit);

    let inferred = resolve_columns(&[], &rows);
    // First-seen key order.
    assert_eq!(inferred, vec!["a".to_string(), "b".to_string()]);
}

#[test]
fn search_html_is_self_contained_and_escapes_query() {
    let now = chrono::Utc::now();
    let (bytes, _trunc) = render_search_html(
        "My <Report>",
        "error | stats count by src_ip",
        now - chrono::Duration::hours(1),
        now,
        now,
        &rows_two_col(),
        &["src_ip".to_string(), "count".to_string()],
        3,
        false,
        1_000_000,
    );
    let html = String::from_utf8(bytes).unwrap();
    // No external assets: no http(s) links, no <script src>, no <link rel>.
    assert!(!html.contains("http://"), "no external http assets");
    assert!(!html.contains("https://"), "no external https assets");
    assert!(!html.to_lowercase().contains("<script"), "no scripts");
    // Report name is HTML-escaped.
    assert!(html.contains("My &lt;Report&gt;"));
    // Query text is present (escaped) and there is a data table.
    assert!(html.contains("stats count by src_ip"));
    assert!(html.contains("<table>"));
}

#[test]
fn search_html_flags_result_truncation() {
    let now = chrono::Utc::now();
    let (bytes, _) = render_search_html(
        "R",
        "q",
        now - chrono::Duration::hours(1),
        now,
        now,
        &rows_two_col(),
        &["src_ip".to_string(), "count".to_string()],
        99_999,
        true, // result truncated
        1_000_000,
    );
    let html = String::from_utf8(bytes).unwrap();
    assert!(html.contains("truncated"), "must surface a truncation banner");
}

#[test]
fn dashboard_html_renders_chart_table_error_and_unsupported() {
    let now = chrono::Utc::now();
    let panels = vec![
        // Chartable line shape (label + numeric) → inline SVG.
        PanelOutput {
            title: "Events over time".into(),
            viz_type: "line".into(),
            columns: vec!["time".into(), "count".into()],
            rows: vec![
                json!({"time": "00:00", "count": 3}),
                json!({"time": "01:00", "count": 9}),
                json!({"time": "02:00", "count": 5}),
            ],
            error: None,
            unsupported: None,
        },
        // Table shape.
        PanelOutput {
            title: "Top hosts".into(),
            viz_type: "table".into(),
            columns: vec!["host".into(), "n".into()],
            rows: vec![json!({"host": "h1", "n": 2})],
            error: None,
            unsupported: None,
        },
        // Failed panel.
        PanelOutput {
            title: "Broken".into(),
            viz_type: "table".into(),
            columns: vec![],
            rows: vec![],
            error: Some("parse error".into()),
            unsupported: None,
        },
        // Unsupported (metric widget).
        PanelOutput {
            title: "Latency".into(),
            viz_type: "obs_metric".into(),
            columns: vec![],
            rows: vec![],
            error: None,
            unsupported: Some("Metric widget — not rendered in v1 reports.".into()),
        },
    ];

    let (bytes, _trunc) =
        render_dashboard_html("Ops", "Ops Dashboard", now - chrono::Duration::hours(6), now, now, &panels, 1_000_000);
    let html = String::from_utf8(bytes).unwrap();

    assert!(html.contains("<svg"), "line panel should render an inline SVG");
    assert!(html.contains("Top hosts") && html.contains("<table>"), "table panel");
    assert!(html.contains("Panel failed") && html.contains("parse error"), "error panel");
    assert!(html.contains("Metric widget"), "unsupported panel note");
    // Offline-safe.
    assert!(!html.contains("http://") && !html.contains("https://"));
}

#[test]
fn dashboard_html_handles_empty_panel() {
    let now = chrono::Utc::now();
    let panels = vec![PanelOutput {
        title: "Nothing".into(),
        viz_type: "table".into(),
        columns: vec!["a".into()],
        rows: vec![],
        error: None,
        unsupported: None,
    }];
    let (bytes, _) = render_dashboard_html("R", "D", now - chrono::Duration::hours(1), now, now, &panels, 1_000_000);
    let html = String::from_utf8(bytes).unwrap();
    assert!(html.contains("No data in the window"));
}

// ==========================================================================
// F-31: download-authorization predicate (report_artifact_download_allowed)
// ==========================================================================

mod download_predicate {
    use crate::reports::report_artifact_download_allowed;
    use std::collections::BTreeSet;

    fn deny(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }
    fn manifest(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn unrestricted_requester_always_allowed() {
        // Empty deny set → allow regardless of manifest/completeness.
        assert!(report_artifact_download_allowed(&deny(&[]), &manifest(&["insider_threat"]), true));
        assert!(report_artifact_download_allowed(&deny(&[]), &manifest(&[]), false));
    }

    #[test]
    fn complete_and_disjoint_is_allowed() {
        // Restricted requester, complete manifest that does NOT overlap → allow.
        assert!(report_artifact_download_allowed(
            &deny(&["insider_threat"]),
            &manifest(&["syslog", "apache"]),
            true,
        ));
    }

    #[test]
    fn complete_but_overlapping_is_denied() {
        assert!(!report_artifact_download_allowed(
            &deny(&["insider_threat"]),
            &manifest(&["syslog", "insider_threat"]),
            true,
        ));
    }

    #[test]
    fn incomplete_manifest_denies_every_restricted_requester() {
        // The pre-feature default ('{}' + complete=false): a restricted requester
        // is denied even though the manifest is empty (bytes may contain anything).
        assert!(!report_artifact_download_allowed(&deny(&["insider_threat"]), &manifest(&[]), false));
        // Even a non-overlapping incomplete manifest denies.
        assert!(!report_artifact_download_allowed(
            &deny(&["insider_threat"]),
            &manifest(&["syslog"]),
            false,
        ));
    }

    #[test]
    fn manifest_is_normalized_before_disjointness() {
        // Deny sets are normalized lowercase; the stored manifest is normalized
        // here too, so mixed-case / whitespace still overlaps.
        assert!(!report_artifact_download_allowed(
            &deny(&["insider_threat"]),
            &manifest(&["  Insider_Threat "]),
            true,
        ));
    }

    #[test]
    fn complete_empty_manifest_allows_restricted_requester() {
        // A COMPLETE empty manifest means a genuinely empty artifact (0 rows) —
        // nothing to protect, so even a restricted requester may download.
        assert!(report_artifact_download_allowed(&deny(&["insider_threat"]), &manifest(&[]), true));
    }
}
