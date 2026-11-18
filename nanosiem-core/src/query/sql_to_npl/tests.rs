// SPDX-License-Identifier: AGPL-3.0-or-later

use chrono::{TimeZone, Utc};

use super::*;
use crate::query::Dataset;
use crate::schema::{profile_for_id, SchemaId};

const W: &str = "timestamp >= {earliest:DateTime64(6, 'UTC')} AND timestamp <= {latest:DateTime64(6, 'UTC')}";

fn udm() -> ConvertContext {
    ConvertContext::new(profile_for_id(SchemaId::Udm))
}

fn ocsf() -> ConvertContext {
    ConvertContext::new(profile_for_id(SchemaId::Ocsf))
}

fn conv(sql: &str, ctx: &ConvertContext) -> SqlToNpl {
    convert_sql_to_npl(sql, ctx)
}

fn exact(sql: &str, ctx: &ConvertContext) -> String {
    let r = conv(sql, ctx);
    assert!(r.unsupported.is_none(), "{sql}: unsupported {:?}", r.unsupported);
    assert!(r.exact, "{sql} → {:?}: {:#?}", r.npl, r.differences);
    r.npl.expect("npl")
}

#[cfg(feature = "enterprise")]
#[test]
fn the_placeholders_match_the_playbook_and_lane_literals() {
    assert_eq!(WINDOW_START_PARAM, crate::hunts::playbook::PIVOT_WINDOW_START_PARAM);
    assert_eq!(WINDOW_END_PARAM, crate::hunts::playbook::PIVOT_WINDOW_END_PARAM);
    assert_eq!(EVENTS_TABLE_PLACEHOLDER, crate::hunts::playbook::EVENTS_TABLE_PLACEHOLDER);
    assert_eq!(SIGNALS_TABLE_PLACEHOLDER, crate::hunts::playbook::SIGNALS_TABLE_PLACEHOLDER);
}

#[test]
fn the_window_becomes_the_time_range_not_a_term() {
    let r = conv(&format!("SELECT * FROM logs WHERE {W} AND dest_port = 443"), &udm());
    assert_eq!(r.npl.as_deref(), Some("dest_port=443"));
    assert_eq!(r.earliest, Some(TimeBound::WindowStart));
    assert_eq!(r.latest, Some(TimeBound::WindowEnd));
    assert!(r.exact, "{:?}", r.differences);
}

#[test]
fn literal_time_bounds_are_returned_as_instants() {
    let r = conv(
        "SELECT * FROM logs WHERE timestamp >= '2026-11-01 00:00:00' AND timestamp < toDateTime64('2026-11-02T00:00:00Z', 6) AND dest_port = 22",
        &udm(),
    );
    assert_eq!(r.earliest, Some(TimeBound::At(Utc.with_ymd_and_hms(2026, 11, 1, 0, 0, 0).unwrap())));
    assert_eq!(r.latest, Some(TimeBound::At(Utc.with_ymd_and_hms(2026, 11, 2, 0, 0, 0).unwrap())));
    let (a, b) = (Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(), Utc.with_ymd_and_hms(2026, 1, 2, 0, 0, 0).unwrap());
    assert_eq!(resolve_bound(Some(&TimeBound::WindowStart), Some(a), Some(b)), Some(a));
    assert_eq!(resolve_bound(Some(&TimeBound::WindowEnd), Some(a), Some(b)), Some(b));
}

#[test]
fn the_lane_example_converts_exactly_on_both_profiles() {
    let sql = format!(
        "SELECT `device.hostname` AS host, count() AS n FROM ocsf_logs WHERE {W} AND lower(`actor.process.name`) = 'powershell.exe' GROUP BY host ORDER BY n DESC"
    );
    assert_eq!(
        exact(&sql, &ocsf()),
        "actor.process.name=\"powershell.exe\" | stats count() as n by device.hostname | sort -n"
    );
    let sql = format!(
        "SELECT src_host AS host, count() AS n FROM logs WHERE {W} AND lower(process_name) = 'powershell.exe' GROUP BY host ORDER BY n DESC"
    );
    assert_eq!(exact(&sql, &udm()), "process_name=\"powershell.exe\" | stats count() as n by src_host | sort -n");
}

#[test]
fn case_sensitive_sql_equality_is_reported_as_broader() {
    let r = conv(&format!("SELECT * FROM logs WHERE {W} AND process_name = 'PowerShell.exe'"), &udm());
    assert_eq!(r.npl.as_deref(), Some("process_name=\"PowerShell.exe\""));
    assert!(!r.exact);
    assert!(r.differences.iter().all(|d| d.kind == DifferenceKind::Broader), "{:?}", r.differences);
}

#[test]
fn values_without_letters_compare_exactly() {
    exact(&format!("SELECT * FROM logs WHERE {W} AND src_ip = '10.0.0.5' AND dest_port IN (445, 139)"), &udm());
    exact(&format!("SELECT * FROM logs WHERE {W} AND user != ''"), &udm());
}

#[test]
fn ilike_and_lower_like_become_case_insensitive_substring_forms() {
    assert_eq!(
        exact(&format!("SELECT * FROM logs WHERE {W} AND command_line ILIKE '%-EncodedCommand%'"), &udm()),
        "command_line CONTAINS \"-EncodedCommand\""
    );
    assert_eq!(
        exact(&format!("SELECT * FROM logs WHERE {W} AND lower(command_line) LIKE '%vssadmin delete shadows%'"), &udm()),
        "command_line CONTAINS \"vssadmin delete shadows\""
    );
    assert_eq!(
        exact(&format!("SELECT * FROM logs WHERE {W} AND process_name ILIKE 'power%'"), &udm()),
        "process_name STARTSWITH \"power\""
    );
}

#[test]
fn boolean_structure_survives() {
    exact(
        &format!(
            "SELECT * FROM logs WHERE {W} AND (lower(user) = 'admin' OR lower(user) = 'root') AND NOT (dest_port = 22)"
        ),
        &udm(),
    );
}

#[test]
fn null_checks_go_to_a_where_clause() {
    let npl = exact(&format!("SELECT * FROM logs WHERE {W} AND user IS NULL AND dest_port = 3389"), &udm());
    assert_eq!(npl, "dest_port=3389 | where isnull(user)");
}

#[test]
fn aggregates_group_by_having_order_and_limit() {
    let npl = exact(
        &format!(
            "SELECT src_ip, count() AS n, sum(bytes_out) AS out FROM logs WHERE {W} AND dest_port = 443 \
             GROUP BY src_ip HAVING n > 10 ORDER BY out DESC LIMIT 20"
        ),
        &udm(),
    );
    assert_eq!(
        npl,
        "dest_port=443 | stats count() as n, sum(bytes_out) as out by src_ip | where n>10 | sort -out | head 20"
    );
}

#[test]
fn a_projected_column_list_becomes_table() {
    let npl = exact(&format!("SELECT timestamp, src_host, command_line FROM logs WHERE {W} AND dest_port = 4444 LIMIT 50"), &udm());
    assert_eq!(npl, "dest_port=4444 | head 50 | table timestamp, src_host, command_line");
}

#[test]
fn uniq_exact_reports_the_empty_value_difference() {
    let r = conv(&format!("SELECT src_host, uniqExact(user) AS users FROM logs WHERE {W} GROUP BY src_host"), &udm());
    assert_eq!(r.npl.as_deref(), Some("* | stats dc(user) as users by src_host"));
    assert!(!r.exact);
    assert!(r.differences.iter().any(|d| d.detail.contains("empty")), "{:?}", r.differences);
}

#[test]
fn out_of_subset_queries_are_refused_with_a_reason_never_guessed() {
    for (sql, why) in [
        (format!("WITH x AS (SELECT 1) SELECT * FROM logs WHERE {W}"), "WITH"),
        (format!("SELECT * FROM logs l JOIN logs r ON l.id = r.id WHERE {W}"), "JOIN"),
        (format!("SELECT * FROM logs WHERE {W} AND id IN (SELECT id FROM logs WHERE {W} AND dest_port = 1 LIMIT 5)"), "subquery"),
        (format!("SELECT * FROM logs WHERE {W} AND id IN (SELECT matched_log_id FROM signals WHERE {W} GROUP BY matched_log_id HAVING count() > 1)"), "correlates events with signals"),
        (format!("SELECT * FROM system.users WHERE {W}"), "table"),
        (format!("SELECT src_host, count() OVER () FROM logs WHERE {W}"), "window function"),
        (format!("SELECT * FROM logs WHERE {W} AND positionCaseInsensitive(command_line, 'x') > 0"), "comparison"),
        (format!("SELECT DISTINCT src_host FROM logs WHERE {W}"), "DISTINCT"),
        (format!("SELECT * FROM logs WHERE {W} LIMIT 10 OFFSET 5"), "OFFSET"),
        (format!("SELECT * FROM (SELECT * FROM logs WHERE {W}) WHERE dest_port = 1"), "subquery in FROM"),
        (format!("SELECT toStartOfHour(timestamp) AS h, count() FROM logs WHERE {W} GROUP BY h"), "computed column"),
        ("SELECT * FROM logs WHERE timestamp > now() - INTERVAL 1 DAY".to_string(), "time bound"),
        (format!("SELECT * FROM logs WHERE {W} AND id IN {{ids:Array(UUID)}}"), "parameter"),
    ] {
        let r = conv(&sql, &udm());
        let u = r.unsupported.unwrap_or_else(|| panic!("{sql} converted to {:?}", r.npl));
        assert!(u.reason.contains(why), "{sql}: {}", u.reason);
        assert!(r.npl.is_none() && !r.exact);
    }
}

#[test]
fn unsupported_reasons_carry_a_span_where_the_parser_kept_one() {
    let sql = format!("SELECT * FROM logs WHERE {W} AND positionCaseInsensitive(command_line, 'x') > 0");
    let u = conv(&sql, &udm()).unsupported.expect("unsupported");
    let span = u.span.expect("span");
    assert_eq!(span.start_line, 1);
    // The placeholders were swapped for same-length identifiers, so columns
    // point into the ORIGINAL text.
    let col = span.start_column as usize - 1;
    assert!(sql[col..].starts_with("positionCaseInsensitive"), "{}", &sql[col..]);
}

#[test]
fn the_distributed_twin_and_qualified_names_read_as_the_events_table() {
    exact(&format!("SELECT * FROM default.logs_distributed WHERE {W} AND dest_port = 53"), &udm());
    exact(&format!("SELECT * FROM {{events}} WHERE {W} AND dest_port = 53"), &udm());
    exact(&format!("SELECT * FROM logs AS l WHERE {W} AND l.dest_port = 53"), &udm());
}

#[test]
fn the_wrong_profile_table_is_refused() {
    let r = conv(&format!("SELECT * FROM logs WHERE {W}"), &ocsf());
    assert!(r.unsupported.expect("refused").reason.contains("ocsf_logs"));
}

#[test]
fn compare_flags_a_wrong_npl() {
    let sql = format!("SELECT * FROM logs WHERE {W} AND dest_port = 443");
    let diffs = compare_npl_with_sql(&sql, "dest_port=80", &udm()).unwrap();
    assert!(diffs.iter().any(|d| d.kind == DifferenceKind::Different), "{diffs:?}");
    assert!(compare_npl_with_sql(&sql, "dest_port=443", &udm()).unwrap().is_empty());
}

#[test]
fn string_values_with_quotes_and_backslashes_round_trip() {
    exact(&format!(r"SELECT * FROM logs WHERE {W} AND lower(file_path) = 'c:\\windows\\temp\\x.exe'"), &udm());
    exact(&format!("SELECT * FROM logs WHERE {W} AND lower(command_line) LIKE '%\"-enc\"%'"), &udm());
}

#[test]
fn the_runner_row_cap_wrapper_reads_through() {
    // `limit_wrapped`, as the Agent Lane query audit records it.
    let inner = format!("SELECT src_ip, count() AS n FROM logs WHERE {W} GROUP BY src_ip ORDER BY n DESC");
    let npl = exact(&format!("SELECT * FROM ({inner}) LIMIT 51"), &udm());
    assert_eq!(npl, "* | stats count() as n by src_ip | sort -n | head 51");
    let npl = exact(&format!("SELECT * FROM ({inner} LIMIT 10) LIMIT 51"), &udm());
    assert!(npl.ends_with("| head 10"), "{npl}");
}

/// The hunts mock (`nanosiem-web/dev/hunts-mock/mock-plugin.mjs`) serves
/// canned conversions for its SQL trail steps; they must be this converter's
/// real output.
#[test]
fn the_hunts_mock_conversions_are_real() {
    let r = conv(
        &format!("SELECT src_host, count() AS n FROM logs WHERE {W} AND lower(process_name) = 'powershell.exe' AND command_line ILIKE '%-enc%' GROUP BY src_host ORDER BY n DESC LIMIT 20"),
        &udm(),
    );
    assert!(r.exact, "{:?}", r.differences);
    assert_eq!(
        r.npl.as_deref(),
        Some("process_name=\"powershell.exe\" command_line CONTAINS \"-enc\" | stats count() as n by src_host | sort -n | head 20")
    );
    let r = conv(
        &format!("SELECT dest_ip, dest_port, count() AS c FROM logs WHERE {W} AND src_host = 'WKS-FIN-0231' AND dest_port = 443 GROUP BY dest_ip, dest_port ORDER BY c DESC"),
        &udm(),
    );
    assert_eq!(r.npl.as_deref(), Some("src_host=\"WKS-FIN-0231\" dest_port=443 | stats count() as c by dest_ip, dest_port | sort -c"));
    assert_eq!(r.differences.len(), 1);
    assert_eq!(r.differences[0].kind, DifferenceKind::Broader);
}

#[test]
fn a_table_search_cannot_read_is_flagged_so_ai_is_not_offered() {
    let system = conv(&format!("SELECT * FROM system.users WHERE {W}"), &udm());
    assert!(system.unsupported.as_ref().unwrap().no_search_dataset);
    let join = conv(&format!("SELECT * FROM logs l JOIN logs r ON l.id = r.id WHERE {W}"), &udm());
    assert!(!join.unsupported.as_ref().unwrap().no_search_dataset);
    // NAN-5612 / NAN-5614: events correlated with signals other than through
    // a plain `IN (SELECT …)` filter has no nPL form, AI-written or not.
    let mixed = SqlToNplRequest {
        sql: format!("SELECT * FROM logs WHERE {W} AND id IN (SELECT matched_log_id FROM {{signals}} WHERE {W} ORDER BY risk_score DESC LIMIT 10)"),
        window_start: None,
        window_end: None,
    };
    let mixed = convert_request(&mixed, &udm());
    assert!(mixed.no_search_dataset && mixed.npl.is_none(), "{mixed:?}");
    assert!(mixed.unsupported_reason.as_deref().unwrap().contains("correlates events with signals"), "{mixed:?}");
}

// --- NAN-5612: dataset=signals ---

/// SQL over the detections (`{signals}`) converts to nPL on Search's
/// `dataset=signals`, proven exact by the same round trip as events.
#[test]
fn sql_over_the_detections_converts_to_dataset_signals_exactly() {
    for ctx in [ocsf(), udm()] {
        for (sql, npl) in [
            (
                format!("SELECT rule_name, count() AS fires FROM {{signals}} WHERE {W} GROUP BY rule_name ORDER BY fires DESC LIMIT 50"),
                "* | stats count() as fires by rule_name | sort -fires | head 50",
            ),
            (
                format!("SELECT risk_entity, count() AS rules, sum(risk_score) AS total FROM {{signals}} WHERE {W} AND severity IN ('high', 'critical') GROUP BY risk_entity ORDER BY rules DESC"),
                "severity IN (\"high\", \"critical\") | stats count() as rules, sum(risk_score) as total by risk_entity | sort -rules",
            ),
            (
                format!("SELECT * FROM {{signals}} WHERE {W} AND detection_path = 'scheduled' AND risk_score >= 50 ORDER BY timestamp DESC LIMIT 20"),
                "detection_path=\"scheduled\" risk_score>=50 | sort -timestamp | head 20",
            ),
        ] {
            let r = conv(&sql, &ctx);
            assert_eq!(r.dataset, Dataset::Signals, "{sql}");
            assert!(r.unsupported.is_none(), "{sql}: {:?}", r.unsupported);
            assert_eq!(r.npl.as_deref(), Some(npl), "{sql}");
            assert!(r.exact, "{sql} -> {:?}: {:#?}", r.npl, r.differences);
            let req = SqlToNplRequest { sql: sql.clone(), window_start: None, window_end: None };
            assert_eq!(convert_request(&req, &ctx).dataset, "signals");
        }
    }
}

/// The Agent Lane row cap and the `_distributed` twin read the same detections.
#[test]
fn the_row_cap_and_distributed_twin_of_signals_convert_too() {
    let r = conv(&format!("SELECT * FROM (SELECT rule_name, count() AS n FROM {{signals}} WHERE {W} GROUP BY rule_name) LIMIT 10"), &ocsf());
    assert_eq!(r.dataset, Dataset::Signals);
    assert!(r.exact, "{:?}: {:#?}", r.npl, r.differences);
    let r = conv(&format!("SELECT * FROM signals_local WHERE {W}"), &ocsf());
    assert!(r.unsupported.as_ref().unwrap().reason.contains("one shard"), "{:?}", r.unsupported);
}

/// The physical `signals` table holds real-time detections only;
/// `dataset=signals` also reads scheduled ones, so the conversion is honest
/// about being broader instead of claiming exact.
#[test]
fn the_raw_signals_table_converts_but_is_not_called_exact() {
    for table in ["signals", "signals_distributed"] {
        let r = conv(&format!("SELECT rule_name, count() AS n FROM {table} WHERE {W} GROUP BY rule_name"), &ocsf());
        assert_eq!(r.dataset, Dataset::Signals, "{table}");
        assert_eq!(r.npl.as_deref(), Some("* | stats count() as n by rule_name"), "{table}");
        assert!(!r.exact, "{table}");
        assert!(
            r.differences.iter().any(|d| d.kind == DifferenceKind::Broader && d.detail.contains("scheduled")),
            "{table}: {:?}",
            r.differences
        );
    }
}

/// The comparator compiles foreign nPL (the AI path) against the dataset the
/// SQL reads, so a correct signals translation verifies exact and the same
/// nPL against the events SQL does not.
#[test]
fn foreign_npl_is_compared_on_the_sql_dataset() {
    let ctx = ocsf();
    let sql = format!("SELECT rule_name, count() AS n FROM {{signals}} WHERE {W} GROUP BY rule_name");
    assert_eq!(sql_dataset(&sql, &ctx), Dataset::Signals);
    assert!(compare_npl_with_sql(&sql, "* | stats count() as n by rule_name", &ctx).unwrap().is_empty());
    assert_eq!(sql_dataset(&format!("SELECT * FROM ocsf_logs WHERE {W}"), &ctx), Dataset::Logs);
}

/// A refused signals query still reports which dataset it reads.
#[test]
fn an_unsupported_signals_query_still_names_its_dataset() {
    let r = conv(&format!("SELECT rule_name, groupUniqArray(4)(severity) AS s, quantile(0.9)(risk_score) AS q FROM {{signals}} WHERE {W} GROUP BY rule_name"), &ocsf());
    assert!(r.unsupported.is_some());
    assert_eq!(r.dataset, Dataset::Signals);
}

// --- review fixes (PR #9876) ---

#[test]
fn lower_against_an_uppercase_value_is_never_exact() {
    for sql in [
        format!("SELECT * FROM logs WHERE {W} AND lower(user) = 'Admin'"),
        format!("SELECT * FROM logs WHERE {W} AND lower(user) IN ('Admin', 'root')"),
        format!("SELECT * FROM logs WHERE {W} AND lower(command_line) LIKE '%Vssadmin%'"),
    ] {
        let r = conv(&sql, &udm());
        assert!(!r.exact, "{sql}");
        assert!(r.unsupported.as_ref().is_some_and(|u| u.reason.contains("uppercase")), "{sql}: {:?}", r.unsupported);
        // The comparator alone (the AI path) must not call the folded nPL exact.
        let d = compare_npl_with_sql(&sql, &r.npl.clone().unwrap_or_else(|| "user=\"admin\"".into()), &udm()).unwrap();
        assert!(d.iter().any(|d| d.kind == DifferenceKind::Different), "{sql}: {d:?}");
    }
}

#[test]
fn a_self_referencing_cte_is_an_error_not_a_crash() {
    for sql in [
        format!("WITH x AS (SELECT * FROM x) SELECT * FROM x WHERE {W}"),
        format!("WITH a AS (SELECT * FROM b), b AS (SELECT * FROM a) SELECT * FROM a WHERE {W}"),
    ] {
        assert!(compare_npl_with_sql(&sql, "*", &udm()).is_err(), "{sql}");
    }
}

#[test]
fn stage_order_matters_to_the_comparison() {
    let sql = format!("SELECT * FROM logs WHERE {W} AND dest_port = 22 LIMIT 10");
    assert!(compare_npl_with_sql(&sql, "dest_port=22 | head 10", &udm()).unwrap().is_empty());
    assert!(!compare_npl_with_sql(&sql, "* | head 10 | where dest_port=22", &udm()).unwrap().is_empty());
    let sql = format!("SELECT count() AS n FROM logs WHERE {W} LIMIT 10");
    assert!(!compare_npl_with_sql(&sql, "* | head 10 | stats count() as n", &udm()).unwrap().is_empty());
    let sql = format!("SELECT src_ip, count() AS n FROM logs WHERE {W} GROUP BY src_ip");
    assert!(!compare_npl_with_sql(&sql, "* | stats count() as n by src_ip, user | stats count() as n by src_ip", &udm())
        .unwrap()
        .is_empty());
}

#[test]
fn clauses_the_comparison_does_not_model_are_differences() {
    for sql in [
        format!("SELECT * FROM logs WHERE {W} AND dest_port = 22 LIMIT 10 OFFSET 100"),
        format!("SELECT * FROM logs WHERE {W} AND dest_port = 22 LIMIT 1 BY src_ip"),
    ] {
        assert!(!compare_npl_with_sql(&sql, "dest_port=22 | head 10", &udm()).unwrap().is_empty(), "{sql}");
    }
    let sql = format!("SELECT DISTINCT * FROM (SELECT src_host FROM logs WHERE {W} AND dest_port = 22) LIMIT 100");
    assert!(!conv(&sql, &udm()).exact);
    let sql = format!("SELECT src_host, uniqUpTo(5)(user) AS u FROM logs WHERE {W} GROUP BY src_host");
    assert!(conv(&sql, &udm()).unsupported.is_some());
    assert!(!compare_npl_with_sql(&sql, "* | stats dc(user) as u by src_host", &udm()).unwrap().is_empty());
}

#[test]
fn a_select_alias_used_in_where_is_refused() {
    let r = conv(&format!("SELECT src_ip AS user FROM logs WHERE {W} AND user = '10.0.0.1'"), &udm());
    assert!(r.unsupported.as_ref().is_some_and(|u| u.reason.contains("alias")), "{:?}", r);
}

#[test]
fn negated_case_folding_is_not_called_broader() {
    let r = conv(&format!("SELECT * FROM logs WHERE {W} AND process_name != 'PowerShell.exe'"), &udm());
    assert!(r.differences.iter().any(|d| d.kind == DifferenceKind::Different), "{:?}", r.differences);
}

#[test]
fn signals_with_other_parameters_is_refused_for_the_parameter() {
    let r = conv(&format!("SELECT * FROM {{signals}} WHERE {W} AND rule_id = {{rule:UUID}}"), &udm());
    assert!(r.unsupported.unwrap().reason.contains("parameter"));
    let r = conv(&format!("SELECT * FROM logs_local WHERE {W}"), &udm());
    assert!(r.unsupported.is_some());
    let r = conv(&format!("SELECT * FROM other_db.logs WHERE {W}"), &udm());
    assert!(r.unsupported.is_some());
}

#[test]
fn reversed_placeholders_bind_to_their_own_end() {
    let r = conv("SELECT * FROM logs WHERE timestamp <= {earliest:DateTime64(6, 'UTC')} AND dest_port = 1", &udm());
    assert_eq!(r.latest, Some(TimeBound::WindowStart));
    let r = conv("SELECT * FROM logs WHERE timestamp >= toDateTime('2026-11-01 00:00:00', 'Asia/Tokyo')", &udm());
    assert!(r.unsupported.is_some());
}
