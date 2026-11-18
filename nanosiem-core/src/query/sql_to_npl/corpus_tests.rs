// SPDX-License-Identifier: AGPL-3.0-or-later

//! The hunt SQL corpus (NAN-5575): queries in the shapes hunt agents send
//! over Agent Lane. Sources: the `sql` tool's own example
//! (`hunts_agent::lane::sql_example`), the guard's accepted queries
//! (`lane_tests`, `engine_tests`, `signals_tests`), the shipped
//! `dataset: signals` pivot templates (`hunts/templates/detection_signals.*`),
//! the source-inventory probe (`hunts::inventory`), and investigator queries
//! in the shapes the hunt prompt steers toward (process, auth, network, file
//! and DNS hunting over `ocsf_logs` / `logs`).
//!
//! Every entry declares what it must come out as: `Exact`, `Broader` (Search
//! matches a superset; every difference is `broader`), `Inexact` (it
//! converts, with listed differences), or `Refused`. The test prints the
//! share that converted exactly so the PR can quote it.

use super::*;
use crate::schema::{profile_for_id, SchemaId};

const W: &str = "timestamp >= {earliest:DateTime64(6, 'UTC')} AND timestamp <= {latest:DateTime64(6, 'UTC')}";

#[derive(Debug, Clone, Copy, PartialEq)]
enum Want {
    Exact,
    Broader,
    Inexact,
    Refused,
}

fn corpus() -> Vec<(SchemaId, String, Want)> {
    use SchemaId::{Ocsf, Udm};
    use Want::*;
    let q = |s: &str| s.replace("{W}", W);
    vec![
        // lane::sql_example (both profiles), as the tool description quotes it.
        (Ocsf, q("SELECT `device.hostname` AS host, count() AS n FROM ocsf_logs WHERE {W} AND `actor.process.name` = 'powershell.exe' GROUP BY host ORDER BY n DESC"), Broader),
        (Udm, q("SELECT src_host AS host, count() AS n FROM logs WHERE {W} AND process_name = 'powershell.exe' GROUP BY host ORDER BY n DESC"), Broader),
        // lane_tests / engine_tests accepted queries.
        (Udm, q("SELECT src_ip, count() AS n FROM logs WHERE {W} GROUP BY src_ip ORDER BY n DESC;"), Exact),
        (Udm, q("SELECT src_host, count() AS n FROM logs WHERE {W} GROUP BY src_host"), Exact),
        (Udm, q(r"SELECT * FROM logs WHERE command_line ILIKE '%net use \\\\%' AND {W}"), Exact),
        (Udm, q("SELECT * FROM logs WHERE command_line ILIKE '%schtasks /create %' AND {W}"), Exact),
        (Udm, q("SELECT * FROM logs WHERE command_line ILIKE '%vssadmin delete shadows%' AND {W}"), Exact),
        (Udm, q("SELECT * FROM logs WHERE command_line ILIKE '%--encodedcommand%' AND {W}"), Exact),
        (Udm, q("SELECT * FROM logs WHERE command_line ILIKE '%curl --data%' AND {W}"), Exact),
        (Udm, q("SELECT * FROM logs WHERE command_line ILIKE 'it''s' AND {W}"), Exact),
        (Udm, q("WITH x AS (SELECT 1) SELECT * FROM logs WHERE {W}"), Refused),
        (Udm, q("SELECT * FROM (SELECT * FROM logs WHERE {W})"), Exact),
        // The runner's row-cap wrapper (`limit_wrapped`), as the Agent Lane
        // query audit records an investigator query.
        (Ocsf, q("SELECT * FROM (SELECT `device.hostname`, count() AS n FROM ocsf_logs WHERE {W} AND class_uid = 1007 GROUP BY `device.hostname` ORDER BY n DESC) LIMIT 51"), Exact),
        (Udm, q("SELECT count() FROM events WHERE {W}"), Refused),
        // signals_tests and the shipped signals pivot templates.
        // NAN-5612: `{signals}` converts to dataset=signals. NAN-5614:
        // rule_id is a UUID, never empty, so dc() counts what uniqExact does.
        (Ocsf, q("SELECT risk_entity, uniqExact(rule_id) AS distinct_rules FROM {signals} WHERE {W} GROUP BY risk_entity"), Exact),
        (Ocsf, q("SELECT rule_name, count() AS fires FROM {signals} WHERE {W} AND severity IN ('high', 'critical') GROUP BY rule_name ORDER BY fires DESC LIMIT 50"), Exact),
        (Udm, q("SELECT risk_entity, sum(risk_score) AS total FROM {signals} WHERE {W} AND risk_entity != '' GROUP BY risk_entity ORDER BY total DESC LIMIT 20"), Exact),
        // NAN-5614: its nPL form (values() over an unfiltered search) is
        // refused by Search's memory guard, so it is not handed out.
        (Ocsf, q("SELECT risk_entity, uniqExact(rule_id) AS distinct_rules, count() AS fires, countIf(severity IN ('low', 'info', 'informational')) AS low_fires, groupUniqArray(10)(rule_name) AS rules, min(timestamp) AS first_fire, max(timestamp) AS last_fire FROM {signals} WHERE {W} AND risk_entity != '' GROUP BY risk_entity ORDER BY distinct_rules DESC, fires DESC, risk_entity ASC"), Refused),
        (Ocsf, q("SELECT id, timestamp, source_type, class_uid, `device.hostname`, `actor.user.name`, `src_endpoint.ip`, `dst_endpoint.ip`, `actor.process.cmd_line` FROM {events} WHERE {W} AND id IN (SELECT matched_log_id FROM {signals} WHERE {W} AND risk_entity IN (SELECT risk_entity FROM {signals} WHERE {W} AND risk_entity != '' GROUP BY risk_entity ORDER BY uniqExact(rule_id) DESC, risk_entity ASC LIMIT 10)) ORDER BY timestamp DESC"), Refused),
        (Udm, q("SELECT count() FROM detections WHERE {W}"), Refused),
        // hunts::inventory signals probe.
        (Ocsf, q("SELECT lower(source_type) AS source_type, count() AS events, toString(min(timestamp)) AS first_seen, toString(max(timestamp)) AS last_seen FROM signals WHERE {W} GROUP BY source_type ORDER BY events DESC, source_type ASC LIMIT 51"), Refused),
        // Investigator hunting shapes — OCSF.
        (Ocsf, q("SELECT `device.hostname`, `actor.user.name`, `actor.process.cmd_line` FROM ocsf_logs WHERE {W} AND lower(`actor.process.name`) = 'rundll32.exe' AND lower(`actor.process.cmd_line`) LIKE '%javascript:%' LIMIT 100"), Exact),
        (Ocsf, q("SELECT `src_endpoint.ip`, count() AS failures FROM ocsf_logs WHERE {W} AND class_uid = 3002 AND status_id = 2 GROUP BY `src_endpoint.ip` HAVING failures > 20 ORDER BY failures DESC LIMIT 25"), Exact),
        (Ocsf, q("SELECT `dst_endpoint.ip`, `dst_endpoint.port`, count() AS c FROM ocsf_logs WHERE {W} AND class_uid = 4001 AND `dst_endpoint.port` IN (4444, 1337, 31337) GROUP BY `dst_endpoint.ip`, `dst_endpoint.port` ORDER BY c DESC"), Exact),
        (Ocsf, q("SELECT `actor.user.name`, uniqExact(`device.hostname`) AS hosts FROM ocsf_logs WHERE {W} AND class_uid = 3002 GROUP BY `actor.user.name` ORDER BY hosts DESC LIMIT 20"), Inexact),
        (Ocsf, q("SELECT * FROM ocsf_logs WHERE {W} AND `actor.process.cmd_line` ILIKE '%-enc %' AND `actor.process.name` ILIKE '%powershell%'"), Exact),
        (Ocsf, q("SELECT `device.hostname`, count() AS n FROM ocsf_logs WHERE {W} AND (lower(`actor.process.name`) = 'certutil.exe' OR lower(`actor.process.name`) = 'bitsadmin.exe') GROUP BY `device.hostname`"), Exact),
        (Ocsf, q("SELECT * FROM ocsf_logs WHERE {W} AND `src_endpoint.ip` = '10.1.2.3' ORDER BY timestamp DESC LIMIT 200"), Exact),
        (Ocsf, q("SELECT `query.hostname`, count() AS n FROM ocsf_logs WHERE {W} AND class_uid = 4003 AND lower(`query.hostname`) LIKE '%.duckdns.org' GROUP BY `query.hostname` ORDER BY n DESC LIMIT 50"), Exact),
        (Ocsf, q("SELECT `device.hostname`, min(timestamp) AS first_seen, max(timestamp) AS last_seen, count() AS n FROM ocsf_logs WHERE {W} AND `file.hashes.sha256` = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' GROUP BY `device.hostname`"), Exact),
        (Ocsf, q("SELECT * FROM ocsf_logs WHERE {W} AND `device.hostname` = 'WS-0142' AND class_uid = 1007"), Broader),
        (Ocsf, q("SELECT `actor.user.name`, count() AS n FROM ocsf_logs WHERE {W} AND `actor.user.name` != '' AND class_uid = 3002 AND status_id = 1 GROUP BY `actor.user.name` ORDER BY n ASC LIMIT 10"), Exact),
        (Ocsf, q("SELECT * FROM ocsf_logs WHERE {W} AND match(`actor.process.cmd_line`, '(?i)invoke-(mimikatz|kerberoast)')"), Exact),
        (Ocsf, q("SELECT `device.hostname`, count() AS n FROM ocsf_logs_distributed WHERE {W} AND `actor.process.name` NOT IN ('svchost.exe', 'explorer.exe') GROUP BY `device.hostname` ORDER BY n DESC LIMIT 10"), Inexact),
        // ^ case folding NARROWS a NOT IN (it also drops SVCHOST.EXE), so it is not broader.
        (Ocsf, q("SELECT `device.hostname`, count() AS n FROM ocsf_logs WHERE {W} AND class_uid = 1007 GROUP BY `device.hostname` ORDER BY count() DESC LIMIT 15"), Exact),
        (Ocsf, q("SELECT `actor.user.name`, groupUniqArray(`src_endpoint.ip`) AS ips FROM ocsf_logs WHERE {W} AND class_uid = 3002 GROUP BY `actor.user.name`"), Inexact),
        (Ocsf, q("SELECT `device.hostname`, count() AS n FROM ocsf_logs WHERE {W} AND positionCaseInsensitive(`actor.process.cmd_line`, 'lsass') > 0 GROUP BY `device.hostname`"), Refused),
        (Ocsf, q("SELECT toStartOfHour(timestamp) AS hour, count() AS n FROM ocsf_logs WHERE {W} AND class_uid = 3002 AND status_id = 2 GROUP BY hour ORDER BY hour"), Refused),
        // NAN-5614: argMax(x, timestamp) is nPL's last(x).
        (Ocsf, q("SELECT `device.hostname`, argMax(`actor.user.name`, timestamp) AS last_user FROM ocsf_logs WHERE {W} GROUP BY `device.hostname`"), Exact),
        // Investigator hunting shapes — UDM.
        (Udm, q("SELECT src_host, user, command_line FROM logs WHERE {W} AND lower(process_name) = 'wmic.exe' AND lower(command_line) LIKE '%process call create%' LIMIT 100"), Exact),
        (Udm, q("SELECT src_ip, count() AS failures FROM logs WHERE {W} AND auth_result = 'failure' GROUP BY src_ip HAVING count() > 50 ORDER BY failures DESC"), Broader),
        (Udm, q("SELECT dest_ip, sum(bytes_out) AS out FROM logs WHERE {W} AND dest_port = 443 AND bytes_out > 10000000 GROUP BY dest_ip ORDER BY out DESC LIMIT 10"), Exact),
        (Udm, q("SELECT * FROM logs WHERE {W} AND user IS NOT NULL AND lower(user) IN ('administrator', 'admin') AND dest_port = 3389"), Exact),
        (Udm, q("SELECT user, count(DISTINCT src_host) AS hosts FROM logs WHERE {W} GROUP BY user ORDER BY hosts DESC LIMIT 20"), Inexact),
        (Udm, q("SELECT * FROM logs WHERE {W} AND lower(file_path) LIKE '%\\\\appdata\\\\roaming\\\\%.exe'"), Exact),
        (Udm, q("SELECT src_host, avg(bytes_in) AS avg_in, max(bytes_in) AS max_in FROM logs WHERE {W} AND protocol = 'tcp' GROUP BY src_host"), Exact),
        (Udm, q("SELECT * FROM logs WHERE timestamp BETWEEN {earliest:DateTime64(6, 'UTC')} AND {latest:DateTime64(6, 'UTC')} AND dest_port = 22 AND NOT (src_ip IN ('10.0.0.1', '10.0.0.2'))"), Exact),
        (Udm, q("SELECT src_host, count() AS n FROM logs WHERE {W} AND source_type = 'sysmon' AND lower(parent_process_name) = 'winword.exe' GROUP BY src_host ORDER BY n DESC"), Exact),
        (Udm, q("SELECT src_ip, dest_ip FROM logs l WHERE {W} AND l.dest_port = 445 ORDER BY timestamp DESC LIMIT 50"), Exact),
        // The hunts mock's SQL trail steps (dev/hunts-mock), so its canned
        // conversions are this converter's real output.
        (Udm, q("SELECT src_host, count() AS n FROM logs WHERE {W} AND lower(process_name) = 'powershell.exe' AND command_line ILIKE '%-enc%' GROUP BY src_host ORDER BY n DESC LIMIT 20"), Exact),
        (Udm, q("SELECT dest_ip, dest_port, count() AS c FROM logs WHERE {W} AND src_host = 'WKS-FIN-0231' AND dest_port = 443 GROUP BY dest_ip, dest_port ORDER BY c DESC"), Broader),
        // The physical real-time `signals` table: converts, broader table
        // (dataset=signals adds scheduled detections); dc(rule_id) is exact.
        (Udm, q("SELECT risk_entity, uniqExact(rule_id) AS rules FROM signals WHERE {W} AND risk_entity != '' GROUP BY risk_entity ORDER BY rules DESC"), Broader),
        (Ocsf, q("SELECT rule_name, count() AS n FROM signals_distributed WHERE {W} GROUP BY rule_name"), Broader),
        // PR #9876 review regression: lower() against an uppercase literal
        // never matches; nPL would fold it and match. Never exact.
        (Udm, q("SELECT * FROM logs WHERE {W} AND lower(user) = 'Admin'"), Refused),
        (Ocsf, q("SELECT `device.hostname`, count() AS n FROM ocsf_logs WHERE {W} AND lower(`actor.process.name`) IN ('PowerShell.exe', 'pwsh.exe') GROUP BY `device.hostname`"), Refused),
        // NAN-5614: any() converts to first(), never exact.
        (Udm, q("SELECT src_host, any(user) AS u FROM logs WHERE {W} GROUP BY src_host"), Inexact),
        (Udm, q("SELECT * FROM logs WHERE {W} AND JSONExtractString(ext, 'logon_type') = '10'"), Refused),
    ]
}

#[test]
fn the_hunt_sql_corpus_converts_as_declared() {
    let corpus = corpus();
    let mut exact = 0;
    let mut converted = 0;
    let mut failures = Vec::new();
    for (schema, sql, want) in &corpus {
        let ctx = ConvertContext::new(profile_for_id(*schema));
        let r = convert_sql_to_npl(sql, &ctx);
        let got = match (&r.unsupported, r.exact) {
            (Some(_), _) => Want::Refused,
            (None, true) => Want::Exact,
            (None, false) if r.differences.iter().all(|d| d.kind == DifferenceKind::Broader) => Want::Broader,
            (None, false) => Want::Inexact,
        };
        if r.unsupported.is_none() {
            converted += 1;
        }
        if r.exact {
            exact += 1;
        }
        println!(
            "[{got:?}] {sql}\n    => {}\n    {:?}{}",
            r.npl.as_deref().unwrap_or("-"),
            r.differences.iter().map(|d| d.detail.as_str()).collect::<Vec<_>>(),
            r.unsupported.as_ref().map(|u| format!(" refused: {}", u.reason)).unwrap_or_default()
        );
        if got != *want {
            failures.push(format!("{sql}: wanted {want:?}, got {got:?} ({:?} / {:?})", r.npl, r.differences));
        }
    }
    let total = corpus.len();
    println!(
        "corpus: {total} queries, {converted} converted ({}%), {exact} exact ({}%)",
        converted * 100 / total,
        exact * 100 / total
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

// --- NAN-5614: the hunts playbook signals pivots ---

/// How a conversion came out.
fn classify(r: &SqlToNpl) -> Want {
    match (&r.unsupported, r.exact) {
        (Some(_), _) => Want::Refused,
        (None, true) => Want::Exact,
        (None, false) if r.differences.iter().all(|d| d.kind == DifferenceKind::Broader) => Want::Broader,
        (None, false) => Want::Inexact,
    }
}

/// Every reason a conversion gives: the refusal, or each difference.
fn reasons(r: &SqlToNpl) -> String {
    let mut out: Vec<&str> = r.differences.iter().map(|d| d.detail.as_str()).collect();
    if let Some(u) = &r.unsupported {
        out.push(&u.reason);
    }
    out.join(" | ")
}

/// Every `dataset: signals` pivot in the hunts playbooks (nano-rs/playbooks
/// `hunts/`, playbook v2, 18 pivots), verbatim, with what it converts as and
/// a phrase its reason must carry. `Inexact` is the honest "approximate":
/// the nPL runs and the differences say exactly how its results differ.
fn playbook_signals_pivots() -> Vec<(&'static str, &'static str, Want, &'static str)> {
    use Want::*;
    vec![
        ("customer_app_ato/landed_accounts", r#"SELECT `user.name` AS account, count() AS successes, uniqExact(`src_endpoint.ip`) AS stuffing_sources, groupUniqArray(10)(`src_endpoint.ip`) AS source_sample, groupUniqArray(5)(`src_endpoint.autonomous_system.name`) AS asn_sample, min(timestamp) AS first_success, max(timestamp) AS last_success, countIf(id IN (SELECT matched_log_id FROM {signals} WHERE {W})) AS already_detected FROM {events} WHERE {W} AND class_uid = 3002 AND status_id = 1 AND `user.name` != '' AND `src_endpoint.ip` IN (SELECT `src_endpoint.ip` FROM {events} WHERE {W} AND class_uid = 3002 AND status_id = 2 AND `src_endpoint.ip` != '' GROUP BY `src_endpoint.ip` HAVING uniqExact(`user.name`) >= 10) GROUP BY account ORDER BY successes DESC, account ASC LIMIT 200"#, Refused, "the subquery aggregates"),
        ("dns_tunneling_throughput/dns_parent_domain_shape", r#"SELECT parent_domain AS parent_domain, uniq(name) AS distinct_names, count() AS queries, countIf(qtype IN ('TXT', 'NULL')) AS txt_null_queries, round(txt_null_queries / queries, 3) AS txt_null_share, round(avg(length(name)), 1) AS avg_name_length, quantileExact(0.5)(length(lbl)) AS median_label_length, max(length(lbl)) AS max_label_length, round(avg(entropy), 3) AS label_entropy_bits, uniq(host_ip) AS source_ips, groupUniqArray(5)(host_name) AS source_hosts, groupUniqArray(5)(host_ip) AS source_ip_sample, countIf(detected) AS already_detected, min(ts) AS first_seen, max(ts) AS last_seen FROM (SELECT timestamp AS ts, id, `query.hostname` AS name, upper(toString(event.query.type)) AS qtype, `src_endpoint.ip` AS host_ip, `src_endpoint.hostname` AS host_name, cutToFirstSignificantSubdomain(`query.hostname`) AS parent_domain, splitByChar('.', `query.hostname`)[1] AS lbl, splitByString('', lbl) AS chars, arraySum(arrayMap(c -> -(c / length(lbl)) * log2(c / length(lbl)), arrayMap(ch -> countEqual(chars, ch), arrayDistinct(chars)))) AS entropy, id IN (SELECT matched_log_id FROM {signals} WHERE {W}) AS detected FROM {events} WHERE {W} AND class_uid = 4003 AND activity_id = 1 AND `query.hostname` != '') WHERE parent_domain != '' AND parent_domain != name GROUP BY parent_domain HAVING distinct_names >= 20 AND ((median_label_length >= 25) + (label_entropy_bits >= 4.0) + (txt_null_share >= 0.5)) >= 2 ORDER BY distinct_names DESC, parent_domain ASC LIMIT 200"#, Refused, "a subquery in FROM"),
        ("dns_tunneling_throughput/dns_tunnel_candidate_queries", r#"SELECT id, ts AS timestamp, host_name AS `src_endpoint.hostname`, host_ip AS `src_endpoint.ip`, name AS `query.hostname`, qtype AS `query.type`, parent_domain, length(lbl) AS label_length, detected AS already_detected FROM (SELECT timestamp AS ts, id, `query.hostname` AS name, upper(toString(event.query.type)) AS qtype, `src_endpoint.ip` AS host_ip, `src_endpoint.hostname` AS host_name, cutToFirstSignificantSubdomain(`query.hostname`) AS parent_domain, splitByChar('.', `query.hostname`)[1] AS lbl, splitByString('', lbl) AS chars, arraySum(arrayMap(c -> -(c / length(lbl)) * log2(c / length(lbl)), arrayMap(ch -> countEqual(chars, ch), arrayDistinct(chars)))) AS entropy, id IN (SELECT matched_log_id FROM {signals} WHERE {W}) AS detected FROM {events} WHERE {W} AND class_uid = 4003 AND activity_id = 1 AND `query.hostname` != '') WHERE parent_domain IN (SELECT parent_domain FROM (SELECT parent_domain AS parent_domain, uniq(name) AS distinct_names, count() AS queries, countIf(qtype IN ('TXT', 'NULL')) AS txt_null_queries, round(txt_null_queries / queries, 3) AS txt_null_share, round(avg(length(name)), 1) AS avg_name_length, quantileExact(0.5)(length(lbl)) AS median_label_length, max(length(lbl)) AS max_label_length, round(avg(entropy), 3) AS label_entropy_bits, uniq(host_ip) AS source_ips, groupUniqArray(5)(host_name) AS source_hosts, groupUniqArray(5)(host_ip) AS source_ip_sample, countIf(detected) AS already_detected, min(ts) AS first_seen, max(ts) AS last_seen FROM (SELECT timestamp AS ts, id, `query.hostname` AS name, upper(toString(event.query.type)) AS qtype, `src_endpoint.ip` AS host_ip, `src_endpoint.hostname` AS host_name, cutToFirstSignificantSubdomain(`query.hostname`) AS parent_domain, splitByChar('.', `query.hostname`)[1] AS lbl, splitByString('', lbl) AS chars, arraySum(arrayMap(c -> -(c / length(lbl)) * log2(c / length(lbl)), arrayMap(ch -> countEqual(chars, ch), arrayDistinct(chars)))) AS entropy, id IN (SELECT matched_log_id FROM {signals} WHERE {W}) AS detected FROM {events} WHERE {W} AND class_uid = 4003 AND activity_id = 1 AND `query.hostname` != '') WHERE parent_domain != '' AND parent_domain != name GROUP BY parent_domain HAVING distinct_names >= 20 AND ((median_label_length >= 25) + (label_entropy_bits >= 4.0) + (txt_null_share >= 0.5)) >= 2)) ORDER BY parent_domain ASC, `src_endpoint.hostname` ASC, timestamp DESC LIMIT 25 BY parent_domain, `src_endpoint.hostname`, `src_endpoint.ip` LIMIT 200"#, Refused, "LIMIT n BY"),
        ("dns_tunneling_throughput/dns_single_audience_throughput", r#"SELECT parent_domain, uniq(name) AS distinct_names, count() AS queries, round(distinct_names / queries, 3) AS unique_name_share, sum(greatest(length(name) - length(parent_domain) - 1, 0)) AS label_bytes, uniq(host_ip) AS source_ips, groupUniqArray(3)(host_ip) AS source_ip_sample, groupUniqArray(3)(host_name) AS source_hosts, countIf(detected) AS already_detected, min(ts) AS first_seen, max(ts) AS last_seen FROM (SELECT timestamp AS ts, id, lower(`query.hostname`) AS name, `src_endpoint.ip` AS host_ip, `src_endpoint.hostname` AS host_name, cutToFirstSignificantSubdomain(lower(`query.hostname`)) AS parent_domain, id IN (SELECT matched_log_id FROM {signals} WHERE {W}) AS detected FROM {events} WHERE {W} AND class_uid = 4003 AND activity_id = 1 AND `query.hostname` != '') WHERE parent_domain != '' AND parent_domain != name GROUP BY parent_domain HAVING distinct_names >= 100 AND source_ips <= 2 ORDER BY label_bytes DESC, parent_domain ASC LIMIT 200"#, Refused, "a subquery in FROM"),
        ("edr_quiet_post_exploitation/dns_beacon_regularity", r#"SELECT host AS `device.hostname`, name AS `query.hostname`, queries, estate_hosts, mean_gap_seconds, gap_cv, already_detected, first_seen, last_seen FROM (SELECT host AS host, name AS name, queries, count() OVER (PARTITION BY name) AS estate_hosts, round(arrayAvg(gaps), 1) AS mean_gap_seconds, round(if(arrayAvg(gaps) > 0, sqrt(arrayAvg(arrayMap(g -> (g - arrayAvg(gaps)) * (g - arrayAvg(gaps)), gaps))) / arrayAvg(gaps), 99), 3) AS gap_cv, already_detected, first_seen, last_seen FROM (SELECT host AS host, name AS name, count() AS queries, arrayPopFront(arrayDifference(arraySort(groupArray(toInt64(toUnixTimestamp(ts)))))) AS gaps, countIf(detected) AS already_detected, min(ts) AS first_seen, max(ts) AS last_seen FROM (SELECT timestamp AS ts, if(`device.hostname` != '', `device.hostname`, `src_endpoint.ip`) AS host, lower(`query.hostname`) AS name, id IN (SELECT matched_log_id FROM {signals} WHERE {W}) AS detected FROM {events} WHERE {W} AND class_uid = 4003 AND activity_id = 1 AND `query.hostname` != '') GROUP BY host, name)) WHERE queries >= 12 AND estate_hosts <= 3 AND mean_gap_seconds >= 10 AND gap_cv <= 0.25 ORDER BY gap_cv ASC, queries DESC LIMIT 200"#, Refused, "a subquery in FROM"),
        ("endpoint_intrusion_chain/dns_parent_domain_shape", r#"SELECT parent_domain AS parent_domain, uniq(name) AS distinct_names, count() AS queries, countIf(qtype IN ('TXT', 'NULL')) AS txt_null_queries, round(txt_null_queries / queries, 3) AS txt_null_share, round(avg(length(name)), 1) AS avg_name_length, quantileExact(0.5)(length(lbl)) AS median_label_length, max(length(lbl)) AS max_label_length, round(avg(entropy), 3) AS label_entropy_bits, uniq(host_ip) AS source_ips, groupUniqArray(5)(host_name) AS source_hosts, groupUniqArray(5)(host_ip) AS source_ip_sample, countIf(detected) AS already_detected, min(ts) AS first_seen, max(ts) AS last_seen FROM (SELECT timestamp AS ts, id, `query.hostname` AS name, upper(toString(event.query.type)) AS qtype, `src_endpoint.ip` AS host_ip, `src_endpoint.hostname` AS host_name, cutToFirstSignificantSubdomain(`query.hostname`) AS parent_domain, splitByChar('.', `query.hostname`)[1] AS lbl, splitByString('', lbl) AS chars, arraySum(arrayMap(c -> -(c / length(lbl)) * log2(c / length(lbl)), arrayMap(ch -> countEqual(chars, ch), arrayDistinct(chars)))) AS entropy, id IN (SELECT matched_log_id FROM {signals} WHERE {W}) AS detected FROM {events} WHERE {W} AND class_uid = 4003 AND activity_id = 1 AND `query.hostname` != '') WHERE parent_domain != '' AND parent_domain != name GROUP BY parent_domain HAVING distinct_names >= 20 AND ((median_label_length >= 25) + (label_entropy_bits >= 4.0) + (txt_null_share >= 0.5)) >= 2 ORDER BY distinct_names DESC, parent_domain ASC LIMIT 200"#, Refused, "a subquery in FROM"),
        ("mailbox_rule_persistence/rule_author_signins", r#"SELECT `user.name` AS account, count() AS signins, countIf(status_id = 2) AS failed_signins, countIf(auth_protocol_id = 11) AS basic_auth_signins, uniqExact(`src_endpoint.location.country`) AS countries, groupUniqArray(10)(`src_endpoint.location.country`) AS country_list, groupUniqArray(10)(`src_endpoint.autonomous_system.name`) AS asn_list, groupUniqArray(10)(`src_endpoint.ip`) AS signin_ips, min(timestamp) AS first_signin, max(timestamp) AS last_signin, countIf(id IN (SELECT matched_log_id FROM {signals} WHERE {W})) AS already_detected FROM {events} WHERE {W} AND class_uid = 3002 AND `user.name` != '' AND lower(`user.name`) IN (SELECT lower(`actor.user.name`) FROM {events} WHERE {W} AND class_uid = 6003 AND (lower(`api.operation`) LIKE '%inboxrule%' OR lower(`api.operation`) = 'set-mailbox') AND `actor.user.name` != '') GROUP BY account ORDER BY countries DESC, signins DESC, account ASC LIMIT 200"#, Refused, "only a plain column can be matched against a subquery"),
        ("nano_detections/detection_census", r#"SELECT rule_name, detection_path, count() AS fires, uniqExact(risk_entity) AS entities, groupUniqArray(4)(severity) AS severities, sum(risk_score) AS total_risk, min(timestamp) AS first_fire, max(timestamp) AS last_fire FROM {signals} WHERE {W} GROUP BY rule_name, detection_path ORDER BY fires DESC, rule_name ASC LIMIT 200"#, Refused, "memory guard"),
        ("nano_detections/signal_clusters", r#"SELECT risk_entity, uniqExact(rule_id) AS distinct_rules, count() AS fires, countIf(severity IN ('low', 'info', 'informational')) AS low_fires, groupUniqArray(10)(rule_name) AS rules, min(timestamp) AS first_fire, max(timestamp) AS last_fire FROM {signals} WHERE {W} AND risk_entity != '' GROUP BY risk_entity ORDER BY distinct_rules DESC, fires DESC, risk_entity ASC LIMIT 200"#, Refused, "memory guard"),
        ("nano_detections/high_severity_low_volume", r#"SELECT rule_id, rule_name, severity, detection_path, count() AS fires, uniqExact(risk_entity) AS entities, groupUniqArray(10)(risk_entity) AS entity_sample, groupUniqArray(10)(matched_log_id) AS matched_log_ids, min(timestamp) AS first_fire, max(timestamp) AS last_fire FROM {signals} WHERE {W} AND severity IN ('high', 'critical') GROUP BY rule_id, rule_name, severity, detection_path HAVING fires <= 5 ORDER BY severity = 'critical' DESC, fires ASC, rule_name ASC LIMIT 200"#, Refused, "the ORDER BY key"),
        ("nano_detections/top_entity_events", r#"SELECT id, timestamp, source_type, class_uid, `device.hostname`, `actor.user.name`, `src_endpoint.ip`, `dst_endpoint.ip`, `actor.process.cmd_line`, `process.name`, `process.cmd_line`, `user.name`, `query.hostname`, `api.operation` FROM {events} WHERE {W} AND id IN (SELECT matched_log_id FROM {signals} WHERE {W} AND risk_entity IN (SELECT risk_entity FROM {signals} WHERE {W} AND risk_entity != '' GROUP BY risk_entity ORDER BY uniqExact(rule_id) DESC, risk_entity ASC LIMIT 10)) ORDER BY timestamp DESC LIMIT 200"#, Refused, "ORDER BY / LIMIT"),
        ("nano_risky_entities/entity_risk_totals", r#"SELECT risk_entity, sum(risk_score) AS total_risk, uniqExact(rule_id) AS distinct_rules, count() AS fires, round(distinct_rules / fires, 3) AS breadth_ratio, sumIf(risk_score, timestamp >= {latest:DateTime64(6, 'UTC')} - INTERVAL 1 DAY) AS risk_last_24h, round(risk_last_24h / greatest(total_risk, 1), 3) AS recent_share, uniqExact(source_type) AS origin_sources, groupUniqArray(10)(rule_name) AS rules, groupUniqArray(5)(severity) AS severities, min(timestamp) AS first_fire, max(timestamp) AS last_fire FROM {signals} WHERE {W} AND risk_entity != '' GROUP BY risk_entity ORDER BY distinct_rules DESC, total_risk DESC, risk_entity ASC LIMIT 200"#, Refused, "the computed column"),
        ("nano_risky_entities/accelerating_entities", r#"SELECT risk_entity, sum(risk_score) AS total_risk, sumIf(risk_score, timestamp >= {latest:DateTime64(6, 'UTC')} - INTERVAL 1 DAY) AS risk_last_24h, round(risk_last_24h / greatest(total_risk, 1), 3) AS recent_share, uniqExactIf(rule_id, timestamp >= {latest:DateTime64(6, 'UTC')} - INTERVAL 1 DAY) AS distinct_rules_24h, uniqExact(rule_id) AS distinct_rules, countIf(timestamp < {latest:DateTime64(6, 'UTC')} - INTERVAL 1 DAY) AS prior_fires, uniqExact(source_type) AS origin_sources, groupUniqArray(10)(rule_name) AS rules, min(timestamp) AS first_fire, max(timestamp) AS last_fire FROM {signals} WHERE {W} AND risk_entity != '' GROUP BY risk_entity HAVING distinct_rules_24h >= 2 AND recent_share >= 0.5 ORDER BY distinct_rules_24h DESC, prior_fires ASC, risk_last_24h DESC, risk_entity ASC LIMIT 200"#, Refused, "relative to the run window"),
        ("nano_risky_entities/top_risk_entity_events", r#"SELECT id, timestamp, source_type, class_uid, `device.hostname`, `actor.user.name`, `user.name`, `src_endpoint.ip`, `dst_endpoint.ip`, `actor.process.cmd_line`, `process.name`, `process.cmd_line`, `query.hostname`, `api.operation` FROM {events} WHERE {W} AND timestamp >= {latest:DateTime64(6, 'UTC')} - INTERVAL 1 DAY AND id IN (SELECT matched_log_id FROM {signals} WHERE {W} AND risk_entity IN (SELECT risk_entity FROM {signals} WHERE {W} AND risk_entity != '' GROUP BY risk_entity HAVING uniqExact(rule_id) >= 2 ORDER BY sumIf(risk_score, timestamp >= {latest:DateTime64(6, 'UTC')} - INTERVAL 1 DAY) DESC, risk_entity ASC LIMIT 10)) ORDER BY timestamp DESC LIMIT 200"#, Refused, "time bound"),
        ("rare_destination_beaconing/http_rare_destination_beacons", r#"SELECT src_ip AS `src_endpoint.ip`, dest AS `http_request.url.hostname`, requests, estate_hosts_seen, active_hours, gap_count, round(mean_gap, 1) AS mean_gap_seconds, round(sd_gap / mean_gap, 3) AS gap_cv, user_agents, already_detected, first_seen, last_seen FROM (SELECT src_ip AS src_ip, dest AS dest, count() AS requests, min(dest_prevalence) AS estate_hosts_seen, arrayFilter(g -> g > 0, arrayDifference(arraySort(groupArray(20000)(toUnixTimestamp(ts))))) AS gaps, length(gaps) AS gap_count, arrayAvg(gaps) AS mean_gap, sqrt(arrayAvg(arrayMap(g -> (g - mean_gap) * (g - mean_gap), gaps))) AS sd_gap, uniqExact(toStartOfHour(ts)) AS active_hours, groupUniqArray(3)(ua) AS user_agents, countIf(detected) AS already_detected, min(ts) AS first_seen, max(ts) AS last_seen FROM (SELECT timestamp AS ts, id, `src_endpoint.ip` AS src_ip, lower(`http_request.url.hostname`) AS dest, `http_request.user_agent` AS ua, prevalence_dest_domain AS dest_prevalence, id IN (SELECT matched_log_id FROM {signals} WHERE {W}) AS detected FROM {events} WHERE {W} AND class_uid = 4002 AND `http_request.url.hostname` != '' AND `src_endpoint.ip` != '' AND prevalence_dest_domain <= 3) GROUP BY src_ip, dest HAVING gap_count >= 12 AND active_hours >= 3) WHERE gap_cv <= 0.5 ORDER BY gap_cv ASC, requests DESC, `src_endpoint.ip` ASC LIMIT 200"#, Refused, "a subquery in FROM"),
        ("rare_destination_beaconing/network_rare_destination_beacons", r#"SELECT src_ip AS `src_endpoint.ip`, dest AS `dst_endpoint.ip`, port AS `dst_endpoint.port`, connections, bytes_out, estate_hosts_seen, active_hours, gap_count, round(mean_gap, 1) AS mean_gap_seconds, round(sd_gap / mean_gap, 3) AS gap_cv, already_detected, first_seen, last_seen FROM (SELECT src_ip AS src_ip, dest AS dest, port AS port, count() AS connections, sum(bytes) AS bytes_out, min(dest_prevalence) AS estate_hosts_seen, arrayFilter(g -> g > 0, arrayDifference(arraySort(groupArray(20000)(toUnixTimestamp(ts))))) AS gaps, length(gaps) AS gap_count, arrayAvg(gaps) AS mean_gap, sqrt(arrayAvg(arrayMap(g -> (g - mean_gap) * (g - mean_gap), gaps))) AS sd_gap, uniqExact(toStartOfHour(ts)) AS active_hours, countIf(detected) AS already_detected, min(ts) AS first_seen, max(ts) AS last_seen FROM (SELECT timestamp AS ts, id, `src_endpoint.ip` AS src_ip, `dst_endpoint.ip` AS dest, `dst_endpoint.port` AS port, `traffic.bytes_out` AS bytes, prevalence_dest_ip AS dest_prevalence, id IN (SELECT matched_log_id FROM {signals} WHERE {W}) AS detected FROM {events} WHERE {W} AND class_uid = 4001 AND `dst_endpoint.ip` != '' AND `src_endpoint.ip` != '' AND prevalence_dest_ip <= 3) GROUP BY src_ip, dest, port HAVING gap_count >= 12 AND active_hours >= 3) WHERE gap_cv <= 0.5 ORDER BY gap_cv ASC, connections DESC, `src_endpoint.ip` ASC LIMIT 200"#, Refused, "a subquery in FROM"),
        ("vpn_edge_appliance_anomalies/concurrent_external_sessions", r#"SELECT user_name AS `user.name`, hour, uniqIf(asn, asn != 0) AS asns_in_hour, uniqIf(country, country != '') AS countries_in_hour, uniq(ip) AS source_ip_count, groupUniqArray(10)(ip) AS source_ips, groupUniqArray(5)(country) AS countries, groupUniqArray(5)(product) AS products, count() AS logons, countIf(detected) AS already_detected FROM (SELECT `user.name` AS user_name, toStartOfHour(timestamp) AS hour, `src_endpoint.autonomous_system.number` AS asn, `src_endpoint.location.country` AS country, `src_endpoint.ip` AS ip, `metadata.product.name` AS product, id IN (SELECT matched_log_id FROM {signals} WHERE {W}) AS detected FROM {events} WHERE {W} AND class_uid = 3002 AND status_id = 1 AND `user.name` != '' AND isIPv4String(`src_endpoint.ip`) AND NOT (isIPAddressInRange(`src_endpoint.ip`, '10.0.0.0/8') OR isIPAddressInRange(`src_endpoint.ip`, '172.16.0.0/12') OR isIPAddressInRange(`src_endpoint.ip`, '192.168.0.0/16') OR isIPAddressInRange(`src_endpoint.ip`, '127.0.0.0/8') OR isIPAddressInRange(`src_endpoint.ip`, '100.64.0.0/10') OR isIPAddressInRange(`src_endpoint.ip`, '169.254.0.0/16'))) GROUP BY user_name, hour HAVING asns_in_hour >= 2 ORDER BY countries_in_hour DESC, asns_in_hour DESC, `user.name` ASC, hour ASC LIMIT 200"#, Refused, "a subquery in FROM"),
        ("web_exploitation_corroborated/scan_then_focus_sources", r#"SELECT src_ip AS `src_endpoint.ip`, host AS `http_request.url.hostname`, sum(hits) AS requests, count() AS distinct_paths, max(hits) AS top_path_hits, argMax(path, hits) AS top_path, round(top_path_hits / requests, 3) AS top_path_share, argMax(ok_hits, hits) AS top_path_success, sum(error_hits) AS error_responses, sum(detected_hits) AS already_detected, min(first_ts) AS first_seen, max(last_ts) AS last_seen FROM (SELECT `src_endpoint.ip` AS src_ip, lower(`http_request.url.hostname`) AS host, `http_request.url.path` AS path, count() AS hits, countIf(`http_response.code` >= 200 AND `http_response.code` < 300) AS ok_hits, countIf(`http_response.code` >= 400) AS error_hits, countIf(detected) AS detected_hits, min(ts) AS first_ts, max(ts) AS last_ts FROM (SELECT timestamp AS ts, id, `src_endpoint.ip`, `http_request.url.hostname`, `http_request.url.path`, `http_response.code`, id IN (SELECT matched_log_id FROM {signals} WHERE {W}) AS detected FROM {events} WHERE {W} AND class_uid = 4002 AND `src_endpoint.ip` != '' AND `http_request.url.path` != '') GROUP BY src_ip, host, path) GROUP BY src_ip, host HAVING distinct_paths >= 50 AND top_path_hits >= 20 AND top_path_success > 0 ORDER BY top_path_hits DESC, `src_endpoint.ip` ASC LIMIT 200"#, Refused, "a subquery in FROM"),
    ]
}

fn check_pivots(label: &str, pivots: &[(String, String, Want, &str)]) {
    let ctx = ConvertContext::new(profile_for_id(SchemaId::Ocsf));
    let mut failures = Vec::new();
    for (name, sql, want, why) in pivots {
        let r = convert_sql_to_npl(sql, &ctx);
        let got = classify(&r);
        let reasons = reasons(&r);
        println!("[{got:?}] {name}\n    => {}\n    {reasons}", r.npl.as_deref().unwrap_or("-"));
        if got != *want {
            failures.push(format!("{name}: wanted {want:?}, got {got:?} ({:?}: {reasons})", r.npl));
        } else if !reasons.contains(why) {
            failures.push(format!("{name}: the reason does not say `{why}`: {reasons}"));
        }
        // A refused pivot names its dataset all the same (the outer SELECT).
        if r.npl.is_some() {
            assert_eq!(r.dataset, sql_dataset(sql, &ctx), "{name}");
        }
    }
    println!("{label}: {} pivots", pivots.len());
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn the_playbook_signals_pivots_convert_as_declared() {
    let pivots: Vec<(String, String, Want, &str)> = playbook_signals_pivots()
        .into_iter()
        .map(|(n, q, w, why)| (n.to_string(), q.replace("{W}", W), w, why))
        .collect();
    assert_eq!(pivots.len(), 18);
    check_pivots("playbook signals pivots", &pivots);
}

/// The OCSF templates' former `dataset: signals` SQL pivots (NAN-5621 moved
/// the templates to nPL), kept as fixed strings so the converter keeps
/// covering those shapes.
#[test]
fn the_former_template_signals_pivots_convert_as_declared() {
    use super::template_sql_fixtures::FORMER_TEMPLATE_SIGNALS_SQL;
    use Want::*;
    let declared: &[(&str, &str, Want, &str)] = &[
        ("detection-signals", "signal_clusters", Refused, "memory guard"),
        ("detection-signals", "top_entity_events", Refused, "ORDER BY / LIMIT"),
        ("dns-tunneling", "dns_parent_domain_shape", Refused, "a subquery in FROM"),
        ("dns-tunneling", "dns_tunnel_candidate_queries", Refused, "a subquery in FROM"),
        ("intrusion-chain", "dns_parent_domain_shape", Refused, "a subquery in FROM"),
    ];
    let pivots: Vec<(String, String, Want, &str)> = FORMER_TEMPLATE_SIGNALS_SQL
        .iter()
        .map(|(slug, name, sql)| {
            let (_, _, want, why) = declared
                .iter()
                .find(|(s, n, _, _)| s == slug && n == name)
                .unwrap_or_else(|| panic!("undeclared template pivot {slug}/{name}"));
            (format!("{slug}/{name}"), sql.to_string(), *want, *why)
        })
        .collect();
    assert_eq!(pivots.len(), declared.len(), "a declared template pivot is gone");
    check_pivots("former template signals pivots", &pivots);
}

/// The shipped templates: every OCSF pivot is nPL (NAN-5621), so none needs
/// a conversion; the legacy UDM template keeps its SQL signals pivots.
#[cfg(feature = "enterprise")]
#[test]
fn the_builtin_templates_need_no_conversion_on_ocsf() {
    use crate::hunts::spec::HuntSpecDraft;
    use crate::hunts::templates::{DETECTION_SIGNALS_OCSF, DETECTION_SIGNALS_UDM, DNS_TUNNELING_OCSF, INTRUSION_CHAIN_OCSF};
    use crate::playbooks::{parse_playbook, split_frontmatter};
    let draft = |t: &crate::hunts::templates::HuntTemplate| {
        let (fm, body) = split_frontmatter(t.source).expect("front matter");
        HuntSpecDraft::from_frontmatter(fm.as_ref(), &parse_playbook(body)).expect("template parses")
    };
    for t in [DETECTION_SIGNALS_OCSF, DNS_TUNNELING_OCSF, INTRUSION_CHAIN_OCSF] {
        for p in draft(&t).pivots {
            assert!(!p.is_sql(), "{}/{} is SQL; OCSF template pivots are nPL", t.slug, p.name);
            assert!(p.search_npl().is_some(), "{}/{}", t.slug, p.name);
        }
    }
    let udm: Vec<_> = draft(&DETECTION_SIGNALS_UDM).pivots.into_iter().filter(|p| p.is_sql()).map(|p| p.name).collect();
    assert_eq!(udm, ["signal_clusters", "top_entity_events"], "the legacy UDM template keeps its SQL pivots");
}

/// Near misses: SQL one step away from a conversion that IS proven, which
/// must never be called exact (NAN-5614). Each is checked through
/// [`compare_npl_with_sql`] against the nPL a careless translation would
/// write, so the comparator itself is what refuses them.
#[test]
fn near_misses_are_never_called_exact() {
    let ctx = ConvertContext::new(profile_for_id(SchemaId::Ocsf));
    let q = |s: &str| s.replace("{W}", W);
    let sub = "id IN [dataset=signals * | return matched_log_id]";
    let cases: Vec<(String, String)> = vec![
        // The subsearch's 10,000-value cap: the plainest join is not exact.
        (q("SELECT * FROM {events} WHERE {W} AND id IN (SELECT matched_log_id FROM {signals} WHERE {W})"), sub.to_string()),
        // The subquery reads its own window, or none.
        (q("SELECT * FROM {events} WHERE {W} AND id IN (SELECT matched_log_id FROM {signals} WHERE timestamp >= {latest:DateTime64(6, 'UTC')} - INTERVAL 1 DAY)"), sub.to_string()),
        (q("SELECT * FROM {events} WHERE {W} AND id IN (SELECT matched_log_id FROM {signals})"), sub.to_string()),
        // Another column, the other polarity, GLOBAL.
        (q("SELECT * FROM {events} WHERE {W} AND id IN (SELECT rule_id FROM {signals} WHERE {W})"), sub.to_string()),
        (q("SELECT * FROM {events} WHERE {W} AND id NOT IN (SELECT matched_log_id FROM {signals} WHERE {W})"), sub.to_string()),
        (q("SELECT * FROM {events} WHERE {W} AND id GLOBAL IN (SELECT matched_log_id FROM {signals} WHERE {W})"), sub.to_string()),
        // A subquery filter the nPL subsearch leaves out, or adds.
        (q("SELECT * FROM {events} WHERE {W} AND id IN (SELECT matched_log_id FROM {signals} WHERE {W} AND severity = 'high')"), sub.to_string()),
        (q("SELECT * FROM {events} WHERE {W} AND id IN (SELECT matched_log_id FROM {signals} WHERE {W})"), "id IN [dataset=signals severity=\"high\" | return matched_log_id]".into()),
        // An aggregating / limited subquery against the stages a subsearch ignores.
        (q("SELECT * FROM {events} WHERE {W} AND id IN (SELECT matched_log_id FROM {signals} WHERE {W} GROUP BY matched_log_id HAVING count() > 1)"),
            "id IN [dataset=signals * | stats count() as n by matched_log_id | where n > 1 | return matched_log_id]".into()),
        // (`SELECT DISTINCT … LIMIT 10000` IS the subsearch, and verifies exact.)
        (q("SELECT * FROM {events} WHERE {W} AND id IN (SELECT matched_log_id FROM {signals} WHERE {W} LIMIT 10000)"), sub.to_string()),
        // Conditional aggregates: another condition, or sum(if) over a
        // column that may be NULL (events), or a different else value.
        (q("SELECT risk_entity, countIf(severity = 'high') AS n FROM {signals} WHERE {W} GROUP BY risk_entity"),
            "* | stats count(eval(severity=\"critical\")) as n by risk_entity".into()),
        (q("SELECT risk_entity, sumIf(risk_score, severity = 'high') AS n FROM {signals} WHERE {W} GROUP BY risk_entity"),
            "* | stats sum(if(severity=\"high\", risk_score, 1)) as n by risk_entity".into()),
        (q("SELECT `src_endpoint.ip`, sumIf(`traffic.bytes_out`, class_uid = 4001) AS n FROM {events} WHERE {W} GROUP BY `src_endpoint.ip`"),
            "* | stats sum(if(class_uid=4001, traffic.bytes_out, 0)) as n by src_endpoint.ip".into()),
        // argMax by something other than time is not last().
        (q("SELECT risk_entity, argMax(rule_name, risk_score) AS r FROM {signals} WHERE {W} GROUP BY risk_entity"),
            "* | stats last(rule_name) as r by risk_entity".into()),
        // any() is not first().
        (q("SELECT risk_entity, any(rule_name) AS r FROM {signals} WHERE {W} GROUP BY risk_entity"),
            "* | stats first(rule_name) as r by risk_entity".into()),
        // uniqExact of a column that can be empty is not dc().
        (q("SELECT rule_name, uniqExact(risk_entity) AS r FROM {signals} WHERE {W} GROUP BY rule_name"),
            "* | stats dc(risk_entity) as r by rule_name".into()),
        // values() is not a capped array, nor another separator.
        (q("SELECT risk_entity, groupUniqArray(rule_name) AS r FROM {signals} WHERE {W} GROUP BY risk_entity"),
            "* | stats values(rule_name) as r by risk_entity".into()),
        (q("SELECT risk_entity, arrayStringConcat(arrayFilter(x -> x != '', groupUniqArray(100)(toString(rule_name))), '|') AS r FROM {signals} WHERE {W} GROUP BY risk_entity"),
            "* | stats values(rule_name) as r by risk_entity".into()),
        (q("SELECT risk_entity, arrayStringConcat(arrayFilter(x -> x != '', groupUniqArray(10)(toString(rule_name))), ', ') AS r FROM {signals} WHERE {W} GROUP BY risk_entity"),
            "* | stats values(rule_name) as r by risk_entity".into()),
        // lower() folding holds only for a column the source writes lowercase.
        (q("SELECT risk_entity, countIf(rule_name = 'x') AS n FROM {signals} WHERE {W} GROUP BY risk_entity"),
            "* | stats count(eval(rule_name=\"x\")) as n by risk_entity".into()),
    ];
    let mut failures = Vec::new();
    for (sql, npl) in &cases {
        match compare_npl_with_sql(sql, npl, &ctx) {
            Ok(d) if d.is_empty() => failures.push(format!("{sql}\n  called exact against {npl}")),
            Ok(d) => println!("[not exact] {sql}\n    {:?}", d.iter().map(|d| d.detail.as_str()).collect::<Vec<_>>()),
            Err(e) => println!("[unreadable] {sql}: {e}"),
        }
    }
    println!("near misses: {}", cases.len());
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The comparator's twin of the near misses: what IS equivalent verifies
/// exact, so the near misses fail for the reason they name.
#[test]
fn proven_signals_forms_verify_exact() {
    let ctx = ConvertContext::new(profile_for_id(SchemaId::Ocsf));
    for sql in [
        "SELECT risk_entity, countIf(severity IN ('high', 'critical')) AS hot, sumIf(risk_score, severity = 'critical') AS crit_risk, uniqExact(rule_id) AS rules, argMax(rule_name, timestamp) AS last_rule, argMin(rule_name, timestamp) AS first_rule, min(timestamp) AS first_fire, max(timestamp) AS last_fire FROM {signals} WHERE {W} AND risk_entity != '' GROUP BY risk_entity HAVING rules >= 2 ORDER BY rules DESC, risk_entity ASC LIMIT 50",
        "SELECT rule_name, countIf(detection_path = 'scheduled' AND risk_score >= 50) AS n, uniqExact(matched_log_id) AS events FROM {signals} WHERE {W} GROUP BY rule_name",
    ] {
        let sql = sql.replace("{W}", W);
        let r = convert_sql_to_npl(&sql, &ctx);
        assert!(r.exact, "{sql}\n  => {:?}\n  {:?} {:?}", r.npl, r.differences, r.unsupported);
    }
}

/// The plain event / signal join converts to a subsearch whose only
/// difference is the subsearch's row cap.
#[test]
fn a_plain_signals_join_converts_with_the_subsearch_cap_as_its_one_difference() {
    let ctx = ConvertContext::new(profile_for_id(SchemaId::Ocsf));
    let sql = format!(
        "SELECT id, timestamp, `device.hostname` FROM {{events}} WHERE {W} AND class_uid = 1007 AND id IN (SELECT matched_log_id FROM {{signals}} WHERE {W} AND severity IN ('high', 'critical')) ORDER BY timestamp DESC LIMIT 200"
    );
    let r = convert_sql_to_npl(&sql, &ctx);
    assert_eq!(
        r.npl.as_deref(),
        Some("class_uid=1007 id IN [dataset=signals severity IN (\"high\", \"critical\") | return matched_log_id] | sort -timestamp | head 200 | table id, timestamp, device.hostname")
    );
    assert_eq!(r.dataset, crate::query::Dataset::Logs);
    assert_eq!(r.differences.len(), 1, "{:?}", r.differences);
    assert!(r.differences[0].detail.contains("at most 10000 distinct values"), "{:?}", r.differences);
    // A signals query's subsearch over events names dataset=logs.
    let sql = format!(
        "SELECT rule_name, count() AS n FROM {{signals}} WHERE {W} AND matched_log_id IN (SELECT id FROM {{events}} WHERE {W} AND class_uid = 1007) GROUP BY rule_name"
    );
    let r = convert_sql_to_npl(&sql, &ctx);
    assert_eq!(
        r.npl.as_deref(),
        Some("matched_log_id IN [dataset=logs class_uid=1007 | return id] | stats count() as n by rule_name")
    );
    assert!(r.differences.iter().all(|d| d.detail.contains("at most 10000")), "{:?}", r.differences);
}

/// nPL's values() cap, which the comparator's messages quote.
#[test]
fn the_values_cap_matches_the_generator() {
    let ctx = ConvertContext::new(profile_for_id(SchemaId::Ocsf));
    let sql = canon::compile_npl("* | stats values(rule_name) as r by risk_entity", &ctx, crate::query::Dataset::Signals)
        .expect("compiles");
    assert!(sql.contains(&format!("groupUniqArray({})", canon::NPL_VALUES_CAP)), "{sql}");
}

/// A capped groupUniqArray converts to values() where Search will run it (a
/// filtered search), approximate, with the cap and format difference
/// spelled out; unfiltered, Search's memory guard refuses values(), so no
/// nPL is handed out at all.
#[test]
fn a_capped_group_uniq_array_is_approximate_or_refused_never_exact() {
    let ctx = ConvertContext::new(profile_for_id(SchemaId::Ocsf));
    let filtered = format!(
        "SELECT risk_entity, groupUniqArray(10)(rule_name) AS rules FROM {{signals}} WHERE {W} AND severity = 'critical' GROUP BY risk_entity"
    );
    let r = convert_sql_to_npl(&filtered, &ctx);
    assert_eq!(r.npl.as_deref(), Some("severity=\"critical\" | stats values(rule_name) as rules by risk_entity"));
    assert!(!r.exact);
    assert!(r.differences.iter().any(|d| d.detail.contains("keeps at most 10 distinct")), "{:?}", r.differences);
    let unfiltered = format!("SELECT risk_entity, groupUniqArray(10)(rule_name) AS rules FROM {{signals}} WHERE {W} GROUP BY risk_entity");
    let r = convert_sql_to_npl(&unfiltered, &ctx);
    assert!(r.npl.is_none());
    assert!(r.unsupported.expect("refused").reason.contains("memory guard"));
}
