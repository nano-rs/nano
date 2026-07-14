use super::*;

fn alert(severity: &str, rule_name: Option<&str>, kind: Option<&str>, source_id: Option<&str>) -> AlertSummary {
    AlertSummary {
        severity: severity.into(),
        rule_name: rule_name.map(str::to_string),
        kind: kind.map(str::to_string),
        source_id: source_id.map(str::to_string),
    }
}

#[test]
fn counts_bucket_by_severity_most_severe_first() {
    let mut c = Counts::default();
    c.add("critical");
    c.add("critical");
    c.add("high");
    c.add("informational");
    assert_eq!(c.by_sev, [2, 1, 0, 0, 1]);
    assert_eq!(c.total(), 4);
}

#[test]
fn counts_are_case_insensitive() {
    let mut c = Counts::default();
    c.add("Critical");
    c.add("HIGH");
    assert_eq!(c.by_sev[0], 1);
    assert_eq!(c.by_sev[1], 1);
}

#[test]
fn unknown_severity_still_moves_the_total() {
    // A severity we don't recognize must not silently vanish from the tally.
    let mut c = Counts::default();
    c.add("catastrophic");
    c.add("");
    assert_eq!(c.total(), 2);
    // Bucketed as the lowest rank.
    assert_eq!(c.by_sev[4], 2);
}

#[test]
fn now_cursor_is_a_parseable_timestamp_and_nil_uuid() {
    use base64::Engine as _;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(now_cursor())
        .expect("cursor is valid base64");
    let decoded = String::from_utf8(decoded).expect("cursor is utf8");

    let (ts, id) = decoded.split_once('|').expect("cursor is `<ts>|<uuid>`");
    assert_eq!(id, "00000000-0000-0000-0000-000000000000");
    // The server parses the timestamp with parse_from_rfc3339 — so must we.
    chrono::DateTime::parse_from_rfc3339(ts).expect("timestamp is rfc3339");
}

#[test]
fn sev_label_and_capitalize() {
    assert_eq!(sev_label("critical", 3), "Critical: 3");
    assert_eq!(capitalize("high"), "High");
    assert_eq!(capitalize(""), "");
}

#[test]
fn banner_title_pairs_severity_and_rule_name() {
    let a = alert("critical", Some("Suspicious PowerShell"), None, None);
    assert_eq!(banner_title(&a), "Critical · Suspicious PowerShell");
}

#[test]
fn banner_title_falls_back_when_rule_name_missing_or_empty() {
    assert_eq!(banner_title(&alert("high", None, None, None)), "High · Alert");
    assert_eq!(banner_title(&alert("high", Some(""), None, None)), "High · Alert");
    // No severity either → just the fallback name, no stray separator.
    assert_eq!(banner_title(&alert("", None, None, None)), "Alert");
}

#[test]
fn risk_notable_body_surfaces_the_entity() {
    let a = alert("high", None, Some("risk_notable"), Some("host:workstation-7"));
    assert_eq!(banner_body(&a), "Risk notable · host: workstation-7");
}

#[test]
fn ordinary_alert_body_is_generic() {
    let a = alert("medium", Some("Rule"), Some("detection"), Some("rule_abc"));
    assert_eq!(banner_body(&a), "New alert in nano");
}

#[test]
fn summary_body_lists_only_nonzero_severities_most_severe_first() {
    let alerts = [
        alert("high", None, None, None),
        alert("critical", None, None, None),
        alert("high", None, None, None),
    ];
    assert_eq!(summary_body(&alerts), "1 critical, 2 high");
}
