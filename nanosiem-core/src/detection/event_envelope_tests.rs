// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unit tests for the canonical `_match_*` event envelope (NAN-830).

use super::*;
use serde_json::json;

fn normalize(v: Value) -> Value {
    let mut v = v;
    normalize_match_event(&mut v);
    v
}

fn field<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key)
        .and_then(|x| x.as_str())
        .unwrap_or_else(|| panic!("missing {}", key))
}

#[test]
fn raw_cloudtrail_event_uses_canonical_fields() {
    let v = normalize(json!({
        "timestamp": "2026-05-16T18:00:14.000Z",
        "eventName": "ConsoleLogin",
        "src_ip": "10.0.0.1",
        "_nano_detected_at": "2026-05-16T18:00:15.000Z",
    }));
    assert_eq!(field(&v, MATCH_KIND), "raw");
    assert_eq!(field(&v, MATCH_EVENT_TIME), "2026-05-16T18:00:14.000Z");
    assert_eq!(field(&v, MATCH_EVENT_LABEL), "ConsoleLogin");
}

#[test]
fn underscore_prefixed_aggregate_works() {
    let v = normalize(json!({
        "_first_seen": "2026-05-16 14:20:28.000000",
        "_last_seen": "2026-05-16 14:35:10.000000",
        "_nano_detected_at": "2026-05-16T14:35:20.000Z",
        "denied_count": 1582,
        "unique_actions": 110,
    }));
    assert_eq!(field(&v, MATCH_KIND), "aggregate");
    assert_eq!(field(&v, MATCH_EVENT_TIME), "2026-05-16 14:35:10.000000");
    assert_eq!(field(&v, MATCH_EVENT_LABEL), "1,582 denied count");
}

#[test]
fn user_aliased_aggregate_works() {
    let v = normalize(json!({
        "first_seen": "2026-05-16T17:45:21.000000Z",
        "last_seen": "2026-05-16T18:00:14.000000Z",
        "_nano_detected_at": "2026-05-16T18:00:19.772Z",
        "actions_attempted": "getsecretvalue, deletesecurity, ...",
        "denied_count": 1000000,
        "unique_actions": 76,
    }));
    assert_eq!(field(&v, MATCH_KIND), "aggregate");
    assert_eq!(field(&v, MATCH_EVENT_TIME), "2026-05-16T18:00:14.000000Z");
    // actions_attempted wins over count-based derivation
    assert_eq!(
        field(&v, MATCH_EVENT_LABEL),
        "getsecretvalue, deletesecurity, ..."
    );
}

#[test]
fn aggregate_with_only_counts_falls_back_to_largest() {
    let v = normalize(json!({
        "first_seen": "2026-05-16 14:20:28.000000",
        "last_seen": "2026-05-16 14:35:10.000000",
        "failure_count": 12,
        "success_count": 8,
    }));
    assert_eq!(field(&v, MATCH_KIND), "aggregate");
    assert_eq!(field(&v, MATCH_EVENT_LABEL), "12 failure count");
}

#[test]
fn aggregate_with_only_actions_attempted() {
    let v = normalize(json!({
        "actions_attempted": "PutObject, DeleteObject",
    }));
    assert_eq!(field(&v, MATCH_KIND), "aggregate");
    assert_eq!(field(&v, MATCH_EVENT_LABEL), "PutObject, DeleteObject");
}

#[test]
fn aggregate_with_no_summary_fields_uses_generic_fallback() {
    let v = normalize(json!({
        "first_seen": "2026-05-16 14:20:28.000000",
        "last_seen": "2026-05-16 14:35:10.000000",
        "user": "intern01",
    }));
    assert_eq!(field(&v, MATCH_KIND), "aggregate");
    assert_eq!(field(&v, MATCH_EVENT_LABEL), "stats aggregate");
}

#[test]
fn sequence_row_gets_step_and_duration_summary() {
    let v = normalize(json!({
        "timestamp": "2026-07-24T15:00:00Z",
        "user": "alice",
        "step1_url": "https://search.example/",
        "step2_file_path": "C:\\Users\\alice\\Downloads\\search_term.zip",
        "step3_process_name": "wscript.exe",
        "step4_dest_host": "low-prevalence.example",
        "step5_process_name": "powershell.exe",
        "sequence_duration_seconds": 64,
        "risk_score": 95,
    }));
    assert_eq!(field(&v, MATCH_KIND), "sequence");
    assert_eq!(field(&v, MATCH_EVENT_LABEL), "5-step sequence · 64s");
}

#[test]
fn malformed_negative_sequence_duration_is_omitted() {
    let v = normalize(json!({
        "step1_user": "alice",
        "step2_process_name": "powershell.exe",
        "sequence_duration_seconds": -42,
    }));
    assert_eq!(field(&v, MATCH_KIND), "sequence");
    assert_eq!(field(&v, MATCH_EVENT_LABEL), "2-step sequence");
}

#[test]
fn aggregate_alias_without_time_markers_is_recognized() {
    let v = normalize(json!({
        "src_host": "WS-ENG-003",
        "hits": 12,
        "commands": ["whoami.exe", "net.exe"],
    }));
    assert_eq!(field(&v, MATCH_KIND), "aggregate");
    assert_eq!(field(&v, MATCH_EVENT_LABEL), "12 hits");
}

#[test]
fn aggregate_array_summary_is_compact() {
    let v = normalize(json!({
        "first_seen": "2026-07-24T15:00:00Z",
        "last_seen": "2026-07-24T15:01:00Z",
        "operations": ["DeleteBucket", "DeleteObject", "StopLogging", "DeleteTrail"],
    }));
    assert_eq!(
        field(&v, MATCH_EVENT_LABEL),
        "DeleteBucket, DeleteObject, StopLogging, …"
    );
}

#[test]
fn projected_process_row_uses_process_name() {
    let v = normalize(json!({
        "timestamp": "2026-07-24T15:00:00Z",
        "user": "alice",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -enc ...",
    }));
    assert_eq!(field(&v, MATCH_KIND), "raw");
    assert_eq!(field(&v, MATCH_EVENT_LABEL), "powershell.exe");
}

#[test]
fn projected_file_row_uses_action_and_basename() {
    let v = normalize(json!({
        "file_action": "created",
        "file_path": "C:\\Users\\alice\\Downloads\\search_term.zip",
    }));
    assert_eq!(field(&v, MATCH_EVENT_LABEL), "created · search_term.zip");
}

#[test]
fn projected_auth_row_uses_result_and_type() {
    let v = normalize(json!({
        "auth_result": "failed",
        "auth_type": "RDP",
        "user": "alice",
    }));
    assert_eq!(field(&v, MATCH_EVENT_LABEL), "failed RDP authentication");
}

#[test]
fn nested_ocsf_network_row_gets_request_summary() {
    let v = normalize(json!({
        "http_request": {
            "http_method": "GET",
            "url": {
                "hostname": "low-prevalence.example"
            }
        }
    }));
    assert_eq!(field(&v, MATCH_EVENT_LABEL), "GET · low-prevalence.example");
}

#[test]
fn source_type_is_the_last_data_driven_fallback() {
    let v = normalize(json!({
        "source_type": "windows_sysmon"
    }));
    assert_eq!(field(&v, MATCH_EVENT_LABEL), "windows sysmon event");
}

#[test]
fn empty_event_gets_non_empty_fallback() {
    let v = normalize(json!({}));
    assert_eq!(field(&v, MATCH_KIND), "raw");
    assert!(v.get(MATCH_EVENT_TIME).is_none());
    assert_eq!(field(&v, MATCH_EVENT_LABEL), "Matched event");
}

#[test]
fn nano_detected_at_does_not_become_event_time() {
    // No other timestamp fields — `_nano_detected_at` is excluded both
    // from the direct list and the loose scan (preserves NAN-739).
    let v = normalize(json!({
        "_nano_detected_at": "2026-05-16T18:00:19.000Z",
        "src_ip": "10.0.0.1",
        "eventName": "S3Read",
    }));
    assert!(v.get(MATCH_EVENT_TIME).is_none());
    assert_eq!(field(&v, MATCH_EVENT_LABEL), "S3Read");
    assert_eq!(field(&v, MATCH_KIND), "raw");
}

#[test]
fn loose_scan_picks_latest_user_aliased_time() {
    let v = normalize(json!({
        "bucket_start": "2026-05-16T10:00:00.000Z",
        "bucket_end":   "2026-05-16T11:00:00.000Z",
        "eventName": "Probe",
    }));
    assert_eq!(field(&v, MATCH_EVENT_TIME), "2026-05-16T11:00:00.000Z");
}

#[test]
fn non_object_event_is_left_untouched() {
    let mut v = json!([1, 2, 3]);
    normalize_match_event(&mut v);
    assert_eq!(v, json!([1, 2, 3]));
}

#[test]
fn single_last_seen_field_alone_does_not_trigger_aggregate() {
    // Some upstream agents emit a `last_seen` on raw events. We require
    // BOTH first_seen and last_seen together to call it an aggregate.
    let v = normalize(json!({
        "timestamp": "2026-05-16T18:00:14.000Z",
        "last_seen": "2026-05-16T18:00:14.000Z",
        "eventName": "GenericEvent",
    }));
    assert_eq!(field(&v, MATCH_KIND), "raw");
    assert_eq!(field(&v, MATCH_EVENT_LABEL), "GenericEvent");
}

#[test]
fn format_count_renders_thousands() {
    assert_eq!(format_count(1582.0), "1,582");
    assert_eq!(format_count(1_000_000.0), "1,000,000");
    assert_eq!(format_count(42.0), "42");
    assert_eq!(format_count(0.0), "0");
}

// ---------------------------------------------------------------------------
// Entity envelope (NAN-2341)
// ---------------------------------------------------------------------------

#[test]
fn risk_dataset_row_resolves_entity_and_label() {
    // The seeded `accumulated_risk_threshold_exceeded` rule's projection —
    // `dataset=risk` carries an explicit entity pair and NO UDM/OCSF column,
    // which is what rendered the match list as `unknown` / `0 IPs`.
    let v = normalize(json!({
        "entity": "198.51.100.10",
        "entity_type": "ip",
        "score_24h": 10350,
        "score_7d": 35212,
        "distinct_rules_7d": 1,
        "last_rule_name": "cloudtrail_destructive_ops_suspicious_source",
    }));
    assert_eq!(field(&v, MATCH_ENTITY), "198.51.100.10");
    assert_eq!(field(&v, MATCH_ENTITY_TYPE), "ip");
    assert_eq!(
        field(&v, MATCH_EVENT_LABEL),
        "risk 10,350 (24h) · cloudtrail_destructive_ops_suspicious_source"
    );
}

#[test]
fn risk_row_without_last_rule_labels_on_score_alone() {
    let v = normalize(json!({
        "entity": "svc-deploy",
        "entity_type": "user",
        "score_7d": 1200,
    }));
    assert_eq!(field(&v, MATCH_EVENT_LABEL), "risk 1,200 (7d)");
}

#[test]
fn explicit_entity_without_declared_type_is_typed_by_value() {
    for (value, expected) in [
        ("10.0.0.5", "ip"),
        ("dan@corp.local", "email"),
        ("WORKSTATION-7", "user"),
        ("db-01.corp.local", "hostname"),
    ] {
        let v = normalize(json!({ "entity": value }));
        assert_eq!(field(&v, MATCH_ENTITY), value);
        assert_eq!(field(&v, MATCH_ENTITY_TYPE), expected, "{value}");
    }
}

#[test]
fn entity_precedence_matches_the_frontend_identity_before_network() {
    // A raw row carrying both — the user is the subject, not the source IP.
    let v = normalize(json!({
        "user": "svc-backup",
        "src_host": "web-03",
        "src_ip": "10.1.2.3",
    }));
    assert_eq!(field(&v, MATCH_ENTITY), "svc-backup");
    assert_eq!(field(&v, MATCH_ENTITY_TYPE), "user");

    let v = normalize(json!({ "src_host": "web-03", "src_ip": "10.1.2.3" }));
    assert_eq!(field(&v, MATCH_ENTITY), "web-03");
    assert_eq!(field(&v, MATCH_ENTITY_TYPE), "hostname");

    let v = normalize(json!({ "src_ip": "10.1.2.3" }));
    assert_eq!(field(&v, MATCH_ENTITY), "10.1.2.3");
    assert_eq!(field(&v, MATCH_ENTITY_TYPE), "ip");
}

#[test]
fn ocsf_rows_resolve_through_flat_and_nested_keys() {
    // Aggregate rows land the group-by key as a flat dotted string; raw OCSF
    // events nest it. `str_field` reads both.
    let flat = normalize(json!({ "src_endpoint.ip": "203.0.113.7" }));
    assert_eq!(field(&flat, MATCH_ENTITY), "203.0.113.7");
    assert_eq!(field(&flat, MATCH_ENTITY_TYPE), "ip");

    let nested = normalize(json!({ "actor": { "user": { "name": "alice" } } }));
    assert_eq!(field(&nested, MATCH_ENTITY), "alice");
    assert_eq!(field(&nested, MATCH_ENTITY_TYPE), "user");
}

#[test]
fn arn_entity_is_emitted_raw_and_typed_by_shape() {
    let role = normalize(json!({
        "user_identity": { "arn": "arn:aws:sts::1234:assumed-role/deploy/session" },
    }));
    // Raw — shortening to "session" is the frontend's display concern.
    assert_eq!(
        field(&role, MATCH_ENTITY),
        "arn:aws:sts::1234:assumed-role/deploy/session"
    );
    assert_eq!(field(&role, MATCH_ENTITY_TYPE), "role");

    let user = normalize(json!({
        "user_identity": { "arn": "arn:aws:iam::1234:user/dan" },
    }));
    assert_eq!(field(&user, MATCH_ENTITY_TYPE), "user");
}

#[test]
fn row_with_no_subject_omits_the_entity_fields() {
    // Absent beats a fabricated "unknown" — the frontend can then fall back to
    // its schema-aware resolver instead of trusting a placeholder.
    let v = normalize(json!({ "count": 12, "eventName": "ConsoleLogin" }));
    assert!(v.get(MATCH_ENTITY).is_none());
    assert!(v.get(MATCH_ENTITY_TYPE).is_none());
}

#[test]
fn blank_entity_type_falls_back_to_value_typing() {
    let v = normalize(json!({ "entity": "10.0.0.5", "entity_type": "   " }));
    assert_eq!(field(&v, MATCH_ENTITY_TYPE), "ip");
}

#[test]
fn unrecognised_entity_type_passes_through_lowercased() {
    // `cloud_account` (and any future backend type) reaches the client intact.
    let v = normalize(json!({ "entity": "1234567890", "entity_type": "Cloud_Account" }));
    assert_eq!(field(&v, MATCH_ENTITY_TYPE), "cloud_account");
}

#[test]
fn declared_risk_subject_overrides_unrelated_actor_and_inherits_across_pipes() {
    let mut rows = vec![json!({"actor.user.uid": "automation", "target": "203.0.113.8"})];
    normalize_match_events_for_query(&mut rows,
        "* | risk score=10 entity=target | risk score=20 | table target");
    assert_eq!(rows[0][MATCH_ENTITY], "203.0.113.8");
    assert_eq!(rows[0][MATCH_ENTITY_TYPE], "ip");

    let mut rows = vec![json!({"first": "old", "second": "new"})];
    normalize_match_events_for_query(&mut rows,
        "* | risk score=10 entity=first | risk score=20 entity=second");
    assert_eq!(rows[0][MATCH_ENTITY], "new");
}

#[test]
fn risk_subject_handles_numeric_nested_and_missing_fields() {
    for (row, expected, ty) in [
        (json!({"subject": 42}), "42", "user"),
        (json!({"subject": "person@example.org"}), "person@example.org", "email"),
        (json!({"subject": "host.example.org"}), "host.example.org", "hostname"),
    ] {
        let mut rows = vec![row];
        normalize_match_events_for_query(&mut rows, "* | risk score=10 entity=subject");
        assert_eq!(rows[0][MATCH_ENTITY], expected);
        assert_eq!(rows[0][MATCH_ENTITY_TYPE], ty);
    }
    let mut rows = vec![json!({"target": {"uid": "nested"}})];
    normalize_match_events_for_query(&mut rows, "* | risk score=10 entity=target.uid");
    assert_eq!(rows[0][MATCH_ENTITY], "nested");
    for missing in [Value::Null, json!(""), json!(" "), json!([]), json!({})] {
        let mut rows = vec![json!({"subject": missing})];
        normalize_match_events_for_query(&mut rows, "* | risk score=10 entity=subject");
        assert!(rows[0].get(MATCH_ENTITY).is_none());
    }
}

#[test]
fn risk_output_envelope_prefers_scored_entity_and_keeps_rows_isolated() {
    let mut rows = vec![
        json!({"risk_entity": "usr_one", "actor.user.uid": "automation"}),
        json!({"risk_entity": "203.0.113.9"}),
        json!({"risk_entity": "unknown"}),
    ];
    normalize_match_events_for_query(&mut rows, "*");
    assert_eq!(rows[0][MATCH_ENTITY], "usr_one");
    assert_eq!(rows[1][MATCH_ENTITY], "203.0.113.9");
    assert_eq!(rows[1][MATCH_ENTITY_TYPE], "ip");
    assert!(rows[2].get(MATCH_ENTITY).is_none());
    let mut invalid = vec![json!({"user": "fallback"})];
    normalize_match_events_for_query(&mut invalid, "| invalid command");
    assert_eq!(invalid[0][MATCH_ENTITY], "fallback");
}

// ---------------------------------------------------------------- event_summary (NAN-5756)

#[test]
fn summary_ocsf_process_row_reads_parent_command_line() {
    let row = json!({
        "process.name": "powershell.exe",
        "process.cmd_line": "powershell.exe -nop -w hidden -enc SQBFAFgA",
        "actor.process.name": "WINWORD.EXE",
        "message": "",
        "source_type": "windows_sysmon",
    });
    assert_eq!(
        event_summary(&row).as_deref(),
        Some("WINWORD.EXE → powershell.exe -nop -w hidden -enc SQBFAFgA")
    );
}

#[test]
fn summary_names_the_image_when_the_command_line_does_not() {
    let row = json!({ "process": { "name": "svch0st.exe", "cmd_line": "--install" } });
    assert_eq!(event_summary(&row).as_deref(), Some("svch0st.exe: --install"));
}

#[test]
fn summary_network_row_carries_destination_and_port() {
    let row = json!({
        "process.name": "svch0st.exe",
        "dst_endpoint.ip": "185.220.101.47",
        "dst_endpoint.port": 9001,
        "message": "connection established",
    });
    assert_eq!(event_summary(&row).as_deref(), Some("svch0st.exe → 185.220.101.47:9001"));
    // UDM columns, string port.
    let udm = json!({ "dest_ip": "10.0.0.9", "dest_port": "443" });
    assert_eq!(event_summary(&udm).as_deref(), Some("10.0.0.9:443"));
}

#[test]
fn summary_ocsf_network_row_names_the_actor_process() {
    let row = json!({
        "actor.process.name": "svch0st.exe",
        "dst_endpoint.ip": "185.220.101.47",
        "dst_endpoint.port": 9001,
    });
    assert_eq!(event_summary(&row).as_deref(), Some("svch0st.exe → 185.220.101.47:9001"));
}

#[test]
fn summary_dns_and_file_rows() {
    let dns = json!({ "query.hostname": "a1b2.tunnel.example", "dst_endpoint.port": 0 });
    assert_eq!(event_summary(&dns).as_deref(), Some("dns a1b2.tunnel.example"));
    let file = json!({ "file.path": "C:\\Users\\a\\Invoice.docm", "activity_name": "Create" });
    assert_eq!(event_summary(&file).as_deref(), Some("Create C:\\Users\\a\\Invoice.docm"));
}

#[test]
fn summary_falls_back_to_message_then_label_never_to_the_source() {
    let msg = json!({ "message": "  User alice logged on  ", "source_type": "okta" });
    assert_eq!(event_summary(&msg).as_deref(), Some("User alice logged on"));
    let auth = json!({ "auth_type": "password", "auth_result": "failure" });
    assert_eq!(event_summary(&auth).as_deref(), Some("failure password authentication"));
    // Only the source: the list already shows it, so no summary.
    assert_eq!(event_summary(&json!({ "source_type": "okta" })), None);
    assert_eq!(event_summary(&json!("not an object")), None);
}

#[test]
fn summary_elides_a_long_command_line() {
    let long = format!("cmd.exe /c {}", "A".repeat(600));
    let s = event_summary(&json!({ "process.cmd_line": long })).unwrap();
    assert!(s.ends_with('…'), "{s}");
    assert!(s.chars().count() <= SUMMARY_CMD_CHARS + 1, "{}", s.chars().count());
}

#[test]
fn semantic_label_keeps_its_source_fallback() {
    let v = normalize(json!({ "timestamp": "2026-05-16T18:00:14Z", "source_type": "aws_cloudtrail" }));
    assert_eq!(field(&v, MATCH_EVENT_LABEL), "aws cloudtrail event");
}

// ---------------------------------------------------------------- event_summary hardening (NAN-5756 review)

#[test]
fn summary_is_one_plain_line_without_bidi_or_control_characters() {
    let row = json!({
        "process.name": "cmd.exe",
        "process.cmd_line": "cmd.exe /c copy Invoice_\u{202E}fdp.exe\r\nFORGED LINE\t\u{200B}x\u{0007}",
        "actor.process.name": "WINWORD\u{2066}.EXE",
    });
    let s = event_summary(&row).unwrap();
    assert_eq!(s, "WINWORD.EXE → cmd.exe /c copy Invoice_fdp.exe FORGED LINE x");
    assert!(!s.chars().any(|c| c.is_control()), "{s:?}");

    // A message fallback too.
    let msg = json!({ "message": "line one\nline two\u{202E}" });
    assert_eq!(event_summary(&msg).as_deref(), Some("line one line two"));
    // A value that is only invisible characters is absent, not blank.
    assert_eq!(event_summary(&json!({ "message": "\u{200B}\u{202E}\n" })), None);
}

#[test]
fn summary_bounds_every_part_so_a_huge_field_cannot_hide_the_rest() {
    let huge = "P".repeat(5000);
    let row = json!({
        "actor.process.name": huge,
        "process.name": "Q".repeat(5000),
        "process.cmd_line": "powershell.exe -enc AAAA",
        "dst_endpoint.ip": "185.220.101.47",
        "dst_endpoint.port": "9".repeat(50),
    });
    let s = event_summary(&row).unwrap();
    assert!(s.chars().count() <= EVENT_SUMMARY_MAX_CHARS, "{}", s.chars().count());
    assert!(s.contains("powershell.exe -enc AAAA"), "{s}");
    assert!(s.contains("185.220.101.47:"), "{s}");

    let long_message = json!({ "message": "m".repeat(10_000) });
    let m = event_summary(&long_message).unwrap();
    assert!(m.chars().count() <= 400 && m.ends_with('…'), "{}", m.chars().count());
}

#[test]
fn summary_urls_lose_userinfo_query_and_fragment() {
    let row = json!({ "url.url_string": "https://bob:hunter2@files.example.com/drop/a.bin?access_token=SECRET&sig=X#frag" });
    let s = event_summary(&row).unwrap();
    assert_eq!(s, "https://files.example.com/drop/a.bin");
    for secret in ["hunter2", "bob", "SECRET", "sig=", "frag"] {
        assert!(!s.contains(secret), "{secret} leaked: {s}");
    }
    // Unparseable (relative) URL: the same cut by hand.
    let rel = json!({ "http_request.url.url_string": "u:p@host/x?api_key=K" });
    assert_eq!(event_summary(&rel).as_deref(), Some("host/x"));
    // URL arguments on a command line are redacted too.
    let cmd = json!({ "process.cmd_line": "curl.exe -o x https://u:pw@c2.example/p?token=T" });
    let c = event_summary(&cmd).unwrap();
    assert_eq!(c, "curl.exe -o x https://c2.example/p");
}

#[test]
fn summary_ocsf_file_activity_keeps_the_path_beside_the_actor() {
    let row = json!({
        "class_uid": 1001,
        "activity_name": "Create",
        "actor.process.name": "WINWORD.EXE",
        "file.path": "C:\\Users\\a\\AppData\\Local\\Temp\\svch0st.exe",
    });
    assert_eq!(
        event_summary(&row).as_deref(),
        Some("WINWORD.EXE → Create C:\\Users\\a\\AppData\\Local\\Temp\\svch0st.exe")
    );
    // A command line that already names the path does not repeat it.
    let launch = json!({ "process.cmd_line": "C:\\t\\a.exe --x", "file.path": "C:\\t\\a.exe" });
    assert_eq!(event_summary(&launch).as_deref(), Some("C:\\t\\a.exe --x"));
}

#[test]
fn summary_ocsf_api_auth_and_registry_rows_read_without_a_message() {
    let api = json!({ "api.operation": "DeleteBucket", "api.service.name": "s3.amazonaws.com", "actor.user.name": "alice" });
    assert_eq!(event_summary(&api).as_deref(), Some("s3.amazonaws.com DeleteBucket · alice"));
    let auth = json!({ "auth_protocol": "Kerberos", "status": "Failure", "user.name": "svc_backup" });
    assert_eq!(event_summary(&auth).as_deref(), Some("Failure Kerberos authentication · svc_backup"));
    let reg = json!({ "activity_name": "Set", "reg_value.path": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\upd" });
    assert_eq!(
        event_summary(&reg).as_deref(),
        Some("Set HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\upd")
    );
    let activity = json!({ "activity_name": "Logon", "class_name": "Authentication" });
    assert_eq!(event_summary(&activity).as_deref(), Some("Logon"));
}

#[test]
fn summary_udm_dns_query_column_does_not_go_blank() {
    assert_eq!(event_summary(&json!({ "query": "x1.tunnel.example" })).as_deref(), Some("dns x1.tunnel.example"));
    // A nested OCSF `query` object is not read as a string.
    let nested = json!({ "query": { "hostname": "y.example" } });
    assert_eq!(event_summary(&nested).as_deref(), Some("dns y.example"));
}
