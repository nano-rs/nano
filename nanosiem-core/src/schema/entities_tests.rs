//! Tests for class-aware entity resolution (NAN-5271 C).
//!
//! The fixtures are real `ocsf_logs` rows from the local OCSF dataset, one per
//! class, in the shape ClickHouse `JSONEachRow` returns them: flat dotted keys,
//! with empty strings for unset promoted columns.

use super::*;
use serde_json::json;

/// Build a JSONEachRow-shaped OCSF row: every entity column present, '' unless set.
fn ocsf_row(class_uid: u64, source_type: &str, set: &[(&str, &str)]) -> Map<String, Value> {
    let mut row = Map::new();
    row.insert("class_uid".into(), json!(class_uid));
    row.insert("source_type".into(), json!(source_type));
    for col in [
        "src_endpoint.hostname",
        "device.hostname",
        "dst_endpoint.hostname",
        "src_endpoint.ip",
        "dst_endpoint.ip",
        "user.name",
        "actor.user.name",
        "process.name",
        "actor.process.name",
        "process.cmd_line",
        "actor.process.cmd_line",
        "file.hashes.sha256",
        "process.file.hashes.sha256",
        "actor.process.file.hashes.sha256",
        "http_request.url.hostname",
        "query.hostname",
        "url.hostname",
    ] {
        row.insert(col.into(), json!(""));
    }
    for (k, v) in set {
        row.insert((*k).into(), json!(v));
    }
    row
}

fn sysmon_process() -> Map<String, Value> {
    ocsf_row(
        1007,
        "windows_sysmon",
        &[
            ("device.hostname", "ws-exec-072.corp.local"),
            ("actor.user.name", "canderson"),
            ("process.name", "sc.exe"),
            ("actor.process.name", "explorer.exe"),
            ("process.cmd_line", r"C:\Windows\system32\sc.exe start w32time task_started"),
            ("actor.process.cmd_line", r#""C:\Windows\explorer.exe""#),
            (
                "process.file.hashes.sha256",
                "67cbe3a7b9c9b7a2e9fb10a33c1a9a3fd297b6f1598aea374bd9b5d2dee352ec",
            ),
        ],
    )
}

fn sysmon_file() -> Map<String, Value> {
    ocsf_row(
        1001,
        "windows_sysmon",
        &[
            ("device.hostname", "ws-legal-054.corp.local"),
            ("actor.user.name", "ahernandez"),
            ("actor.process.name", "gpupdate.exe"),
            (
                "file.hashes.sha256",
                "9728a8047b5c8cab935a4376acbabd9be6e051c5a7cb530c365bc6f0582af184",
            ),
        ],
    )
}

fn windows_auth() -> Map<String, Value> {
    ocsf_row(
        3002,
        "windows_event",
        &[
            ("src_endpoint.hostname", "lt-sales-050"),
            ("device.hostname", "lt-eng-050.corp.local"),
            ("dst_endpoint.hostname", "lt-eng-050.corp.local"),
            ("src_endpoint.ip", "10.1.8.114"),
            ("user.name", "knguyen"),
        ],
    )
}

fn sysmon_network() -> Map<String, Value> {
    ocsf_row(
        4001,
        "windows_sysmon",
        &[
            ("src_endpoint.hostname", "lt-exec-037.corp.local"),
            ("device.hostname", "lt-exec-037.corp.local"),
            ("src_endpoint.ip", "10.1.7.245"),
            ("dst_endpoint.ip", "5.157.11.19"),
            ("actor.user.name", "cscott"),
            ("actor.process.name", "wsqmcons.exe"),
        ],
    )
}

fn http_proxy() -> Map<String, Value> {
    ocsf_row(
        4002,
        "conduit_proxy",
        &[
            ("dst_endpoint.hostname", "cf.live.cnn.us.prd.media.max.com"),
            ("src_endpoint.ip", "10.1.2.218"),
            ("dst_endpoint.ip", "18.165.83.89"),
            ("http_request.url.hostname", "cf.live.cnn.us.prd.media.max.com"),
        ],
    )
}

fn sysmon_dns() -> Map<String, Value> {
    ocsf_row(
        4003,
        "windows_sysmon",
        &[
            ("src_endpoint.hostname", "ws-support-089.corp.local"),
            ("device.hostname", "ws-support-089.corp.local"),
            ("actor.user.name", "NETWORK SERVICE"),
            ("actor.process.name", "svchost.exe"),
            ("query.hostname", "github.com"),
        ],
    )
}

fn cloudtrail() -> Map<String, Value> {
    ocsf_row(
        6003,
        "aws_cloudtrail",
        &[("src_endpoint.ip", "198.51.100.25"), ("actor.user.name", "intern01")],
    )
}

fn sysmon_registry() -> Map<String, Value> {
    ocsf_row(
        201002,
        "windows_sysmon",
        &[
            ("device.hostname", "ws-hr-083.corp.local"),
            ("actor.user.name", "dtaylor"),
            ("actor.process.name", "TrustedInstaller.exe"),
        ],
    )
}

fn r(row: &Map<String, Value>, k: EntityKind) -> Option<String> {
    resolve(row, k)
}

#[test]
fn sysmon_process_creation_resolves_device_actor_user_and_child_process() {
    let row = sysmon_process();
    assert_eq!(r(&row, EntityKind::SrcHost).as_deref(), Some("ws-exec-072.corp.local"));
    assert_eq!(r(&row, EntityKind::User).as_deref(), Some("canderson"));
    // The launched child is the subject, not the parent.
    assert_eq!(r(&row, EntityKind::Process).as_deref(), Some("sc.exe"));
    assert!(r(&row, EntityKind::CommandLine).unwrap().contains("sc.exe start"));
    assert_eq!(
        r(&row, EntityKind::ProcessHash).as_deref(),
        Some("67cbe3a7b9c9b7a2e9fb10a33c1a9a3fd297b6f1598aea374bd9b5d2dee352ec")
    );
    assert_eq!(r(&row, EntityKind::SrcIp), None);
    assert_eq!(r(&row, EntityKind::DestHost), None);
}

#[test]
fn sysmon_file_resolves_file_hash_and_acting_process() {
    let row = sysmon_file();
    assert_eq!(r(&row, EntityKind::SrcHost).as_deref(), Some("ws-legal-054.corp.local"));
    assert_eq!(r(&row, EntityKind::User).as_deref(), Some("ahernandez"));
    assert_eq!(r(&row, EntityKind::Process).as_deref(), Some("gpupdate.exe"));
    assert_eq!(
        r(&row, EntityKind::FileHash).as_deref(),
        Some("9728a8047b5c8cab935a4376acbabd9be6e051c5a7cb530c365bc6f0582af184")
    );
}

#[test]
fn auth_resolves_source_workstation_not_logging_device() {
    let row = windows_auth();
    assert_eq!(r(&row, EntityKind::SrcHost).as_deref(), Some("lt-sales-050"));
    assert_eq!(r(&row, EntityKind::DestHost).as_deref(), Some("lt-eng-050.corp.local"));
    assert_eq!(r(&row, EntityKind::User).as_deref(), Some("knguyen"));
    assert_eq!(r(&row, EntityKind::SrcIp).as_deref(), Some("10.1.8.114"));
}

#[test]
fn network_proxy_dns_and_cloudtrail() {
    let net = sysmon_network();
    assert_eq!(r(&net, EntityKind::SrcIp).as_deref(), Some("10.1.7.245"));
    assert_eq!(r(&net, EntityKind::DestIp).as_deref(), Some("5.157.11.19"));
    assert_eq!(r(&net, EntityKind::SrcHost).as_deref(), Some("lt-exec-037.corp.local"));
    assert_eq!(r(&net, EntityKind::User).as_deref(), Some("cscott"));
    assert_eq!(r(&net, EntityKind::Process).as_deref(), Some("wsqmcons.exe"));

    let proxy = http_proxy();
    assert_eq!(r(&proxy, EntityKind::Domain).as_deref(), Some("cf.live.cnn.us.prd.media.max.com"));
    assert_eq!(r(&proxy, EntityKind::SrcIp).as_deref(), Some("10.1.2.218"));
    assert_eq!(r(&proxy, EntityKind::SrcHost), None);

    let dns = sysmon_dns();
    assert_eq!(r(&dns, EntityKind::Domain).as_deref(), Some("github.com"));
    assert_eq!(r(&dns, EntityKind::SrcHost).as_deref(), Some("ws-support-089.corp.local"));

    let ct = cloudtrail();
    assert_eq!(r(&ct, EntityKind::User).as_deref(), Some("intern01"));
    assert_eq!(r(&ct, EntityKind::SrcIp).as_deref(), Some("198.51.100.25"));
}

#[test]
fn registry_is_an_endpoint_class() {
    let row = sysmon_registry();
    assert_eq!(ClassFamily::of(Some(201002)), ClassFamily::Endpoint);
    assert_eq!(r(&row, EntityKind::SrcHost).as_deref(), Some("ws-hr-083.corp.local"));
    assert_eq!(r(&row, EntityKind::User).as_deref(), Some("dtaylor"));
}

#[test]
fn primary_entity_never_unknown_on_any_sampled_class() {
    // Finding #7: on these classes `src_endpoint.ip` is empty, and the old
    // attribution became `unknown`.
    let cases: Vec<(Map<String, Value>, EntityKind, &str)> = vec![
        (sysmon_process(), EntityKind::User, "canderson"),
        (sysmon_file(), EntityKind::User, "ahernandez"),
        (sysmon_registry(), EntityKind::User, "dtaylor"),
        (windows_auth(), EntityKind::SrcIp, "10.1.8.114"),
        (sysmon_network(), EntityKind::SrcIp, "10.1.7.245"),
        (http_proxy(), EntityKind::SrcIp, "10.1.2.218"),
        (sysmon_dns(), EntityKind::User, "NETWORK SERVICE"),
        (cloudtrail(), EntityKind::SrcIp, "198.51.100.25"),
    ];
    for (row, kind, value) in cases {
        let (k, _, v) = primary_entity(&row).expect("primary entity");
        assert_eq!((k, v.as_str()), (kind, value), "class {:?}", row.get("class_uid"));
    }
}

#[test]
fn udm_rows_and_udm_keyed_payloads_still_resolve() {
    let udm = json!({
        "src_host": "dc01", "user": "alice", "src_ip": "10.0.0.5", "dest_ip": "1.2.3.4",
        "process_name": "cmd.exe", "file_hash": "abc", "dns_query": "evil.example"
    });
    let row = udm.as_object().unwrap();
    assert_eq!(r(row, EntityKind::SrcHost).as_deref(), Some("dc01"));
    assert_eq!(r(row, EntityKind::User).as_deref(), Some("alice"));
    assert_eq!(r(row, EntityKind::Process).as_deref(), Some("cmd.exe"));
    assert_eq!(r(row, EntityKind::Domain).as_deref(), Some("evil.example"));
    assert_eq!(primary_entity(row).map(|(_, k, v)| (k, v)), Some(("src_ip", "10.0.0.5".into())));

    // The real-time matched-log JSON on OCSF: UDM keys, class-correct values,
    // and an empty src_ip.
    let rt = json!({"src_ip": "", "src_host": "ws-exec-072.corp.local", "src_user": "canderson"});
    let rt = rt.as_object().unwrap();
    assert_eq!(primary_entity(rt).map(|(_, _, v)| v).as_deref(), Some("canderson"));
}

#[test]
fn nested_objects_and_numeric_class_strings_resolve() {
    let nested = json!({"class_uid": "1007", "device": {"hostname": "h1"}, "actor": {"user": {"name": "u1"}}});
    let row = nested.as_object().unwrap();
    assert_eq!(row_class_uid(row), Some(1007));
    assert_eq!(r(row, EntityKind::SrcHost).as_deref(), Some("h1"));
    assert_eq!(r(row, EntityKind::User).as_deref(), Some("u1"));
}

#[test]
fn placeholder_values_are_not_entities() {
    let row = json!({"src_ip": "-", "user": "null", "src_host": "  "});
    assert_eq!(primary_entity(row.as_object().unwrap()), None);
}

#[test]
fn resolve_field_crosses_udm_and_ocsf_names() {
    // A UDM risk_entity_field on an OCSF row (finding #29) …
    let row = sysmon_process();
    assert_eq!(
        resolve_field(&row, "src_host"),
        Some(("ws-exec-072.corp.local".into(), "device.hostname".into()))
    );
    assert_eq!(resolve_field(&row, "user").map(|(v, _)| v).as_deref(), Some("canderson"));
    // … an OCSF field on a UDM-keyed payload …
    let rt = json!({"src_ip": "10.9.9.9"});
    assert_eq!(
        resolve_field(rt.as_object().unwrap(), "src_endpoint.ip"),
        Some(("10.9.9.9".into(), "src_ip".into()))
    );
    // … and a literal key always wins.
    assert_eq!(resolve_field(&row, "process.name").map(|(v, _)| v).as_deref(), Some("sc.exe"));
    // `user.name` named on a Sysmon row resolves through the concept to actor.user.name.
    assert_eq!(resolve_field(&row, "user.name").map(|(v, _)| v).as_deref(), Some("canderson"));
    // Unknown, non-entity fields stay unresolved.
    assert_eq!(resolve_field(&row, "severity"), None);
}

#[test]
fn alert_primary_entity_scans_events() {
    let events = json!([{"message": "no entity"}, Value::Object(sysmon_file())]);
    assert_eq!(alert_primary_entity(None, &events).as_deref(), Some("ahernandez"));
    assert_eq!(
        alert_primary_entity(Some("src_host"), &events).as_deref(),
        Some("ws-legal-054.corp.local")
    );
}

#[test]
fn from_field_name_maps_both_vocabularies() {
    assert_eq!(EntityKind::from_field_name("src_ip"), Some(EntityKind::SrcIp));
    assert_eq!(EntityKind::from_field_name("src_endpoint.ip"), Some(EntityKind::SrcIp));
    assert_eq!(EntityKind::from_field_name("device.hostname"), Some(EntityKind::SrcHost));
    assert_eq!(EntityKind::from_field_name("actor.user.name"), Some(EntityKind::User));
    assert_eq!(EntityKind::from_field_name("src_host_unified"), Some(EntityKind::SrcHost));
    assert_eq!(EntityKind::from_field_name("query.hostname"), Some(EntityKind::Domain));
    assert_eq!(EntityKind::from_field_name("message"), None);
}

#[test]
fn sql_forms_use_physical_columns_only() {
    for kind in EntityKind::ALL {
        let sql = ocsf_sql_expr(kind);
        assert!(!sql.contains("_unified"), "{kind:?}: {sql}");
    }
    assert_eq!(ocsf_sql_expr(EntityKind::SrcIp), r#""src_endpoint.ip""#);
    assert_eq!(ocsf_sql_expr(EntityKind::DestUser), "''");
    let host = ocsf_sql_expr(EntityKind::SrcHost);
    assert!(host.starts_with("multiIf("), "{host}");
    assert!(host.contains("class_uid = 1007"), "{host}");
    // The generic arm matches the src_host_unified ALIAS definition.
    assert!(
        host.ends_with(
            r#"if(notEmpty("src_endpoint.hostname"), "src_endpoint.hostname", "device.hostname"))"#
        ),
        "{host}"
    );
    let primary = ocsf_primary_entity_sql();
    assert!(primary.starts_with(r#"arrayFirst(x -> notEmpty(x), ["src_endpoint.ip", "dst_endpoint.ip", "#), "{primary}");
}

#[test]
fn every_family_list_names_known_ocsf_columns() {
    use crate::schema::SchemaProfile;
    let p = crate::schema::OcsfProfile::new();
    for kind in EntityKind::ALL {
        for family in ClassFamily::ALL {
            for col in ocsf_columns(kind, family) {
                assert!(p.is_known_field(col), "{kind:?}/{family:?}: {col} is not an OCSF column");
            }
        }
    }
}

/// Webhook payload compatibility: a numeric value under the rule's literal
/// entity field was stringified before NAN-5271 C and must stay filled.
#[test]
fn alert_primary_entity_keeps_numeric_literal_field() {
    let events = json!([{"dest_port": 443, "src_ip": "10.0.0.1"}]);
    assert_eq!(alert_primary_entity(Some("dest_port"), &events).as_deref(), Some("443"));
    assert_eq!(alert_primary_entity(Some("src_ip"), &events).as_deref(), Some("10.0.0.1"));
}

/// Every UDM entity key and unified ALIAS name is flagged non-physical, so the
/// OCSF real-time MV maps it to the concept (some, like `user`, are OCSF-known
/// object paths and would otherwise pass DDL validation as a bare column).
#[test]
fn udm_entity_keys_are_non_physical_on_ocsf() {
    for kind in EntityKind::ALL {
        for key in udm_keys(kind) {
            assert!(is_non_physical_entity_name(key), "{key}");
            assert!(EntityKind::from_field_name(key).is_some(), "{key}");
        }
        if let Some(col) = ocsf_indexed_column(kind) {
            assert!(is_non_physical_entity_name(col), "{col}");
        }
    }
    assert!(!is_non_physical_entity_name("src_endpoint.ip"));
    assert!(!is_non_physical_entity_name("actor.user.name"));
}

/// Real Windows logon rows from local `ocsf_logs` (NAN-5271 C follow-up). The
/// logon is logged on the target machine, so on auth classes `device.hostname`
/// is the destination host. 4672 (Authorize Session, 3003) has no
/// `dst_endpoint` at all: 23,895 of 23,895 local rows carried the host only in
/// `device.hostname`.
#[test]
fn auth_dest_host_falls_back_to_device_hostname() {
    // 3003 / 4672, verbatim entity columns.
    let special_logon = json!({
        "class_uid": 3003, "metadata.event_code": "4672",
        "device.hostname": "ws-hr-092.corp.local", "dst_endpoint.hostname": "",
        "src_endpoint.hostname": "", "src_endpoint.ip": "",
        "user.name": "rjackson", "actor.user.name": ""
    });
    let row = special_logon.as_object().unwrap();
    assert_eq!(resolve(row, EntityKind::DestHost).as_deref(), Some("ws-hr-092.corp.local"));
    assert_eq!(resolve(row, EntityKind::User).as_deref(), Some("rjackson"));

    // 3002 / 4624 interactive logon: `dst_endpoint` wins, the source
    // workstation stays the source.
    let logon = json!({
        "class_uid": 3002, "metadata.event_code": "4624", "logon_type_id": 2,
        "device.hostname": "ws-it-063.corp.local", "dst_endpoint.hostname": "ws-it-063.corp.local",
        "src_endpoint.hostname": "ws-mkt-063", "src_endpoint.ip": "10.1.3.118",
        "user.name": "mgonzalez"
    });
    let row = logon.as_object().unwrap();
    assert_eq!(resolve(row, EntityKind::DestHost).as_deref(), Some("ws-it-063.corp.local"));
    assert_eq!(resolve(row, EntityKind::SrcHost).as_deref(), Some("ws-mkt-063"));

    // Outside auth classes `device.hostname` is never the peer.
    let net = json!({"class_uid": 4001, "device.hostname": "ws-01", "dst_endpoint.hostname": ""});
    assert_eq!(resolve(net.as_object().unwrap(), EntityKind::DestHost), None);
}

/// The SQL form carries the same auth-class fallback.
#[test]
fn auth_dest_host_sql_falls_back_to_device_hostname() {
    let sql = ocsf_sql_expr(EntityKind::DestHost);
    assert!(
        sql.contains(r#"class_uid BETWEEN 3000 AND 3999, if(notEmpty("dst_endpoint.hostname"), "dst_endpoint.hostname", "device.hostname")"#),
        "{sql}"
    );
    assert!(sql.ends_with(r#", "dst_endpoint.hostname")"#), "{sql}");
}
