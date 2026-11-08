// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4914 phase 1: Azure Event Hubs source configs, point-forward for queue
//! and subscription sources, and the generated-config contracts they rely on.

use super::super::azure_event_hubs::{self, AZURE_RECORDS_SPLIT_VRL};
use super::super::point_forward::{self, BACKLOG_CUTOFF_GRACE_MS};
use super::super::types::{SourceConfiguration, SourceConfigurationWithRules};
use super::*;
use chrono::{TimeZone, Utc};
use std::collections::BTreeMap;
use vrl::value::{Secrets, Value};

fn config(config_type: &str, conn: serde_json::Value) -> SourceConfigurationWithRules {
    let created = Utc.with_ymd_and_hms(2026, 11, 1, 12, 0, 0).unwrap();
    SourceConfigurationWithRules {
        config: SourceConfiguration {
            id: Uuid::new_v4(),
            name: "pull_test".to_string(),
            description: None,
            config_type: config_type.to_string(),
            connection_config: conn,
            credential_id: None,
            enabled: true,
            deployed: false,
            deployed_at: None,
            created_at: created,
            updated_at: created,
            default_source_type: Some("azure_activity".to_string()),
            events_24h: None,
            bytes_per_day_24h: None,
            last_event_at: None,
            last_deployment: None,
        },
        routing_rules: vec![],
    }
}

fn eh_conn() -> serde_json::Value {
    serde_json::json!({
        "namespace": "acme-logs",
        "event_hub_name": "insights-logs-signinlogs",
        "checkpoint_account": "acmecheckpoints",
        "checkpoint_container": "nano-checkpoints",
    })
}

fn eh_source(creds: Option<serde_json::Value>) -> toml::Table {
    azure_event_hubs::source_table(&eh_conn(), creds.as_ref()).expect("source table")
}

fn run_vrl(program: &str, event: Value) -> (Value, Value) {
    let compiled = vrl::compiler::compile(program, &vrl::stdlib::all())
        .unwrap_or_else(|d| panic!("VRL must compile: {d:?}\n{program}"))
        .program;
    let mut target = vrl::compiler::TargetValue {
        value: event,
        metadata: Value::Object(BTreeMap::new()),
        secrets: Secrets::default(),
    };
    let mut runtime = vrl::compiler::runtime::Runtime::default();
    let result = runtime
        .resolve(&mut target, &compiled, &vrl::compiler::TimeZone::Local)
        .expect("VRL must not fail at runtime");
    (result, target.value)
}

fn obj(pairs: &[(&str, Value)]) -> Value {
    Value::Object(
        pairs
            .iter()
            .map(|(k, v)| ((*k).into(), v.clone()))
            .collect(),
    )
}

// ---------------------------------------------------------------- Event Hubs

#[test]
fn event_hubs_sas_connection_string_needs_no_namespace_or_auth() {
    let creds = serde_json::json!({
        "connection_string": "Endpoint=sb://acme.servicebus.windows.net/;SharedAccessKeyName=k;SharedAccessKey=s",
        "checkpoint_connection_string": "DefaultEndpointsProtocol=https;AccountName=a;AccountKey=k",
    });
    let source = eh_source(Some(creds));
    assert_eq!(source["type"].as_str(), Some("azure_event_hubs"));
    assert!(source.get("connection_string").is_some());
    assert!(source.get("namespace").is_none());
    assert!(source.get("auth").is_none());
    assert_eq!(source["start_position"].as_str(), Some("latest"));
    assert_eq!(source["consumer_group"].as_str(), Some("$Default"));
    let store = source["checkpoint_store"].as_table().unwrap();
    assert_eq!(store["type"].as_str(), Some("azure_blob"));
    assert!(store.get("connection_string").is_some());
    assert!(store.get("auth").is_none(), "a key-bearing connection string must not sit next to auth");
    assert_eq!(store["container_name"].as_str(), Some("nano-checkpoints"));
    assert_eq!(source["acknowledgements"]["enabled"].as_bool(), Some(true));
    assert_eq!(source["decoding"]["codec"].as_str(), Some("bytes"));
}

#[test]
fn event_hubs_service_principal_authenticates_hub_and_checkpoint_store() {
    let creds = serde_json::json!({
        "azure_tenant_id": "t", "azure_client_id": "c", "azure_client_secret": "s",
    });
    let source = eh_source(Some(creds));
    assert_eq!(source["namespace"].as_str(), Some("acme-logs.servicebus.windows.net"));
    let auth = source["auth"].as_table().unwrap();
    assert_eq!(auth["azure_credential_kind"].as_str(), Some("client_secret_credential"));
    let store = source["checkpoint_store"].as_table().unwrap();
    assert_eq!(store["account_name"].as_str(), Some("acmecheckpoints"));
    assert_eq!(
        store["auth"]["azure_credential_kind"].as_str(),
        Some("client_secret_credential")
    );
}

#[test]
fn event_hubs_without_credential_uses_managed_identity() {
    let source = eh_source(None);
    assert_eq!(source["auth"]["azure_credential_kind"].as_str(), Some("managed_identity"));
    assert_eq!(
        source["checkpoint_store"]["auth"]["azure_credential_kind"].as_str(),
        Some("managed_identity")
    );
}

#[test]
fn event_hubs_partial_service_principal_is_not_a_credential() {
    let creds = serde_json::json!({ "azure_tenant_id": "t", "azure_client_id": "c" });
    let source = eh_source(Some(creds));
    assert_eq!(source["auth"]["azure_credential_kind"].as_str(), Some("managed_identity"));
}

#[test]
fn event_hubs_validation_refuses_backfill_and_missing_checkpoints() {
    let mut conn = eh_conn();
    conn["start_position"] = "earliest".into();
    assert!(azure_event_hubs::validate_conn(&conn).is_err());

    let mut conn = eh_conn();
    conn.as_object_mut().unwrap().remove("checkpoint_container");
    assert!(azure_event_hubs::validate_conn(&conn).is_err());

    let mut conn = eh_conn();
    conn["checkpoint_container"] = "Bad--Name".into();
    assert!(azure_event_hubs::validate_conn(&conn).is_err());

    let mut conn = eh_conn();
    conn["namespace"] = "not a host".into();
    assert!(azure_event_hubs::validate_conn(&conn).is_err());

    assert!(azure_event_hubs::validate_conn(&eh_conn()).is_ok());
}

#[test]
fn event_hubs_namespace_host_forms() {
    assert_eq!(
        azure_event_hubs::azure_namespace_host("sb://Acme-Logs.servicebus.windows.net/").as_deref(),
        Some("acme-logs.servicebus.windows.net")
    );
    assert_eq!(
        azure_event_hubs::azure_namespace_host("acme").as_deref(),
        Some("acme.servicebus.windows.net")
    );
    assert!(azure_event_hubs::azure_namespace_host("-bad").is_none());
    assert!(azure_event_hubs::azure_namespace_host("a b").is_none());
}

#[test]
fn event_hubs_connection_config_secrets_never_reach_a_snapshot() {
    let creds = serde_json::json!({
        "connection_string": "Endpoint=sb://acme.servicebus.windows.net/;SharedAccessKey=SUPERSECRET",
        "checkpoint_connection_string": "AccountName=acme;AccountKey=ALSOSECRET",
    });
    let rendered =
        SourceConfigService::wrap_source_table("pull_test_source", eh_source(Some(creds)));
    let snapshot = redact_config_snapshot(&rendered);
    assert!(!snapshot.contains("SUPERSECRET"), "{snapshot}");
    assert!(!snapshot.contains("ALSOSECRET"), "{snapshot}");

    let sp = serde_json::json!({
        "azure_tenant_id": "t", "azure_client_id": "c", "azure_client_secret": "SPSECRET",
    });
    let rendered = SourceConfigService::wrap_source_table("pull_test_source", eh_source(Some(sp)));
    assert!(!redact_config_snapshot(&rendered).contains("SPSECRET"));
}

#[test]
fn event_hubs_routing_stashes_source_type_and_splits_records_last() {
    let cfg = config("azure_event_hubs", eh_conn());
    let block = SourceConfigService::generate_routing_transform(
        &cfg,
        "pull_test_source",
        "pull_test_route",
        false,
    );
    SourceConfigService::validate_generated_config(&block).expect("routing VRL compiles");
    let stash = block.find("%source_type = .source_type").expect("stash");
    let split = block.find("one event per record").expect("records split");
    assert!(stash < split, "the split must run after routing");
}

#[test]
fn event_hubs_records_split_semantics() {
    let program = format!(".source_type = \"azure_activity\"\n{AZURE_RECORDS_SPLIT_VRL}");
    let batch = r#"{"records":[{"a":1},{"a":2},"plain"],"other":"dropped"}"#;
    let event = obj(&[
        ("message", Value::from(batch)),
        ("properties", obj(&[("x", Value::from("y"))])),
    ]);
    let (_, out) = run_vrl(&program, event);
    let Value::Array(events) = out else {
        panic!("a batch becomes an array of events, got {out:?}")
    };
    assert_eq!(events.len(), 3);
    for e in &events {
        assert!(e.as_object().unwrap().get("properties").is_none());
        assert_eq!(
            e.as_object().unwrap().get("source_type"),
            Some(&Value::from("azure_activity"))
        );
    }
    assert_eq!(
        events[2].as_object().unwrap().get("message"),
        Some(&Value::from("plain"))
    );

    // Not a batch: passes through as one event, untouched.
    let single = obj(&[("message", Value::from("not json"))]);
    let (_, out) = run_vrl(&program, single);
    assert!(out.is_object());
    assert_eq!(
        out.as_object().unwrap().get("message"),
        Some(&Value::from("not json"))
    );
}

#[test]
fn every_pull_route_stashes_source_type_but_system_routes_do_not() {
    for t in ["kafka", "aws_s3", "aws_sqs", "gcp_pubsub", "azure_event_hubs"] {
        let block = SourceConfigService::generate_routing_transform(
            &config(t, serde_json::json!({})),
            "src",
            "route",
            false,
        );
        assert!(block.contains("%source_type = .source_type"), "{t}");
    }
    let system = SourceConfigService::generate_routing_transform(
        &config("http", serde_json::json!({})),
        "src",
        "route",
        true,
    );
    assert!(!system.contains("%source_type"));
}

#[test]
fn event_hubs_property_match_coerces_to_string() {
    assert_eq!(
        SourceConfigService::routing_field_expression("azure_event_hubs", "properties.source_type"),
        "(to_string(.properties.source_type) ?? \"\")"
    );
    assert_eq!(
        SourceConfigService::routing_field_expression("azure_event_hubs", "message"),
        ".message"
    );
}

#[test]
fn event_hubs_is_a_pull_source_with_a_fetch_transport() {
    let t = SourceConfigType::from_str("azure_event_hubs").unwrap();
    assert!(t.is_pull_source());
    assert!(t.requires_credentials());
    assert_eq!(
        SourceConfigService::forwarded_via_for_pull_source("azure_event_hubs"),
        Some("azure_event_hubs")
    );
}

// ------------------------------------------------- Azure endpoint boundary

use super::super::azure_event_hubs::{azure_host_allowed, check_connection_string, AzureService};

#[test]
fn event_hubs_hosts_must_be_azure_or_admin_allowlisted() {
    let eh = AzureService::EventHubs;
    for ok in [
        "acme.servicebus.windows.net",
        "acme.servicebus.chinacloudapi.cn",
        "acme.servicebus.usgovcloudapi.net",
        "acme.privatelink.servicebus.windows.net",
        "ACME.SERVICEBUS.WINDOWS.NET.",
    ] {
        assert!(azure_host_allowed(ok, eh, None), "{ok}");
    }
    for bad in [
        "collector.attacker.example",
        "servicebus.windows.net.attacker.example",
        "acmeservicebus.windows.net",
        "servicebus.windows.net",
        "10.0.0.5",
        "127.0.0.1",
        "169.254.169.254",
        "[::1]",
        "vector",
        "localhost",
        "acme.blob.core.windows.net",
    ] {
        assert!(!azure_host_allowed(bad, eh, None), "{bad}");
    }
    // The admin allowlist (exact host or .suffix) is the only way out.
    assert!(azure_host_allowed("eh-emulator", eh, Some("eh-emulator")));
    assert!(azure_host_allowed("ns.azurestack.corp.example", eh, Some(" .azurestack.corp.example ,x")));
    assert!(!azure_host_allowed("10.0.0.5", eh, Some("eh-emulator")));
    assert!(azure_host_allowed("acme.blob.core.usgovcloudapi.net", AzureService::Blob, None));
    assert!(!azure_host_allowed("acme.servicebus.windows.net", AzureService::Blob, None));
}

#[test]
fn connection_string_endpoints_are_checked() {
    let eh = AzureService::EventHubs;
    let blob = AzureService::Blob;
    assert!(check_connection_string("Endpoint=sb://acme.servicebus.windows.net/;SharedAccessKeyName=k;SharedAccessKey=s", eh, None).is_ok());
    let err = check_connection_string("Endpoint=sb://collector.attacker.example/;SharedAccessKey=s", eh, None).unwrap_err();
    assert!(err.contains("collector.attacker.example") && !err.contains("SharedAccessKey=s"), "{err}");
    assert!(check_connection_string("Endpoint=sb://10.0.0.5/;SharedAccessKey=s", eh, None).is_err());
    assert!(check_connection_string("SharedAccessKey=s", eh, None).is_err(), "no Endpoint");
    assert!(check_connection_string("Endpoint=sb://localhost;SharedAccessKey=s;UseDevelopmentEmulator=true", eh, None).is_err());
    assert!(check_connection_string("Endpoint=sb://eh-emulator;SharedAccessKey=s;UseDevelopmentEmulator=true", eh, Some("eh-emulator")).is_ok());

    assert!(check_connection_string("DefaultEndpointsProtocol=https;AccountName=acme;AccountKey=k", blob, None).is_ok());
    assert!(check_connection_string("AccountName=acme;AccountKey=k;EndpointSuffix=core.chinacloudapi.cn", blob, None).is_ok());
    assert!(check_connection_string("AccountName=acme;AccountKey=k;EndpointSuffix=attacker.example", blob, None).is_err());
    assert!(check_connection_string("AccountName=acme;AccountKey=k;BlobEndpoint=http://10.0.0.5:10000/acme", blob, None).is_err());
    assert!(check_connection_string("AccountName=acme;AccountKey=k;BlobEndpoint=https://acme.blob.core.windows.net/", blob, None).is_ok());
    assert!(check_connection_string("AccountName=acme;AccountKey=k;QueueEndpoint=https://evil.example", blob, None).is_err());
    assert!(check_connection_string("UseDevelopmentStorage=true", blob, None).is_err());
    assert!(check_connection_string("BlobEndpoint=https://u:p@acme.blob.core.windows.net", blob, None).is_err());
}

#[test]
fn credential_and_render_refuse_non_azure_endpoints() {
    let attacker = serde_json::json!({"connection_string": "Endpoint=sb://collector.attacker.example/;SharedAccessKey=s"});
    assert!(nanosiem_core_validate("azure_event_hubs", &attacker).is_err());
    assert!(azure_event_hubs::source_table(&eh_conn(), Some(&attacker)).is_err(), "rendering refuses it too");
    let internal_blob = serde_json::json!({
        "connection_string": "Endpoint=sb://acme.servicebus.windows.net/;SharedAccessKey=s",
        "checkpoint_connection_string": "AccountName=a;AccountKey=k;BlobEndpoint=http://169.254.169.254/",
    });
    assert!(nanosiem_core_validate("azure_event_hubs", &internal_blob).is_err());
    assert!(azure_event_hubs::source_table(&eh_conn(), Some(&internal_blob)).is_err());
    let mut conn = eh_conn();
    conn["namespace"] = "collector.attacker.example".into();
    assert!(azure_event_hubs::validate_conn(&conn).is_err(), "write-time namespace check");
    let sp = serde_json::json!({"azure_tenant_id": "t", "azure_client_id": "c", "azure_client_secret": "s"});
    assert!(azure_event_hubs::source_table(&conn, Some(&sp)).is_err(), "render-time namespace check");
}

fn nanosiem_core_validate(provider: &str, creds: &serde_json::Value) -> Result<(), String> {
    crate::parsers::validate_credential_payload(provider, creds)
}

// ------------------------------------------------------------- point-forward

#[test]
fn point_forward_applies_to_queue_and_subscription_sources_only() {
    let created_ms = Utc
        .with_ymd_and_hms(2026, 11, 1, 12, 0, 0)
        .unwrap()
        .timestamp_millis();
    for t in ["aws_s3", "aws_sqs", "gcp_pubsub"] {
        assert_eq!(
            point_forward::cutoff_unix_ms(&config(t, serde_json::json!({}))),
            Some(created_ms - BACKLOG_CUTOFF_GRACE_MS),
            "{t}"
        );
    }
    for t in ["kafka", "azure_event_hubs", "splunk_hec", "http"] {
        assert_eq!(point_forward::cutoff_unix_ms(&config(t, serde_json::json!({}))), None, "{t}");
    }
    let opted_out = config("aws_s3", serde_json::json!({ "include_backlog": true }));
    assert_eq!(point_forward::cutoff_unix_ms(&opted_out), None);
}

#[test]
fn point_forward_include_backlog_must_be_boolean() {
    assert!(point_forward::validate_conn("aws_s3", &serde_json::json!({"include_backlog": "yes"})).is_err());
    assert!(point_forward::validate_conn("aws_s3", &serde_json::json!({"include_backlog": true})).is_ok());
    assert!(point_forward::validate_conn("aws_s3", &serde_json::json!({})).is_ok());
}

fn filter_condition(config_type: &str, cutoff: i64) -> String {
    let rendered = point_forward::render_filter("f", "src", config_type, cutoff);
    SourceConfigService::validate_generated_config(&rendered).expect("filter compiles");
    let parsed: toml::Value = toml::from_str(&rendered).unwrap();
    assert_eq!(parsed["transforms"]["f"]["type"].as_str(), Some("filter"));
    assert_eq!(parsed["transforms"]["f"]["inputs"][0].as_str(), Some("src"));
    parsed["transforms"]["f"]["condition"]
        .as_str()
        .unwrap()
        .to_string()
}

fn ts(ms: i64) -> Value {
    Value::Timestamp(Utc.timestamp_millis_opt(ms).unwrap())
}

#[test]
fn point_forward_filter_drops_backlog_keeps_new_and_undatable() {
    let cutoff = 1_793_000_000_000;
    for t in ["aws_sqs", "gcp_pubsub", "aws_s3"] {
        let cond = filter_condition(t, cutoff);
        let keep = |event: Value| run_vrl(&cond, event).0 == Value::Boolean(true);
        assert!(!keep(obj(&[("timestamp", ts(cutoff - 1))])), "{t}: backlog dropped");
        assert!(keep(obj(&[("timestamp", ts(cutoff))])), "{t}: at cutoff kept");
        assert!(keep(obj(&[("timestamp", ts(cutoff + 60_000))])), "{t}: new kept");
        assert!(keep(obj(&[("message", Value::from("x"))])), "{t}: undatable kept");
        assert!(
            keep(obj(&[("timestamp", Value::from("2020-01-01"))])),
            "{t}: a string timestamp is undatable, kept"
        );
    }
}

#[test]
fn point_forward_s3_prefers_notification_time_over_last_modified() {
    let cutoff = 1_793_000_000_000;
    let cond = filter_condition("aws_s3", cutoff);
    // A restored object: LastModified long ago, notification after creation.
    let restored = obj(&[
        ("timestamp", ts(cutoff - 86_400_000)),
        ("s3_event_time", ts(cutoff + 1_000)),
    ]);
    assert_eq!(run_vrl(&cond, restored).0, Value::Boolean(true));
    // An s3_event_time string is never trusted; .timestamp decides.
    let spoofed = obj(&[
        ("timestamp", ts(cutoff - 86_400_000)),
        ("s3_event_time", Value::from("2099-01-01T00:00:00Z")),
    ]);
    assert_eq!(run_vrl(&cond, spoofed).0, Value::Boolean(false));
}

/// Writes representative generated configs for a `vector validate` run in a
/// throwaway container (the in-process gate only compiles VRL; it does not
/// know the fork's component schemas). Run with
/// `NANO_PULL_SAMPLES_DIR=/some/dir cargo test ... -- --ignored dump_pull_samples`.
#[test]
#[ignore]
fn dump_pull_samples_for_vector_validate() {
    let dir = std::env::var("NANO_PULL_SAMPLES_DIR").expect("NANO_PULL_SAMPLES_DIR");
    let sas = serde_json::json!({
        "connection_string": "Endpoint=sb://acme.servicebus.windows.net/;SharedAccessKeyName=k;SharedAccessKey=s;EntityPath=hub",
        "checkpoint_connection_string": "DefaultEndpointsProtocol=https;AccountName=acme;AccountKey=a2V5;EndpointSuffix=core.windows.net",
    });
    let sp = serde_json::json!({
        "azure_tenant_id": "00000000-0000-0000-0000-000000000001",
        "azure_client_id": "00000000-0000-0000-0000-000000000002",
        "azure_client_secret": "s",
    });
    let cases: Vec<(&str, Option<serde_json::Value>)> =
        vec![("eh_sas", Some(sas)), ("eh_sp", Some(sp)), ("eh_mi", None)];
    for (name, creds) in cases {
        let cfg = config("azure_event_hubs", eh_conn());
        let source_name = format!("{name}_source");
        let mut out = SourceConfigService::wrap_source_table(
            &source_name,
            azure_event_hubs::source_table(&eh_conn(), creds.as_ref()).unwrap(),
        );
        out.push('\n');
        out.push_str(&SourceConfigService::generate_routing_transform(
            &cfg,
            &source_name,
            &format!("{name}_route"),
            false,
        ));
        std::fs::write(format!("{dir}/{name}.toml"), out).unwrap();
    }
    let queue_sources: Vec<(&str, String)> = vec![
        (
            "aws_sqs",
            SourceConfigService::generate_aws_sqs_source(
                "aws_sqs_source",
                &serde_json::json!({"queue_url": "https://sqs.us-east-1.amazonaws.com/123456789012/q", "region": "us-east-1"}),
                None,
            ),
        ),
        (
            "gcp_pubsub",
            SourceConfigService::generate_gcp_pubsub_source(
                "gcp_pubsub_source",
                &serde_json::json!({"project": "p", "subscription": "s"}),
                None,
            ),
        ),
        (
            "aws_s3",
            SourceConfigService::generate_aws_s3_source(
                "aws_s3_source",
                &serde_json::json!({"sqs_queue_url": "https://sqs.us-east-1.amazonaws.com/123456789012/q", "region": "us-east-1"}),
                None,
            ),
        ),
    ];
    let mut routes = vec!["eh_sas_route".to_string(), "eh_sp_route".into(), "eh_mi_route".into()];
    for (t, source_block) in queue_sources {
        let cfg = config(t, serde_json::json!({}));
        let filter = format!("{t}_pf");
        let mut out = source_block;
        out.push('\n');
        out.push_str(&point_forward::render_filter(
            &filter,
            &format!("{t}_source"),
            t,
            point_forward::cutoff_unix_ms(&cfg).unwrap(),
        ));
        out.push('\n');
        out.push_str(&SourceConfigService::generate_routing_transform(
            &cfg,
            &filter,
            &format!("{t}_route"),
            false,
        ));
        std::fs::write(format!("{dir}/{t}_point_forward.toml"), out).unwrap();
        routes.push(format!("{t}_route"));
    }
    let inputs = routes
        .iter()
        .map(|r| format!("\"{r}\""))
        .collect::<Vec<_>>()
        .join(", ");
    std::fs::write(
        format!("{dir}/zz_sink.toml"),
        format!("[sinks.validate_blackhole]\ntype = \"blackhole\"\ninputs = [{inputs}]\n"),
    )
    .unwrap();
}

// ------------------------------------------------ secret-only refresh guard

use super::normalize_for_secret_compare;

fn sqs_render(queue: &str, creds: &serde_json::Value) -> String {
    let cfg = config("aws_sqs", serde_json::json!({"queue_url": queue, "region": "us-east-1"}));
    let mut out = SourceConfigService::generate_aws_sqs_source("q_source", &cfg.config.connection_config, Some(creds));
    out.push_str(&SourceConfigService::generate_routing_transform(&cfg, "q_source", "q_route", false));
    redact_config_snapshot(&format!("# Generated at: {}\n{out}", chrono::Utc::now().to_rfc3339()))
}

#[test]
fn a_rotation_alone_compares_equal_to_the_deployed_snapshot() {
    let old = serde_json::json!({"access_key_id": "AKIAOLDOLDOLD", "secret_access_key": "old-secret"});
    let new = serde_json::json!({"access_key_id": "AKIANEWNEWNEW", "secret_access_key": "new-secret"});
    let q = "https://sqs.us-east-1.amazonaws.com/1/q";
    let deployed = sqs_render(q, &old);
    let now = sqs_render(q, &new);
    assert_ne!(deployed, now, "the key id is not redacted, so the raw renders differ");
    assert_eq!(
        normalize_for_secret_compare(&now, Some(&new)),
        normalize_for_secret_compare(&deployed, Some(&old)),
        "only credential material differs: the refresh may redeploy"
    );
}

#[test]
fn a_pending_edit_never_compares_equal() {
    let old = serde_json::json!({"access_key_id": "AKIAOLDOLDOLD", "secret_access_key": "old-secret"});
    let new = serde_json::json!({"access_key_id": "AKIANEWNEWNEW", "secret_access_key": "new-secret"});
    let deployed = sqs_render("https://sqs.us-east-1.amazonaws.com/1/q", &old);
    // Saved but not deployed: the queue moved to an attacker-chosen account.
    let edited = sqs_render("https://sqs.us-east-1.amazonaws.com/666/exfil", &new);
    assert_ne!(
        normalize_for_secret_compare(&edited, Some(&new)),
        normalize_for_secret_compare(&deployed, Some(&old)),
        "a pending edit must block the rotation-triggered redeploy"
    );
    // Without the previous payload (it could not be read) nothing matches,
    // which also fails closed (no redeploy).
    assert_ne!(
        normalize_for_secret_compare(&sqs_render("https://sqs.us-east-1.amazonaws.com/1/q", &new), Some(&new)),
        normalize_for_secret_compare(&deployed, None),
    );
}
