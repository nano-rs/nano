// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4914 phase 4: bundled specs, feed input rules (config, credentials,
//! schedule floors, run limits), parser-lane resolution, checkpoint reset
//! planning and the HEC endpoint rules.

use chrono::{DateTime, Utc};
use nano_connector::first_party;
use nano_connector::point_forward::{self, PointForward};
use nano_connector::service::admin::{self, AdminError, NewFeed};
use nano_connector::service::hec::{check_host, credential_refusal, credential_refusal_in, hec_endpoint};
use nano_connector::service::reset::{checkpoint_kind, plan_reset, plan_reset_with_prior, ResetError};
use serde_json::{json, Map, Value};
use uuid::Uuid;

fn config(v: Value) -> Map<String, Value> {
    v.as_object().cloned().unwrap()
}

fn t(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
}

#[test]
fn every_bundled_spec_plans_and_needs_a_credential() {
    let mut slugs = Vec::new();
    for s in first_party::SPECS {
        let plan = first_party::plan(s.slug).unwrap_or_else(|e| panic!("{}: {e}", s.slug));
        assert_eq!(plan.connector, s.slug);
        assert!(!admin::credential_fields(&plan.spec).unwrap().is_empty(), "{}", s.slug);
        assert!(!plan.spec.auth.kind.ends_with("broker"), "{}: no hosted broker auth", s.slug);
        slugs.push(s.slug);
    }
    assert_eq!(slugs, ["okta_system_log", "google_workspace", "slack", "netskope", "okta_users", "entra_directory"]);
    assert!(matches!(first_party::plan("../../etc/passwd"), Err(AdminError::CatalogNotFound(_))));
}

#[test]
fn credential_fields_per_connector() {
    let fields = |slug: &str| -> Vec<String> {
        admin::credential_fields(&first_party::plan(slug).unwrap().spec).unwrap().into_iter().collect()
    };
    assert_eq!(fields("okta_system_log"), ["API_TOKEN"]);
    assert_eq!(fields("google_workspace"), ["CLIENT_EMAIL", "PRIVATE_KEY"]);
    assert_eq!(fields("slack"), ["USER_TOKEN"]);
    assert_eq!(fields("netskope"), ["API_TOKEN"]);
    // G22 identity directory feeds.
    assert_eq!(fields("okta_users"), ["API_TOKEN"]);
    assert_eq!(fields("entra_directory"), ["CLIENT_SECRET"]);
}

#[test]
fn lanes_are_literal_or_expanded_from_the_config_fanout() {
    let okta = first_party::plan("okta_system_log").unwrap();
    assert_eq!(admin::lanes(&okta, &config(json!({"OKTA_DOMAIN": "acme.okta.com"}))).unwrap().into_iter().collect::<Vec<_>>(), ["okta"]);

    let gws = first_party::plan("google_workspace").unwrap();
    assert_eq!(gws.source_type, "gws_{{item}}");
    let lanes = admin::lanes(&gws, &config(json!({"ADMIN_EMAIL": "a@x.com", "STREAMS": "login, admin ,drive"}))).unwrap();
    assert_eq!(lanes.into_iter().collect::<Vec<_>>(), ["gws_admin", "gws_drive", "gws_login"]);
    assert!(admin::lanes(&gws, &config(json!({"ADMIN_EMAIL": "a@x.com", "STREAMS": ""}))).is_err());
    assert!(admin::lanes(&gws, &config(json!({"ADMIN_EMAIL": "a@x.com", "STREAMS": "Login Events"}))).is_err());
}

fn feed(name: &str, cfg: Value) -> NewFeed {
    NewFeed { name: name.into(), config: config(cfg), credential_id: Some(Uuid::now_v7()), enabled: true, ..Default::default() }
}

#[test]
fn config_must_be_exactly_what_the_spec_reads() {
    let okta = first_party::plan("okta_system_log").unwrap();
    assert!(admin::check_inputs(&okta, &feed("Okta", json!({"OKTA_DOMAIN": "acme.okta.com"}))).is_ok());
    let missing = admin::check_inputs(&okta, &feed("Okta", json!({}))).unwrap_err();
    assert!(missing.to_string().contains("missing OKTA_DOMAIN"), "{missing}");
    let extra = admin::check_inputs(&okta, &feed("Okta", json!({"OKTA_DOMAIN": "a.okta.com", "API_TOKEN": "x"}))).unwrap_err();
    assert!(extra.to_string().contains("never reads"), "{extra}");
    assert!(admin::check_inputs(&okta, &feed(" Okta", json!({"OKTA_DOMAIN": "a.okta.com"}))).is_err(), "untrimmed name");
    let mut no_cred = feed("Okta", json!({"OKTA_DOMAIN": "a.okta.com"}));
    no_cred.credential_id = None;
    assert!(admin::check_inputs(&okta, &no_cred).unwrap_err().to_string().contains("credential"));
    let nested = admin::check_inputs(&okta, &feed("Okta", json!({"OKTA_DOMAIN": {"x": 1}}))).unwrap_err();
    assert!(nested.to_string().contains("string"), "{nested}");
}

#[test]
fn schedules_cannot_beat_the_vendor_floor_and_run_limits_fit_the_spec() {
    let okta = first_party::plan("okta_system_log").unwrap(); // spec: */2
    let with = |s: &str| NewFeed { schedule: Some(s.into()), ..feed("Okta", json!({"OKTA_DOMAIN": "a.okta.com"})) };
    assert!(admin::check_inputs(&okta, &with("*/2 * * * *")).is_ok());
    assert!(admin::check_inputs(&okta, &with("*/15 * * * *")).is_ok());
    assert!(admin::check_inputs(&okta, &with("* * * * *")).is_err(), "faster than the spec's */2");
    assert!(admin::check_inputs(&okta, &with("not cron")).is_err());

    let slack = first_party::plan("slack").unwrap(); // spec: hourly
    let slack_with = |s: &str| NewFeed { schedule: Some(s.into()), ..feed("Slack", json!({"TEAM_ID": "T1"})) };
    assert!(admin::check_inputs(&slack, &slack_with("0 */2 * * *")).is_ok());
    assert!(admin::check_inputs(&slack, &slack_with("*/5 * * * *")).is_err(), "Slack access logs are hourly aggregates");

    let mut long = feed("Okta", json!({"OKTA_DOMAIN": "a.okta.com"}));
    long.max_run_secs = Some(3600);
    assert!(admin::check_inputs(&okta, &long).is_err(), "okta's spec caps a run at 600 s");
    long.max_run_secs = Some(300);
    assert!(admin::check_inputs(&okta, &long).is_ok());
}

#[test]
fn vendor_secrets_take_only_the_fields_the_spec_reads() {
    let okta = first_party::plan("okta_system_log").unwrap();
    let s = admin::vendor_secrets(&okta.spec, &json!({"API_TOKEN": "tok", "external_id": "ignored"})).unwrap();
    assert_eq!(s.len(), 1);
    assert_eq!(s["API_TOKEN"].expose(), "tok");
    assert_eq!(format!("{:?}", s["API_TOKEN"]), "Secret(<redacted>)");
    let err = admin::vendor_secrets(&okta.spec, &json!({"TOKEN": "x"})).unwrap_err();
    assert!(err.contains("API_TOKEN") && !err.contains('x'), "{err}");
    assert!(admin::vendor_secrets(&okta.spec, &json!({"API_TOKEN": "  "})).is_err());
}

#[test]
fn reset_anchors_at_now_minus_overlap_and_refuses_non_window_streams() {
    let okta = first_party::get("okta_system_log").unwrap().yaml;
    let now = t("2026-10-12T12:00:00Z");
    let p = plan_reset(okta, "system_log", now).unwrap();
    assert_eq!(p.anchor, t("2026-10-12T11:55:00Z"));
    assert_eq!(
        p.checkpoint,
        json!({
            "window": {"resume": p.anchor.timestamp_millis()},
            "point_forward": {"activated_at": "2026-10-12T12:00:00Z", "initial_cursor": "2026-10-12T11:55:00Z", "overlap_secs": 300},
        })
    );
    let pf = PointForward::from_saved(&p.checkpoint, t("2026-10-12T13:00:00Z"));
    assert_eq!((pf.initial_cursor, pf.activating), (p.anchor, false));
    assert_eq!(point_forward::initial_cursor(now), p.anchor);
    assert_eq!(checkpoint_kind(Some(&p.checkpoint)), "window_resume");
    assert!(matches!(plan_reset(okta, "other", now), Err(ResetError::UnknownStream(ids)) if ids == "system_log"));
    let gws = first_party::get("google_workspace").unwrap().yaml;
    assert!(matches!(plan_reset(gws, "activities", now), Err(ResetError::Unsupported(_))), "fan-out has no single time");
    let netskope = first_party::get("netskope").unwrap().yaml;
    let ns = nano_connector::spec::ConnectorSpec::from_yaml(netskope).unwrap();
    assert!(matches!(plan_reset(netskope, &ns.streams[0].id, now), Err(ResetError::Unsupported(_))), "iterator stream");
}

/// NAN-4931: resetting an identity stream drops the delta cursor (the next
/// run is a full directory walk) but keeps the shrink-guard baseline.
#[test]
fn identity_stream_reset_forces_a_full_resync_and_keeps_the_shrink_baseline() {
    let now = t("2026-10-12T12:00:00Z");
    for slug in ["okta_users", "entra_directory"] {
        let yaml = first_party::get(slug).unwrap().yaml;
        let prior = json!({"state": {"delta_link": "opaque"}, "identity_last_full_rows": 4200});
        let p = plan_reset_with_prior(yaml, "users", now, Some(&prior)).unwrap();
        assert!(p.full_resync, "{slug}");
        assert_eq!(p.checkpoint, json!({"identity_last_full_rows": 4200}), "{slug}");
        assert!(p.checkpoint.get("state").is_none(), "{slug}: no delta cursor survives");
        let fresh = plan_reset(yaml, "users", now).unwrap();
        assert_eq!(fresh.checkpoint, json!({}), "{slug}");
    }
    let okta = first_party::get("okta_system_log").unwrap().yaml;
    assert!(!plan_reset(okta, "system_log", now).unwrap().full_resync);
}

#[test]
fn checkpoint_kind_names_the_shape_only() {
    assert_eq!(checkpoint_kind(None), "none");
    assert_eq!(checkpoint_kind(Some(&json!({"window": {"watermark": 1, "seen": {"secret-uid": 1}}}))), "window_watermark");
    assert_eq!(checkpoint_kind(Some(&json!({"items": {"login": {}}}))), "fanout");
    assert_eq!(checkpoint_kind(Some(&json!({"state": {"cursor": "tok"}}))), "state");
    assert_eq!(checkpoint_kind(Some(&json!({}))), "other");
}

#[test]
fn hec_endpoint_rules() {
    assert_eq!(hec_endpoint("http://vector:8088", true).unwrap().as_str(), "http://vector:8088/services/collector/event");
    assert!(hec_endpoint("http://vector:8088", false).is_err(), "http needs the explicit opt-in");
    assert!(hec_endpoint("http://127.0.0.1:8088", true).is_ok());
    assert!(hec_endpoint("http://vector.nano.svc.cluster.local:8088", true).is_ok());
    assert!(hec_endpoint("http://acme.example.com", true).is_err(), "public hosts never get http");
    assert!(hec_endpoint("http://93.184.215.14", true).is_err());
    assert!(hec_endpoint("https://u:p@vector", false).is_err());
    assert!(hec_endpoint("https://vector/other", false).is_err());
    let u = hec_endpoint("https://ingest.acme.example", false).unwrap();
    assert!(check_host(&u, Some(".acme.example")).is_ok());
    assert!(check_host(&u, Some("other.example")).is_err());
}

#[test]
fn ingest_auth_refusals_are_named_and_found_inside_engine_errors() {
    let revoked = credential_refusal(401, "-").unwrap();
    assert!(revoked.starts_with("credential_revoked: "));
    assert!(credential_refusal(403, "-").unwrap().starts_with("credential_rejected: "));
    for status in [400, 404, 429, 500, 503] {
        assert_eq!(credential_refusal(status, "-"), None, "{status}");
    }
    let wrapped = format!("ingest did not acknowledge: {revoked}");
    assert_eq!(credential_refusal_in(&wrapped), Some(revoked.as_str()));
}

#[test]
fn migration_293_matches_the_store() {
    let sql = include_str!("../../migrations/postgres/293_connector_feeds.sql");
    for column in ["credential_id UUID REFERENCES public.cloud_credentials(id) ON DELETE RESTRICT", "lease_generation", "spec_sha256", "source_type"] {
        assert!(sql.contains(column), "{column}");
    }
    assert!(!sql.contains("tenant_id"), "single-tenant schema");
    assert!(!sql.contains("REFERENCES public.tenants"), "no tenants table on clickhouse/dev");
}

#[test]
fn the_runner_uses_the_platform_credential_and_refuses_the_install_token() {
    use nano_connector::service::ingest::resolve_ingest_token;
    let env_of = |pairs: &'static [(&'static str, &'static str)]| {
        move |k: &str| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| v.to_string())
    };
    let no_file = |_: &str| -> Result<String, String> { Err("no file".into()) };
    let ok = resolve_ingest_token(&env_of(&[("NANO_PLATFORM_INGEST_TOKEN", "platform"), ("VECTOR_AUTH_TOKEN", "install")]), &no_file).unwrap();
    assert_eq!(ok.expose(), "platform");
    let err = resolve_ingest_token(&env_of(&[("CONNECTOR_HEC_TOKEN", "install"), ("VECTOR_AUTH_TOKEN", "install")]), &no_file).unwrap_err();
    assert!(err.contains("install token"), "{err}");
    assert!(resolve_ingest_token(&env_of(&[("VECTOR_AUTH_TOKEN", "install")]), &no_file).is_err(), "no fallback to the install token");
    let file = resolve_ingest_token(&env_of(&[("CONNECTOR_HEC_TOKEN_FILE", "/run/t")]), &|_| Ok("from-file\n".into())).unwrap();
    assert_eq!(file.expose(), "from-file");
}

#[test]
fn compose_wires_the_platform_credential_not_the_install_token() {
    for (name, yml) in [
        ("docker-compose.opensource.yml", include_str!("../../docker-compose.opensource.yml")),
        ("docker-compose.yml", include_str!("../../docker-compose.yml")),
    ] {
        let at = yml.find("connector-runner:").unwrap_or_else(|| panic!("{name}: runner service"));
        let block = &yml[at..at + yml[at..].find("deploy:").unwrap()];
        assert!(block.contains("NANO_PLATFORM_INGEST_TOKEN: ${NANO_PLATFORM_INGEST_TOKEN"), "{name}");
        assert!(!block.contains("VECTOR_AUTH_TOKEN"), "{name}: the runner must never get the install token");
        // NAN-4931: identity feeds write the ClickHouse user directory; without
        // these they fail with identity_directory_unconfigured.
        for var in ["CLICKHOUSE_URL:", "CLICKHOUSE_USER:", "CLICKHOUSE_PASSWORD:", "CLICKHOUSE_DATABASE:"] {
            assert!(block.contains(var), "{name}: runner needs {var}");
        }
        assert!(block.contains("      clickhouse:\n        condition: service_healthy"), "{name}: runner waits for ClickHouse");
    }
}

/// NAN-4931: a feed pinned to an older bundled spec can move to the current
/// one only when no operator input is needed.
#[test]
fn repin_needs_same_streams_credentials_and_a_fitting_config() {
    let yaml = first_party::get("entra_directory").unwrap().yaml;
    let plan = admin::plan_from_spec("entra_directory", yaml).unwrap();
    let wanted = admin::config_keys(yaml).unwrap();
    let optional = admin::optional_config_keys(yaml).unwrap();
    let cfg: Map<String, Value> = wanted.iter().filter(|k| !optional.contains(*k)).map(|k| (k.clone(), json!("x"))).collect();
    let feed = NewFeed { name: "entra".into(), config: cfg, credential_id: Some(Uuid::nil()), enabled: true, ..Default::default() };
    // An older bundle that differs only in a comment / mapping fix re-pins.
    let older = format!("# older build\n{yaml}");
    assert!(admin::repin_compatible(&older, &plan, &feed).is_ok());
    // A different stream set never re-pins (checkpoints would not carry over).
    let okta = first_party::get("okta_users").unwrap().yaml;
    let okta_plan = admin::plan_from_spec("okta_users", okta).unwrap();
    let other = admin::repin_compatible(yaml, &okta_plan, &feed).unwrap_err();
    assert!(other.contains("changed") || other.contains("settings"), "{other}");
    // A config the new spec would refuse keeps the old pin.
    let bad = NewFeed { config: Map::new(), ..feed.clone() };
    assert!(admin::repin_compatible(&older, &plan, &bad).unwrap_err().contains("settings"));
}
