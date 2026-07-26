// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regression net for the credential read-leak class (NAN-2067 / NAN-2068).
//!
//! Both findings were proven the same way: a key downgraded to exactly
//! `source_configs:view` / `log_sources:view` issued a GET and read a live
//! secret out of the response body. These tests assert the property that
//! actually matters — **the plaintext never appears anywhere in the serialized
//! response bytes** — over every response shape those endpoints return,
//! including the `#[serde(flatten)]` wrappers that silently inherit the leak.
//!
//! They also pin the other half of the fix: a redacted read that is echoed
//! straight back into an update must leave the stored secret intact. Without
//! that, redaction converts a disclosure bug into the NAN-1358 data-loss bug
//! (a save from a stale UI wipes the credential and breaks ingestion).
//!
//! DB-free by construction: the redaction boundary is a pure transform over the
//! response models, so these run in CI without Postgres.

use nanosiem_core::config_secrets::{
    is_fully_redacted, merge_config_secrets, REDACTED_PLACEHOLDER,
};
use nanosiem_core::log_sources::{LogSource, LogSourceWithDraftStatus};
use nanosiem_core::source_configs::{SourceConfiguration, SourceConfigurationWithRules};
use serde_json::{json, Value};
use uuid::Uuid;

/// Every marker below is a distinct, greppable sentinel so a failure names the
/// exact field that leaked.
const KAFKA_PW: &str = "MARKER-kafka-sasl-password";
const AWS_SECRET: &str = "MARKER-aws-secret-access-key";
const AWS_SESSION: &str = "MARKER-aws-session-token";
const GCP_JSON: &str = "MARKER-gcp-service-account-json";
const TLS_KEY: &str = "MARKER-tls-private-key";

fn all_markers() -> [&'static str; 5] {
    [KAFKA_PW, AWS_SECRET, AWS_SESSION, GCP_JSON, TLS_KEY]
}

/// A connection_config carrying every secret shape a source-config driver can
/// store, plus non-secret siblings that must survive redaction.
fn kitchen_sink_connection_config() -> Value {
    json!({
        "bootstrap_servers": "broker.internal:9092",
        "sasl_username": "svc-ingest",
        "sasl_password": KAFKA_PW,
        "access_key_id": "AKIAEXAMPLE",
        "secret_access_key": AWS_SECRET,
        "session_token": AWS_SESSION,
        "credentials_json": GCP_JSON,
        "region": "us-east-1",
        "tls": {
            "key_content": TLS_KEY,
            "crt_content": "-----BEGIN CERTIFICATE-----\nPUBLIC-CLIENT-CERT",
            "ca_content": "-----BEGIN CERTIFICATE-----\nPUBLIC-CA-CERT",
        },
    })
}

/// A log-source source_config with the system-injected `_credentials` subtree
/// (the NAN-2068 shape) plus a TLS private key.
fn kitchen_sink_source_config() -> Value {
    json!({
        "region": "us-west-2",
        "bucket": "acme-logs",
        "_credentials": {
            "sasl_password": KAFKA_PW,
            "secret_access_key": AWS_SECRET,
            "session_token": AWS_SESSION,
            "credentials_json": GCP_JSON,
            "access_key_id": "AKIAEXAMPLE",
        },
        "tls": { "key_content": TLS_KEY },
    })
}

/// Built through serde rather than a struct literal so that adding a field to
/// the response model does not break this file — a compile error here would be
/// a maintenance tax, whereas a silently-defaulted `connection_config` would
/// make the assertions vacuous, which the guard below catches.
fn source_config_fixture() -> SourceConfiguration {
    let mut sc: SourceConfiguration = serde_json::from_value(json!({
        "id": Uuid::new_v4(),
        "name": "kafka-prod",
        "description": "prod ingest",
        "config_type": "kafka",
        "connection_config": kitchen_sink_connection_config(),
        "enabled": true,
        "deployed": true,
        "deployed_at": null,
        "created_at": "2026-07-24T00:00:00Z",
        "updated_at": "2026-07-24T00:00:00Z",
    }))
    .expect("SourceConfiguration fixture must match the model");
    assert!(
        sc.connection_config.get("sasl_password").is_some(),
        "fixture did not carry a secret — the test would be vacuous"
    );
    sc.connection_config = kitchen_sink_connection_config();
    sc
}

/// Assert no marker survives into the serialized bytes, naming the offender.
fn assert_no_secret_in_serialized<T: serde::Serialize>(value: &T, context: &str) {
    let bytes = serde_json::to_string(value).expect("serialize");
    for marker in all_markers() {
        assert!(
            !bytes.contains(marker),
            "{context}: secret `{marker}` leaked into the serialized response:\n{bytes}"
        );
    }
}

// ---------------------------------------------------------------------------
// NAN-2067 — source_configs:view
// ---------------------------------------------------------------------------

#[test]
fn source_configuration_response_carries_no_plaintext_secret() {
    let redacted = source_config_fixture().redacted();
    assert_no_secret_in_serialized(&redacted, "GET /api/source-configurations/{id}");

    // Masked, not dropped — a viewer still learns WHICH secrets are configured.
    let c = &redacted.connection_config;
    assert_eq!(c["sasl_password"], REDACTED_PLACEHOLDER);
    assert_eq!(c["secret_access_key"], REDACTED_PLACEHOLDER);
    assert_eq!(c["session_token"], REDACTED_PLACEHOLDER);
    assert_eq!(c["credentials_json"], REDACTED_PLACEHOLDER);
    assert_eq!(c["tls"]["key_content"], REDACTED_PLACEHOLDER);

    // Non-secret connection metadata stays readable — redaction must not
    // blind an operator to the configuration itself.
    assert_eq!(c["bootstrap_servers"], "broker.internal:9092");
    assert_eq!(c["sasl_username"], "svc-ingest");
    assert_eq!(c["access_key_id"], "AKIAEXAMPLE");
    assert_eq!(c["region"], "us-east-1");
    assert!(c["tls"]["crt_content"]
        .as_str()
        .unwrap()
        .contains("PUBLIC-CLIENT-CERT"));
    assert!(c["tls"]["ca_content"]
        .as_str()
        .unwrap()
        .contains("PUBLIC-CA-CERT"));
}

#[test]
fn source_configuration_with_rules_flatten_wrapper_does_not_reopen_the_leak() {
    // `SourceConfigurationWithRules` #[serde(flatten)]s the config, so it
    // inherits the leak unless the wrapper redacts too. This is the
    // `GET /{id}/full` shape.
    let wrapped = SourceConfigurationWithRules {
        config: source_config_fixture(),
        routing_rules: vec![],
    }
    .redacted();

    assert_no_secret_in_serialized(&wrapped, "GET /api/source-configurations/{id}/full");
    assert!(is_fully_redacted(&wrapped.config.connection_config));
}

#[test]
fn source_config_list_response_carries_no_plaintext_secret() {
    // The list endpoint leaked the same marker as detail in the finding's repro.
    let listed: Vec<SourceConfiguration> = vec![source_config_fixture(), source_config_fixture()]
        .into_iter()
        .map(SourceConfiguration::redacted)
        .collect();

    assert_no_secret_in_serialized(&listed, "GET /api/source-configurations");
}

// ---------------------------------------------------------------------------
// NAN-2068 — log_sources:view
// ---------------------------------------------------------------------------

fn log_source_fixture() -> LogSource {
    let mut ls: LogSource = serde_json::from_value(json!({
        "id": Uuid::new_v4(),
        "name": "s3-cloudtrail",
        "description": null,
        "source_type": "aws_s3",
        "source_config": kitchen_sink_source_config(),
        "parser_vrl": ".foo = 1",
        "output_fields": null,
        "category": null,
        "vendor": null,
        "product": null,
        "icon": null,
        "color": null,
        "match_field": null,
        "match_pattern": null,
        "match_values": null,
        "validated": true,
        "validation_error": null,
        "deployed": true,
        "deployed_at": null,
        "enabled": true,
        "stale_alert_enabled": false,
        "stale_threshold_minutes": 60,
        "sampling_ratio": null,
        "sampling_exclude_condition": null,
        "source_parser_repository_id": null,
        "source_parser_path": null,
        "created_at": "2026-07-24T00:00:00Z",
        "updated_at": "2026-07-24T00:00:00Z",
    }))
    .expect("LogSource fixture must match the model — update this fixture if fields changed");
    // Guard against a silently-defaulted fixture: if `source_config` stopped
    // deserializing, every assertion below would pass vacuously.
    assert!(
        ls.source_config.get("_credentials").is_some(),
        "fixture did not carry _credentials — the test would be vacuous"
    );
    ls.source_config = kitchen_sink_source_config();
    ls
}

#[test]
fn log_source_response_carries_no_plaintext_credentials() {
    let redacted = log_source_fixture().redacted();
    assert_no_secret_in_serialized(&redacted, "GET /api/log-sources/{id}");

    let creds = &redacted.source_config["_credentials"];
    // The whole `_credentials` subtree is credential material, so even
    // `access_key_id` — readable at top level — is masked inside it.
    assert_eq!(creds["sasl_password"], REDACTED_PLACEHOLDER);
    assert_eq!(creds["credentials_json"], REDACTED_PLACEHOLDER);
    assert_eq!(creds["access_key_id"], REDACTED_PLACEHOLDER);
    assert_eq!(redacted.source_config["tls"]["key_content"], REDACTED_PLACEHOLDER);

    // Non-secret ingest configuration survives.
    assert_eq!(redacted.source_config["region"], "us-west-2");
    assert_eq!(redacted.source_config["bucket"], "acme-logs");
}

#[test]
fn log_source_draft_status_flatten_wrapper_does_not_reopen_the_leak() {
    // `GET /{id}/draft-status` flattens LogSource — the finding's third path.
    let wrapped = LogSourceWithDraftStatus {
        log_source: log_source_fixture(),
        has_draft_changes: true,
        active_version_number: Some(3),
        active_parser_vrl: Some(".foo = 1".to_string()),
    }
    .redacted();

    assert_no_secret_in_serialized(&wrapped, "GET /api/log-sources/{id}/draft-status");
    assert!(is_fully_redacted(&wrapped.log_source.source_config));
}

// ---------------------------------------------------------------------------
// The other half: a redacted read echoed back must not wipe the stored secret
// ---------------------------------------------------------------------------

#[test]
fn ui_read_modify_write_round_trip_preserves_every_stored_secret() {
    // Simulates SourceConfigurationDetail.tsx / LogSourceDetail.tsx exactly:
    // hydrate form state from the (now redacted) GET, change one visible
    // field, PUT the whole object back.
    for stored in [kitchen_sink_connection_config(), kitchen_sink_source_config()] {
        let mut from_the_wire = stored.clone();
        nanosiem_core::config_secrets::redact_config_secrets(&mut from_the_wire);

        // User edits a non-secret field in the browser.
        from_the_wire["region"] = json!("eu-central-1");

        let persisted = merge_config_secrets(from_the_wire, Some(&stored));

        // Every secret survived untouched...
        let bytes = serde_json::to_string(&persisted).unwrap();
        for marker in all_markers() {
            if serde_json::to_string(&stored).unwrap().contains(marker) {
                assert!(
                    bytes.contains(marker),
                    "round-trip WIPED stored secret `{marker}` — this is the NAN-1358 \
                     data-loss failure mode:\n{bytes}"
                );
            }
        }
        // ...and the intended edit landed.
        assert_eq!(persisted["region"], "eu-central-1");
        // ...and no placeholder was persisted as if it were a real secret.
        assert!(
            !bytes.contains(REDACTED_PLACEHOLDER),
            "placeholder persisted as a secret value:\n{bytes}"
        );
    }
}

#[test]
fn editor_can_rotate_a_secret_without_ever_reading_the_old_one() {
    // The finding requires this explicitly: an edit caller updates a secret
    // without first being shown the stored plaintext. The realistic request
    // echoes the masked siblings back (that is what the UI sends) and types a
    // real value into the one field being rotated.
    let stored = kitchen_sink_connection_config();
    let mut incoming = stored.clone();
    nanosiem_core::config_secrets::redact_config_secrets(&mut incoming);
    incoming["sasl_password"] = json!("rotated-pw");

    let persisted = merge_config_secrets(incoming, Some(&stored));

    assert_eq!(persisted["sasl_password"], "rotated-pw", "rotation landed");
    // Echoed-back siblings keep their stored values.
    assert_eq!(persisted["secret_access_key"], AWS_SECRET);
    assert_eq!(persisted["tls"]["key_content"], TLS_KEY);
}

#[test]
fn omitting_a_secret_clears_it_rather_than_silently_retaining_it() {
    // Clear-by-omission is a live client gesture:
    // `TlsConfigSection.handleClear` sets `key_content` to `undefined`, and
    // `SourceConfigurationDetail` sends `{}` to purge legacy HEC
    // `valid_tokens`. Preserve-on-omit would silently defeat both — the TLS
    // key would survive a "Clear" the operator believes succeeded.
    let stored = kitchen_sink_connection_config();
    let mut incoming = stored.clone();
    nanosiem_core::config_secrets::redact_config_secrets(&mut incoming);
    incoming
        .as_object_mut()
        .unwrap()
        .get_mut("tls")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .remove("key_content");

    let persisted = merge_config_secrets(incoming, Some(&stored));

    assert!(
        persisted["tls"].get("key_content").is_none(),
        "Clear gesture was silently ignored — the private key survived"
    );
    // Unrelated secrets that WERE echoed back are untouched.
    assert_eq!(persisted["sasl_password"], KAFKA_PW);
}

#[test]
fn historical_deployment_snapshots_are_scrubbed_at_the_read_boundary() {
    // Redacting only on write would leave rows persisted BEFORE the fix
    // exposed: an upgraded tenant whose deploy failed under the old code still
    // has raw generated TOML in `config_snapshot`, and the deployment-history
    // endpoints serve it under `*:view`. Both services now scrub on read, so
    // the property to pin is that the scrub is idempotent (already-redacted
    // rows survive unchanged) and total (a raw historical row is cleaned).
    let historical_raw = format!(
        "[sources.kafka_prod.sasl]\n\
         enabled = true\n\
         username = \"svc-ingest\"\n\
         password = \"{KAFKA_PW}\"\n\
         \n\
         [sources.s3_prod.auth]\n\
         access_key_id = \"AKIAEXAMPLE\"\n\
         secret_access_key = \"{AWS_SECRET}\"\n\
         session_token = \"{AWS_SESSION}\"\n"
    );

    let scrubbed = nanosiem_core::parsers::redact_config_snapshot(&historical_raw);

    for marker in [KAFKA_PW, AWS_SECRET, AWS_SESSION] {
        assert!(
            !scrubbed.contains(marker),
            "historical snapshot still leaks `{marker}`:\n{scrubbed}"
        );
    }
    // Non-secret context stays useful for forensics — that is the whole point
    // of keeping the snapshot at all.
    assert!(scrubbed.contains("username = \"svc-ingest\""));
    assert!(scrubbed.contains("access_key_id = \"AKIAEXAMPLE\""));

    // Idempotent: re-scrubbing a row written by the new code is a no-op.
    assert_eq!(
        nanosiem_core::parsers::redact_config_snapshot(&scrubbed),
        scrubbed
    );
}

// ---------------------------------------------------------------------------
// NAN-2069 — the marketplace catalog holds a DUPLICATE of the same secret
// ---------------------------------------------------------------------------

#[test]
fn marketplace_catalog_entry_response_carries_no_plaintext_credential() {
    // Publishing a custom enrichment copies its `config` — including a
    // cleartext `auth_config` — verbatim into `marketplace_catalog`, which is
    // readable through a DIFFERENT route under the same `enrichments:view`
    // gate. `GET /api/marketplace/catalog` has no per-entry filter, so one
    // call returned every published enrichment's credentials at once.
    let entry: nanosiem_core::marketplace::MarketplaceCatalogEntry =
        serde_json::from_value(json!({
            "id": Uuid::now_v7(),
            "slug": "threat-intel",
            "name": "Threat Intel",
            "description": null,
            "category": "security",
            "tags": [],
            "icon": null,
            "author": null,
            "source_type": "custom",
            "repository_id": null,
            "repository_file_path": null,
            "manifest_version": 1,
            "execution_backend": "deno",
            "custom_enrichment_id": null,
            "native_source_id": null,
            "identity_provider_id": null,
            "installed": true,
            "installed_at": null,
            "installed_version": null,
            "requires_credential": "none",
            "credential_fields": {},
            "credentials_encrypted": null,
            "credentials_nonce": null,
            "code": "const PROPRIETARY_MARKER = true;",
            "allowed_domains": [],
            "config": {
                "auth_config": {
                    "auth_type": "bearer",
                    "token": KAFKA_PW,
                    "client_id": "public-client",
                }
            },
            "enabled": true,
            "last_sync_at": null,
            "last_sync_status": null,
            "last_error": null,
            "record_count": 0,
            "is_syncing": false,
            "changelog": null,
            "created_at": "2026-07-24T00:00:00Z",
            "updated_at": "2026-07-24T00:00:00Z",
        }))
        .expect("MarketplaceCatalogEntry fixture must match the model");

    assert_eq!(
        entry.config.0["auth_config"]["token"], KAFKA_PW,
        "fixture did not carry a secret — the test would be vacuous"
    );

    let visible = entry.clone().redacted_with_code_access(true);
    assert_eq!(
        visible.code.as_deref(),
        Some("const PROPRIETARY_MARKER = true;")
    );

    let redacted = entry.redacted();
    let bytes = serde_json::to_string(&redacted).expect("serialize");

    assert!(
        !bytes.contains(KAFKA_PW),
        "marketplace catalog leaked the duplicated credential:\n{bytes}"
    );
    assert_eq!(
        redacted.config.0["auth_config"]["token"],
        REDACTED_PLACEHOLDER
    );
    assert_eq!(redacted.code, None);
    assert!(
        !bytes.contains("PROPRIETARY_MARKER"),
        "fail-closed marketplace response leaked executable source:\n{bytes}"
    );
    // Non-secret metadata survives.
    assert_eq!(redacted.config.0["auth_config"]["client_id"], "public-client");
}

#[test]
fn client_cannot_inject_its_own_credentials_subtree() {
    // NAN-2068: `_credentials` is system-injected at deploy time from the
    // encrypted store. A client that POSTs one must not have it persisted,
    // or it becomes a way to smuggle attacker-chosen secrets into generated
    // Vector config.
    let hijack = json!({
        "region": "us-west-2",
        "_credentials": { "sasl_password": "attacker-controlled" },
    });

    // On create there is nothing stored — the subtree is dropped entirely.
    let created = merge_config_secrets(hijack.clone(), None);
    assert!(
        created.get("_credentials").is_none(),
        "client-authored _credentials was persisted on create"
    );

    // On update the stored subtree wins over the client's.
    let stored = kitchen_sink_source_config();
    let updated = merge_config_secrets(hijack, Some(&stored));
    assert_eq!(updated["_credentials"]["sasl_password"], KAFKA_PW);
}
