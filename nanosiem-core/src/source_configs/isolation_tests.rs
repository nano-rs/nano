// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4936: source isolation. The preflight must mirror what the pinned
//! Vector fork rejects at component build, and the responder client must turn
//! the Vector container's answer into a verdict without ever reading a missing
//! answer as a pass.

use super::*;
use serde_json::json;

fn service_account() -> serde_json::Value {
    json!({
        "type": "service_account",
        "project_id": "p",
        "private_key_id": "k",
        "private_key": "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n",
        "client_email": "sa@p.iam.gserviceaccount.com",
        "client_id": "1",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/sa"
    })
}

fn gcp_creds(v: serde_json::Value) -> serde_json::Value {
    json!({ "credentials_json": v.to_string() })
}

/// NAN-4935 made the pinned fork accept ADC shapes; the preflight delegates to
/// the same classifier, so a complete authorized_user file passes here and is
/// judged by the real build (layer 2) instead.
#[test]
fn gcp_preflight_follows_the_nan4935_classifier() {
    preflight("gcp_pubsub", Some(&gcp_creds(service_account()))).unwrap();
    let adc = json!({
        "type": "authorized_user",
        "client_id": "e2e.apps.googleusercontent.com",
        "client_secret": "e2e-not-a-secret",
        "refresh_token": "e2e-not-a-token",
    });
    assert_eq!(
        preflight("gcp_pubsub", Some(&gcp_creds(adc.clone()))).is_ok(),
        crate::parsers::gcp_credentials::validate_gcp_pubsub_payload(&gcp_creds(adc)).is_ok()
    );

    let mut sa = service_account();
    sa.as_object_mut().unwrap().remove("client_email");
    let reason = preflight("gcp_pubsub", Some(&gcp_creds(sa))).unwrap_err();
    assert!(reason.starts_with("Invalid GCP credentials"), "{reason}");

    let bad = json!({ "credentials_json": "{not json" });
    assert!(preflight("gcp_pubsub", Some(&bad)).is_err());
    // A credential that yields no file fails closed (never ambient identity).
    assert!(preflight("gcp_pubsub", Some(&json!({ "credentials_json": "" }))).is_err());
    assert!(preflight("gcp_pubsub", Some(&json!({}))).is_err());
}

/// No credential attached means the metadata server; only the real build can
/// judge that, so the preflight must not refuse it.
#[test]
fn absent_gcp_credential_is_left_to_the_real_build() {
    preflight("gcp_pubsub", None).unwrap();
}

#[test]
fn kafka_ca_must_be_pem_when_present() {
    preflight("kafka", Some(&json!({ "tls_ca_cert": "" }))).unwrap();
    preflight(
        "kafka",
        Some(&json!({ "tls_ca_cert": "-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----" })),
    )
    .unwrap();
    assert!(preflight("kafka", Some(&json!({ "tls_ca_cert": "garbage" }))).is_err());
}

#[test]
fn other_types_have_no_structural_preflight() {
    preflight("aws_s3", Some(&json!({ "access_key_id": "x" }))).unwrap();
    preflight("aws_sqs", None).unwrap();
}

#[test]
fn grading_uses_the_exit_code_and_keeps_vectors_reason() {
    assert_eq!(grade("0", "Validated\n"), IsolationOutcome::Passed);
    let output = "\u{1b}[31mx\u{1b}[0m Source \"bad_source\": Invalid GCP credentials: missing field `project_id` at line 1 column 147\n\n~~~~~~~~\n";
    match grade("78", output) {
        IsolationOutcome::Failed(reason) => {
            assert!(reason.contains("Invalid GCP credentials: missing field `project_id`"), "{reason}");
            assert!(!reason.contains('\u{1b}'), "ANSI must be stripped: {reason:?}");
            assert!(!reason.contains("~~~"), "{reason}");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        grade("124", ""),
        IsolationOutcome::Failed("vector validate timed out building the source".to_string())
    );
}

#[test]
fn the_isolation_config_feeds_the_route_into_a_stub_sink() {
    let files = isolation_files("[sources.a_source]\ntype = \"demo_logs\"\n", "a_route");
    assert_eq!(files.len(), 2);
    let sink: toml::Value = toml::from_str(&files[1].1).unwrap();
    assert_eq!(sink["sinks"][ISOLATION_SINK]["type"].as_str(), Some("blackhole"));
    assert_eq!(sink["sinks"][ISOLATION_SINK]["inputs"][0].as_str(), Some("a_route"));
}

#[tokio::test]
async fn no_heartbeat_means_no_responder() {
    let dir = tempfile::tempdir().unwrap();
    let runner = IsolationRunner::new(dir.path().to_path_buf(), "/v".to_string());
    assert!(!runner.available().await);
    tokio::fs::write(dir.path().join(".responder"), b"1").await.unwrap();
    assert!(runner.available().await);
}

/// Stand-in for the shell loop in the Vector container: answer each request
/// with a fixed exit code and output.
async fn fake_responder(root: std::path::PathBuf, code: &'static str, output: &'static str) {
    loop {
        if let Ok(mut entries) = tokio::fs::read_dir(&root).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                let dir = entry.path();
                if dir.join("request").exists() && !dir.join("result").exists() {
                    assert!(dir.join("config/source.toml").exists());
                    tokio::fs::write(dir.join("output"), output).await.unwrap();
                    tokio::fs::write(dir.join("result"), format!("{code}\n")).await.unwrap();
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn the_responders_verdict_is_returned_and_the_request_cleaned_up() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    tokio::fs::create_dir_all(&root).await.unwrap();
    let responder = tokio::spawn(fake_responder(root.clone(), "78", "x Source \"s\": boom\n"));

    let runner = IsolationRunner::new(dir.path().to_path_buf(), "/v".to_string());
    let outcome = runner
        .validate(&isolation_files("[sources.s]\ntype = \"demo_logs\"\n", "s_route"))
        .await
        .unwrap();
    responder.abort();
    assert_eq!(outcome, IsolationOutcome::Failed("x Source \"s\": boom".to_string()));
    let leftovers: Vec<_> = std::fs::read_dir(&root).unwrap().flatten().collect();
    assert!(leftovers.is_empty(), "request dir must be removed: {leftovers:?}");
}

/// A responder that heartbeated and then stalled is no evidence: TimedOut,
/// never Passed.
#[tokio::test]
async fn silence_is_a_timeout_not_a_pass() {
    let dir = tempfile::tempdir().unwrap();
    let mut runner = IsolationRunner::new(dir.path().to_path_buf(), "/v".to_string());
    runner.timeout = Duration::from_millis(300);
    let outcome = runner
        .validate(&isolation_files("[sources.s]\ntype = \"demo_logs\"\n", "s_route"))
        .await
        .unwrap();
    assert_eq!(outcome, IsolationOutcome::TimedOut);
}

#[tokio::test]
async fn file_names_cannot_escape_the_request_directory() {
    let dir = tempfile::tempdir().unwrap();
    let runner = IsolationRunner::new(dir.path().to_path_buf(), "/v".to_string());
    let err = runner
        .validate(&[("../evil.toml".to_string(), String::new())])
        .await
        .unwrap_err();
    assert!(err.to_string().contains("refusing"), "{err}");
}

/// Runs `config/vector/.nano/vector-entrypoint.sh` exactly as shipped, in the
/// pinned Vector image (`NANOSIEM_TEST_VECTOR_IMAGE`), with a throwaway
/// validation volume and dynamic dir, and Vector running a tiny config.
/// `SECRET` stands in for the container's real secrets.
struct EntrypointContainer {
    name: String,
    validation: tempfile::TempDir,
    dynamic: tempfile::TempDir,
}

const FAKE_SECRET: &str = "nan4936-not-for-tenants";

impl EntrypointContainer {
    /// `prepare` runs on the dynamic dir before the container starts (the cold
    /// start guard runs at startup).
    fn start(prepare: impl FnOnce(&std::path::Path)) -> Self {
        let image = std::env::var("NANOSIEM_TEST_VECTOR_IMAGE")
            .expect("NANOSIEM_TEST_VECTOR_IMAGE must name the pinned Vector image");
        let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let validation = tempfile::tempdir().unwrap();
        let dynamic = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dynamic.path().join("sources/configs")).unwrap();
        std::fs::create_dir_all(dynamic.path().join("sources/parsers")).unwrap();
        // The live config the guard protects: logs flow internal_logs -> the
        // source's route -> a sink, the way nano's router reads `<name>_route`.
        std::fs::write(
            dynamic.path().join("sources/parsers/base.toml"),
            "[sources.internal_logs]\ntype = \"internal_logs\"\n\n\
             [sinks.out]\ntype = \"blackhole\"\ninputs = [\"internal_logs\"]\nprint_interval_secs = 0\n",
        )
        .unwrap();
        prepare(dynamic.path());
        let name = format!("nan4936-entrypoint-{}", uuid::Uuid::new_v4().simple());
        let status = std::process::Command::new("docker")
            .args(["run", "-d", "--rm", "--name", &name, "-e"])
            .arg(format!("SECRET={FAKE_SECRET}"))
            .args(["--entrypoint", "/bin/sh", "-v"])
            .arg(format!("{}:/etc/vector/.nano:ro", repo.join("config/vector/.nano").display()))
            .arg("-v")
            .arg(format!("{}:/etc/vector/dynamic", dynamic.path().display()))
            .arg("-v")
            .arg(format!("{}:/var/lib/nano-validation", validation.path().display()))
            .args([
                image.as_str(),
                "/etc/vector/.nano/vector-entrypoint.sh",
                "--dangerously-allow-env-var-interpolation",
                "--config-dir",
                "/etc/vector/dynamic/sources/parsers",
                "--config-dir",
                "/etc/vector/dynamic/sources/configs",
            ])
            .status()
            .unwrap();
        assert!(status.success());
        Self { name, validation, dynamic }
    }

    fn runner(&self) -> IsolationRunner {
        IsolationRunner::new(self.validation.path().to_path_buf(), "/var/lib/nano-validation".to_string())
    }

    async fn wait_heartbeat(&self) {
        let runner = self.runner();
        for _ in 0..80 {
            if runner.available().await {
                return;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        panic!("responder never heartbeated; logs:\n{}", self.logs());
    }

    fn logs(&self) -> String {
        let out = std::process::Command::new("docker").args(["logs", &self.name]).output().unwrap();
        format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
    }

    fn running(&self) -> bool {
        let out = std::process::Command::new("docker")
            .args(["inspect", "-f", "{{.State.Running}}", &self.name])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).trim() == "true"
    }
}

impl Drop for EntrypointContainer {
    fn drop(&mut self) {
        let _ = std::process::Command::new("docker").args(["rm", "-f", &self.name]).status();
    }
}

fn bad_gcp_source(creds_path: &str) -> String {
    format!(
        "[sources.bad_source]\ntype = \"gcp_pubsub\"\nproject = \"p\"\nsubscription = \"s\"\n\
         credentials_path = \"{creds_path}\"\n\n\
         [transforms.bad_route]\ntype = \"remap\"\ninputs = [\"bad_source\"]\nsource = \".source_type = \\\"x\\\"\"\n"
    )
}

const REFUSED_SA: &str = r#"{"type":"service_account","project_id":"p","private_key_id":"k","private_key":"-----BEGIN PRIVATE KEY-----\nTUlJQg==\n-----END PRIVATE KEY-----\n","client_email":"x@p.iam.gserviceaccount.com","client_id":"1","auth_uri":"https://a","token_uri":"https://oauth2.googleapis.com/token","auth_provider_x509_cert_url":"https://b","client_x509_cert_url":"https://c"}"#;

/// The responder builds candidates in isolation: a source that cannot build
/// fails with Vector's reason, a good one passes.
#[tokio::test]
#[ignore = "requires docker and NANOSIEM_TEST_VECTOR_IMAGE (the pinned Vector image)"]
async fn responder_in_the_pinned_image_refuses_a_bad_credential_and_passes_a_good_source() {
    let c = EntrypointContainer::start(|_| {});
    c.wait_heartbeat().await;
    let runner = c.runner();

    let request = runner.prepare().await.unwrap();
    std::fs::write(request.host_dir.join("bad.creds"), REFUSED_SA).unwrap();
    let bad = bad_gcp_source(&format!("{}/bad.creds", request.runtime_dir));
    let outcome = runner.submit(&request, &isolation_files(&bad, "bad_route")).await.unwrap();
    runner.discard(&request).await;
    match outcome {
        IsolationOutcome::Failed(reason) => assert!(reason.contains("GCP"), "{reason}"),
        other => panic!("bad credential must fail isolation: {other:?}"),
    }

    let good = "[sources.ok_source]\ntype = \"demo_logs\"\nformat = \"shuffle\"\nlines = [\"x\"]\n\n\
                [transforms.ok_route]\ntype = \"remap\"\ninputs = [\"ok_source\"]\nsource = \".source_type = \\\"x\\\"\"\n";
    assert_eq!(
        runner.validate(&isolation_files(good, "ok_route")).await.unwrap(),
        IsolationOutcome::Passed
    );
}

/// NAN-4936 (codex P1): a tenant value naming one of the container's secrets
/// must never expand. The responder validates with an empty environment and no
/// interpolation, so `${SECRET}` stays literal in Vector's own error.
#[tokio::test]
#[ignore = "requires docker and NANOSIEM_TEST_VECTOR_IMAGE (the pinned Vector image)"]
async fn responder_never_expands_container_secrets_in_a_candidate() {
    let c = EntrypointContainer::start(|_| {});
    c.wait_heartbeat().await;
    let runner = c.runner();
    for value in ["${SECRET}.attacker.invalid", "$SECRET.attacker.invalid"] {
        // An endpoint Vector parses at build time, so its value lands in the error.
        let candidate = format!(
            "[sources.x_source]\ntype = \"gcp_pubsub\"\nproject = \"p\"\nsubscription = \"s\"\n\
             endpoint = \"{value}\"\nskip_authentication = true\n\n\
             [transforms.x_route]\ntype = \"remap\"\ninputs = [\"x_source\"]\nsource = \".a = 1\"\n"
        );
        let outcome = runner.validate(&isolation_files(&candidate, "x_route")).await.unwrap();
        assert_ne!(outcome, IsolationOutcome::TimedOut, "the responder must have answered");
        let text = format!("{outcome:?}");
        assert!(!text.contains(FAKE_SECRET), "secret expanded for {value}: {text}");
    }
    assert!(!c.logs().contains(FAKE_SECRET));
}

/// NAN-4936 (codex P1): an api without a docker CLI reloads Vector through the
/// responder, which SIGHUPs PID 1 only after checking it is the Vector binary.
#[tokio::test]
#[ignore = "requires docker and NANOSIEM_TEST_VECTOR_IMAGE (the pinned Vector image)"]
async fn responder_delivers_a_reload_request_to_vector() {
    let c = EntrypointContainer::start(|_| {});
    c.wait_heartbeat().await;
    let method = crate::parsers::vector_config_test_hooks::request_reload_in(
        c.validation.path(),
        Duration::from_secs(10),
    )
    .await
    .expect("reload request answered");
    assert_eq!(method, "validation-volume reload request");
    for _ in 0..40 {
        if c.logs().contains("signal=\"SIGHUP\"") {
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("Vector never received SIGHUP:\n{}", c.logs());
}

/// NAN-4936 (codex P1): a deployed source that can no longer build (a revoked
/// credential) must not stop Vector from starting. The entrypoint's cold-start
/// guard replaces its source table with an inert stand-in of the same id
/// (the router still names `bad_route`), keeps the original and Vector's
/// reason in dynamic/quarantine/, and Vector starts.
#[tokio::test]
#[ignore = "requires docker and NANOSIEM_TEST_VECTOR_IMAGE (the pinned Vector image)"]
async fn cold_start_guard_quarantines_a_source_that_cannot_build_and_vector_starts() {
    let c = EntrypointContainer::start(|dynamic| {
        std::fs::write(dynamic.join("sources/configs__bad.creds"), REFUSED_SA).unwrap();
        std::fs::write(
            dynamic.join("sources/configs/gcp_pubsub_bad.toml"),
            bad_gcp_source("/etc/vector/dynamic/sources/configs__bad.creds"),
        )
        .unwrap();
        // The rest of the config names the source's route, as nano's router does.
        std::fs::write(
            dynamic.join("sources/parsers/base.toml"),
            "[sources.internal_logs]\ntype = \"internal_logs\"\n\n\
             [sinks.out]\ntype = \"blackhole\"\ninputs = [\"internal_logs\", \"bad_route\"]\nprint_interval_secs = 0\n",
        )
        .unwrap();
    });
    c.wait_heartbeat().await;
    let mut started = false;
    for _ in 0..60 {
        if c.logs().contains("Vector has started") {
            started = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(started && c.running(), "Vector did not start:\n{}", c.logs());
    let q = c.dynamic.path().join("quarantine");
    assert!(q.join("gcp_pubsub_bad.toml").exists());
    let reason = std::fs::read_to_string(q.join("gcp_pubsub_bad.reason")).unwrap();
    assert!(reason.contains("GCP"), "{reason}");
    let live = std::fs::read_to_string(c.dynamic.path().join("sources/configs/gcp_pubsub_bad.toml")).unwrap();
    assert!(!live.contains("[sources."), "{live}");
    assert!(live.contains("[transforms.bad_source]") && live.contains("[transforms.bad_route]"), "{live}");
}

#[test]
fn vector_output_never_carries_credential_values() {
    let creds = json!({
        "access_key_id": "AKIAEXAMPLEKEY",
        "secret_access_key": "s3cr3t/with\\slash",
        "credentials_json": service_account().to_string(),
    });
    let reason = "x Source: bad key AKIAEXAMPLEKEY / s3cr3t/with\\slash in sa@p.iam.gserviceaccount.com";
    let scrubbed = scrub_secrets(reason, Some(&creds));
    assert!(!scrubbed.contains("AKIAEXAMPLEKEY"), "{scrubbed}");
    assert!(!scrubbed.contains("s3cr3t"), "{scrubbed}");
    assert!(!scrubbed.contains("sa@p.iam"), "{scrubbed}");
    assert!(scrubbed.contains("x Source: bad key"), "{scrubbed}");
    assert_eq!(scrub_secrets("plain", None), "plain");
}

#[test]
fn env_interpolation_syntax_is_detected() {
    for bad in ["${VECTOR_AUTH_TOKEN}", "x${A:-b}y", "$VECTOR_AUTH_TOKEN.attacker:9092", "$_X"] {
        assert!(contains_env_interpolation(bad), "{bad}");
    }
    for ok in ["plain", "^end$", "cost $5", "a$", "$$", "50%$"] {
        assert!(!contains_env_interpolation(ok), "{ok}");
    }
}

#[test]
fn tenant_json_with_env_interpolation_is_rejected_with_its_path() {
    let conn = json!({ "bootstrap_servers": "${VECTOR_AUTH_TOKEN}.attacker.example:9092", "topics": ["ok"] });
    let err = reject_env_interpolation(&conn, "connection_config").unwrap_err();
    assert!(err.contains("connection_config.bootstrap_servers"), "{err}");
    let nested = json!({ "a": [ { "b": "$CLICKHOUSE_PASSWORD" } ] });
    assert!(reject_env_interpolation(&nested, "c").unwrap_err().contains("c.a[0].b"));
    // Azure's reserved consumer group is allowed (rendering escapes it).
    reject_env_interpolation(&json!({ "consumer_group": "$Default" }), "c").unwrap();
}

#[test]
fn rendering_escapes_every_dollar_so_vector_reads_it_literally() {
    let rendered = "password = \"pa${VECTOR_AUTH_TOKEN}ss\"\ngroup = \"$Default\"\n";
    let escaped = escape_env_interpolation(rendered);
    assert_eq!(
        escaped,
        "# nano-env-escaped: v1\npassword = \"pa$${VECTOR_AUTH_TOKEN}ss\"\ngroup = \"$$Default\"\n"
    );
    // Still valid TOML for the in-process checks.
    toml::from_str::<toml::Value>(&escaped).unwrap();
}

/// NAN-4936 (codex re-check P1): a source-config file rendered BEFORE the
/// escaping change sits in the persistent dynamic volume. The live Vector runs
/// with env interpolation on, so a tenant `${SECRET}` in it would expand on the
/// first upgraded start. The entrypoint escapes such files before Vector
/// starts: the event carries the literal text, never the secret.
#[tokio::test]
#[ignore = "requires docker and NANOSIEM_TEST_VECTOR_IMAGE (the pinned Vector image)"]
async fn a_pre_upgrade_file_never_expands_container_secrets_on_first_start() {
    let c = EntrypointContainer::start(|dynamic| {
        std::fs::write(
            dynamic.join("sources/configs/old_source.toml"),
            "# rendered before NAN-4936 (no escape header)\n\
             [sources.old_source]\ntype = \"demo_logs\"\nformat = \"shuffle\"\n\
             lines = [\"tenant-said ${SECRET} and $SECRET\"]\ninterval = 0.2\n\n\
             [transforms.old_route]\ntype = \"remap\"\ninputs = [\"old_source\"]\nsource = \".a = 1\"\n",
        )
        .unwrap();
        std::fs::write(
            dynamic.join("sources/parsers/base.toml"),
            "[sinks.out]\ntype = \"console\"\ninputs = [\"old_route\"]\nencoding.codec = \"text\"\n",
        )
        .unwrap();
    });
    let mut seen = false;
    for _ in 0..60 {
        if c.logs().contains("tenant-said") {
            seen = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let logs = c.logs();
    assert!(seen, "the old source never ran:\n{logs}");
    assert!(!logs.contains(FAKE_SECRET), "the secret expanded:\n{logs}");
    assert!(logs.contains("tenant-said ${SECRET} and $SECRET"), "{logs}");
    let migrated =
        std::fs::read_to_string(c.dynamic.path().join("sources/configs/old_source.toml")).unwrap();
    assert!(migrated.starts_with(ENV_ESCAPED_HEADER), "{migrated}");
    assert!(migrated.contains("$${SECRET} and $$SECRET"), "{migrated}");
}
