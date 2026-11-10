// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5233: the push-enrichment lane (`enrichment_ingest` on :8090, the edge's
//! `/enrichment`) shares the log lanes' tokens file, so every per-source
//! ingest token authenticates there. Its prepare transform must accept only a
//! multiplex credential (the platform credential, or the install token in
//! legacy multiplex mode) and refuse a token bound to a log source. Runs the
//! shipped `enrichment_ingest_prepare` VRL, from every copy that ships it, with
//! the metadata the nano-rs/vector fork stamps for a matched file entry.

use serde::Deserialize as _;
use serde_json::{json, Value};

use super::vector_lane_tests::{kept, run, settings, source, stamped_route, transform_source, Outcome, TOKEN};
use super::{file_extra_entries, InstallTokenMode, TokenFileEntry, INSTALL_CREDENTIAL_ID, PLATFORM_PULL_CREDENTIAL_ID};

const ENRICH: &str = include_str!("../../../config/vector/04-enrichment-source.toml");

/// A repository file outside the crate. The open-core mirror strips `deploy/`,
/// so those copies are read at run time (never `include_str!`) and skipped
/// where absent; the private tree asserts every copy.
fn repo_file(path: &str) -> Option<String> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("nanosiem-core has a repository parent")
        .join(path);
    path.exists()
        .then(|| std::fs::read_to_string(&path).expect("repository file is readable"))
}

/// The `04-enrichment-source.toml` key of a Kubernetes ConfigMap manifest.
fn configmap_enrich(manifest: &str) -> String {
    serde_yaml::Deserializer::from_str(manifest)
        .filter_map(|doc| serde_yaml::Value::deserialize(doc).ok())
        .find_map(|doc| doc["data"]["04-enrichment-source.toml"].as_str().map(str::to_string))
        .expect("manifest ships 04-enrichment-source.toml")
}

/// The prepare program of every shipped copy of the enrichment source.
fn prepare_programs() -> Vec<(&'static str, String)> {
    let program = |config: &str| transform_source(config, "enrichment_ingest_prepare");
    let mut programs = vec![("config/vector", program(ENRICH))];
    if let Some(helm) = repo_file("deploy/helm/nano/files/vector/04-enrichment-source.toml") {
        programs.push(("helm", program(&helm)));
    }
    for (label, path) in [
        ("k8s/vector", "deploy/k8s/vector/configmap.yaml"),
        ("k8s/rackspace", "deploy/k8s/rackspace/vector-configmap.yaml"),
    ] {
        if let Some(manifest) = repo_file(path) {
            programs.push((label, program(&configmap_enrich(&manifest))));
        }
    }
    programs
}

fn record() -> Value {
    json!({"message": r#"{"kind":"identity","source":"ad","external_id":"S-1-5-21-1"}"#})
}

/// The stamp the fork sets for a matched file entry (`id`, rendered `name`).
fn stamp_of(entry: &TokenFileEntry) -> (String, String) {
    (entry.id.to_string(), stamped_route(&entry.route))
}

fn assert_accepted(label: &str, program: &str, stamp: Option<(&str, &str)>) {
    let (event, metadata) = kept(run(program, record(), stamp));
    assert_eq!(event["source_type"], "nano_enrich", "{label}");
    assert_eq!(event["kind"], "identity", "{label}");
    assert_eq!(metadata["nano_durable_ingest"], true, "{label}");
}

fn assert_refused(label: &str, program: &str, stamp: (&str, &str)) {
    assert!(
        matches!(run(program, record(), Some(stamp)), Outcome::Aborted),
        "{label}: a record authenticated by {stamp:?} must not reach the enrichment router"
    );
}

/// A named per-source token (and the install token once bound in strict
/// mode) carries its log source's route key: refused on the enrichment lane.
#[test]
fn source_bound_tokens_are_refused_on_the_enrichment_lane() {
    let named_route = stamped_route("apache_access");
    let strict_install = file_extra_entries(
        Some("install"),
        Some("platform"),
        &settings(true, InstallTokenMode::Strict),
        Some(&source("okta")),
    );
    let strict_install = strict_install
        .iter()
        .find(|entry| entry.id == INSTALL_CREDENTIAL_ID)
        .expect("a bound strict install token is listed");
    let (install_id, install_route) = stamp_of(strict_install);
    for (label, program) in prepare_programs() {
        assert_refused(label, &program, (TOKEN, &named_route));
        assert_refused(label, &program, (&install_id, &install_route));
        // A listed entry without a route is not a multiplex credential either.
        assert_refused(label, &program, (TOKEN, ""));
        // Route keys that only look like the enrichment lane are not `*`.
        assert_refused(label, &program, (TOKEN, "nano_enrich"));
    }
}

/// The in-platform writer (`EnrichmentLaneClient` -> platform credential, then
/// the install token on a 401) keeps working: the platform credential and the
/// legacy-multiplex install token are both listed with the multiplex route.
#[test]
fn multiplex_credentials_are_accepted_on_the_enrichment_lane() {
    let platform = file_extra_entries(
        Some("install"),
        Some("platform"),
        &settings(true, InstallTokenMode::Strict),
        Some(&source("okta")),
    );
    let platform = platform
        .iter()
        .find(|entry| entry.id == PLATFORM_PULL_CREDENTIAL_ID)
        .expect("the platform credential is listed");
    let legacy = file_extra_entries(
        Some("install"),
        None,
        &settings(true, InstallTokenMode::LegacyMultiplex),
        None,
    );
    let legacy = legacy
        .iter()
        .find(|entry| entry.id == INSTALL_CREDENTIAL_ID)
        .expect("the legacy multiplex install token is listed");
    for (label, program) in prepare_programs() {
        for entry in [platform, legacy] {
            let (id, route) = stamp_of(entry);
            assert_accepted(label, &program, Some((&id, &route)));
        }
    }
}

/// No credential stamp: the source's static `auth` accepted the request (only
/// the explicit static-fallback / unauthenticated opt-ins do), so the source
/// decision stands, as on the log lanes. A per-source token can never arrive
/// unstamped: it is either listed (stamped) or refused with 401.
#[test]
fn unstamped_records_follow_the_source_auth_decision() {
    for (label, program) in prepare_programs() {
        assert_accepted(label, &program, None);
    }
}
