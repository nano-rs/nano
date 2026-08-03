// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2305 — validate the directory set Vector actually loads, and stop
//! turning "we could not validate" into "validation passed".

use super::*;

/// The running Vector is launched with four `--config-dir` arguments
/// (docker-compose.yml). `vector validate` was given two of them, so the staged
/// `_router.toml` could name a source-config route transform the validator had
/// no way to see — and an input naming a missing component is fatal to the whole
/// config, which failed the deploy of a config that was in fact correct.
#[test]
fn validation_covers_every_config_dir_vector_loads() {
    let dirs = staged_config_dir_args("/etc/vector/staging");

    assert_eq!(
        dirs,
        vec![
            "/etc/vector/staging".to_string(),
            "/etc/vector/staging/sources/parsers".to_string(),
            "/etc/vector/staging/sources/configs".to_string(),
            "/etc/vector/staging/sinks".to_string(),
        ],
        "the validated directory set must mirror the --config-dir list Vector is \
         launched with; a subset validates a topology nobody runs"
    );
}

/// `VECTOR_STAGING_PATH` is configurable, so the subdirectories have to hang off
/// whatever root the container was told about rather than a hardcoded prefix.
#[test]
fn validation_dirs_follow_the_configured_staging_root() {
    let dirs = staged_config_dir_args("/etc/vector/dynamic/staging");
    assert!(dirs
        .iter()
        .all(|d| d.starts_with("/etc/vector/dynamic/staging")));
    assert!(dirs.contains(&"/etc/vector/dynamic/staging/sources/configs".to_string()));
}

/// The mount-failure signature is not a proof of anything about the config: a
/// staged file that Vector FOUND and could not parse produces exactly this
/// output, because every staged path contains "staging". It used to gate a
/// success path, so a broken config was promoted unvalidated. It may now only
/// annotate a failure — this test pins that it is a classifier, not a verdict.
#[test]
fn a_broken_staged_file_matches_the_mount_signature() {
    let vector_output = "ERROR Failed to load \
         \"/etc/vector/staging/sources/parsers/apache.toml\": expected an equals, found a \
         newline at line 4";

    assert!(
        looks_like_staging_mount_failure(vector_output),
        "the signature is broad enough to match a genuine parse error, which is exactly \
         why it must never select a success path"
    );
}

/// NAN-2309: the staged validate must not touch the environment.
///
/// NAN-2305 widened validation to include `sources/configs`. Those declare real
/// listeners, so validating them against the RUNNING Vector made
/// `vector validate` try to bind ports that same Vector already holds:
///
/// ```text
/// x Source "splunk_hec_ingest": TCP bind failed: Address in use (os error 98)
/// ```
///
/// Every publish then failed on any tenant whose ingress binds a port — which
/// is all of them. Observed live: the running pipeline stayed healthy and kept
/// ingesting, but no parser could be created, changed or deployed. A config
/// freeze rather than an outage, and invisible to CI, which has no live Vector
/// holding those ports.
#[test]
fn staged_validation_does_not_touch_the_environment() {
    let argv = validate_argv("nanosiem-vector", "/etc/vector/staging");

    assert!(
        argv.contains(&"--no-environment".to_string()),
        "staged validate must pass --no-environment; without it Vector binds \
         sockets and dials brokers, and the live process already owns those \
         ports: {argv:?}"
    );

    // The flag has to precede the config dirs it applies to, and validate must
    // still cover the whole graph NAN-2305 widened it to.
    let flag = argv.iter().position(|a| a == "--no-environment").unwrap();
    let first_dir = argv.iter().position(|a| a == "--config-dir").unwrap();
    assert!(flag < first_dir, "flag must precede --config-dir: {argv:?}");
    assert_eq!(
        argv.iter().filter(|a| *a == "--config-dir").count(),
        staged_config_dir_args("/etc/vector/staging").len(),
        "every staged config dir must still be validated: {argv:?}"
    );
}
