// SPDX-License-Identifier: AGPL-3.0-or-later
//! Shared-log-source coverage for collector streams (NAN-2256).
//!
//! Every stream of a collector resolves to the same repository parser and so
//! shares ONE log source: the first to provision creates it, the rest link to
//! the existing one. Only the creating stream's `source_type` ever reached
//! `match_values`, so every later stream's events matched nothing and landed
//! unparsed — while the stream still reported as linked.
//!
//! It stayed hidden because the community parsers happen to enumerate one alias
//! per stream (nine `netskope_*`, four `gws_*`), which `resolve_match_values`
//! folded in as a side effect. That coupling is undeclared and one-directional:
//! adding a stream to a manifest silently under-routes it until someone edits a
//! parser in a different repository.
//!
//! These exercise the real DB path because the whole behaviour is a
//! read-modify-write against `log_sources` — the interesting parts (does it
//! skip the write when already covered, does it demand a grant only when it
//! writes, does it preserve the primary) are invisible to a unit test.
//!
//! `#[ignore]`d DB suite — run via `pg-integration-tests` CI or
//! `docker compose up -d postgres` + `cargo test -- --ignored`.

mod common;

use nanosiem_core::auth::{TargetEffect, TargetGrants};
use nanosiem_core::log_sources::{LogSourceRepository, NewLogSource};
use nanosiem_core::parser_repository::{ParserRepositoryError, ParserRepositoryService};
use uuid::Uuid;

fn log_source_named(name: &str, match_values: Vec<String>) -> NewLogSource {
    NewLogSource {
        name: name.to_string(),
        description: None,
        namespace: "default".into(),
        timezone: "UTC".into(),
        source_type: "routed".into(),
        parser_vrl: ".udm = {}".into(),
        output_fields: None,
        dispatch_source_config_id: None,
        category: None,
        vendor: None,
        product: None,
        icon: None,
        color: None,
        match_field: None,
        match_pattern: None,
        match_values: Some(match_values),
        sampling_ratio: None,
        sampling_exclude_condition: None,
        lifecycle_status: None,
    }
}

/// A unique name per test run so parallel `#[tokio::test]`s in this binary
/// don't collide on the log_sources name.
fn unique(prefix: &str) -> String {
    format!("{prefix}-{}", Uuid::new_v4())
}

/// The Google Workspace shape: the `login` stream created the log source, so it
/// claims only `gws_login`. Enabling `admin` must widen it, or every
/// `gws_admin` event falls through to `source_router.generic` unparsed.
#[tokio::test]
#[ignore]
async fn linking_a_second_stream_widens_the_shared_log_source() {
    let pool = common::migrated_pool().await;
    let repo = LogSourceRepository::new(pool.clone());
    let service = ParserRepositoryService::new(pool.clone());

    let created = repo
        .create(&log_source_named(
            &unique("gws"),
            vec!["gws_login".into(), "google_workspace".into()],
        ))
        .await
        .expect("create log source");

    let added = service
        .ensure_log_source_claims_source_type(created.id, "gws_admin", &TargetGrants::system())
        .await
        .expect("widen");

    assert!(added, "a source_type the log source did not claim is a write");

    let after = repo.find_by_id(created.id).await.expect("refetch");
    let values = after.match_values.expect("match_values");
    assert!(
        values.iter().any(|v| v == "gws_admin"),
        "second stream's source_type must route: {values:?}"
    );
    assert_eq!(
        values.first().map(String::as_str),
        Some("gws_login"),
        "the primary must not move — routing rules point at match_values.first()"
    );
    assert!(
        values.iter().any(|v| v == "google_workspace"),
        "widening must never drop an existing value (NAN-2249): {values:?}"
    );
}

/// Idempotent: a stream re-enabled, or a reconcile that runs again, must not
/// keep appending. It also must not demand a permission for a no-op — see the
/// next test.
#[tokio::test]
#[ignore]
async fn widening_is_idempotent() {
    let pool = common::migrated_pool().await;
    let repo = LogSourceRepository::new(pool.clone());
    let service = ParserRepositoryService::new(pool.clone());

    let created = repo
        .create(&log_source_named(&unique("netskope"), vec!["netskope_alert".into()]))
        .await
        .expect("create log source");

    let first = service
        .ensure_log_source_claims_source_type(created.id, "netskope_page", &TargetGrants::system())
        .await
        .expect("first widen");
    let second = service
        .ensure_log_source_claims_source_type(created.id, "netskope_page", &TargetGrants::system())
        .await
        .expect("second widen");

    assert!(first, "first call writes");
    assert!(!second, "second call must be a no-op");

    let after = repo.find_by_id(created.id).await.expect("refetch");
    let values = after.match_values.expect("match_values");
    assert_eq!(
        values.iter().filter(|v| *v == "netskope_page").count(),
        1,
        "no duplicate appends: {values:?}"
    );
}

/// An already-covered log source costs the caller no permission. Provisioning
/// runs on every reconcile, so demanding `log_sources:edit` for a no-op would
/// make a correctly-configured collector fail for an operator who is only
/// allowed to manage collectors.
#[tokio::test]
#[ignore]
async fn no_grant_required_when_already_covered() {
    let pool = common::migrated_pool().await;
    let repo = LogSourceRepository::new(pool.clone());
    let service = ParserRepositoryService::new(pool.clone());

    let created = repo
        .create(&log_source_named(&unique("slack"), vec!["slack_access_log".into()]))
        .await
        .expect("create log source");

    let added = service
        .ensure_log_source_claims_source_type(
            created.id,
            "slack_access_log",
            &TargetGrants::none(),
        )
        .await
        .expect("a no-op must not require a grant");

    assert!(!added);
}

/// ...but an actual write does. Silently widening someone's log source without
/// `log_sources:edit` would launder a missing permission; provisioning reports
/// this as `NotPermitted` so the operator sees the stream is uncovered.
#[tokio::test]
#[ignore]
async fn widening_requires_log_source_edit() {
    let pool = common::migrated_pool().await;
    let repo = LogSourceRepository::new(pool.clone());
    let service = ParserRepositoryService::new(pool.clone());

    let created = repo
        .create(&log_source_named(&unique("gws-denied"), vec!["gws_login".into()]))
        .await
        .expect("create log source");

    let err = service
        .ensure_log_source_claims_source_type(created.id, "gws_drive", &TargetGrants::none())
        .await
        .expect_err("must refuse without the grant");

    assert!(
        matches!(err, ParserRepositoryError::Forbidden(ref p) if p == TargetEffect::LogSourceEdit.permission()),
        "expected Forbidden(log_sources:edit), got {err:?}"
    );

    let after = repo.find_by_id(created.id).await.expect("refetch");
    let values = after.match_values.expect("match_values");
    assert!(
        !values.iter().any(|v| v == "gws_drive"),
        "a refused widen must write nothing: {values:?}"
    );
}

/// The reason this is one SQL statement rather than a read-modify-write.
///
/// Two callers provisioning different streams onto the same shared log source
/// — two HTTP handlers, or two collector instances using one parser — would
/// otherwise both read the same array and the second write would clobber the
/// first. The lost stream collects unparsed until some later reconcile happens
/// to re-add it, which is exactly the silent, eventually-self-healing failure
/// this issue exists to remove.
///
/// Fires 8 concurrent widens of distinct source_types at one log source; every
/// one must survive.
#[tokio::test]
#[ignore]
async fn concurrent_widens_do_not_lose_values() {
    let pool = common::migrated_pool().await;
    let repo = LogSourceRepository::new(pool.clone());

    let created = repo
        .create(&log_source_named(&unique("concurrent"), vec!["primary".into()]))
        .await
        .expect("create log source");

    let expected: Vec<String> = (0..8).map(|i| format!("stream_{i}")).collect();

    let mut handles = Vec::new();
    for value in expected.clone() {
        let pool = pool.clone();
        let id = created.id;
        handles.push(tokio::spawn(async move {
            ParserRepositoryService::new(pool)
                .ensure_log_source_claims_source_type(id, &value, &TargetGrants::system())
                .await
        }));
    }
    for h in handles {
        h.await.expect("task").expect("widen");
    }

    let after = repo.find_by_id(created.id).await.expect("refetch");
    let values = after.match_values.expect("match_values");

    for value in &expected {
        assert!(
            values.contains(value),
            "{value} was lost to a concurrent write: {values:?}"
        );
    }
    assert_eq!(
        values.first().map(String::as_str),
        Some("primary"),
        "the primary must survive concurrent appends"
    );
    assert_eq!(
        values.len(),
        expected.len() + 1,
        "no duplicates and nothing dropped: {values:?}"
    );
}
