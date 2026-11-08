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

/// Delete the fixture. These suites run against a long-lived developer
/// database, and an earlier version of the sibling enterprise suite left
/// ENABLED rows behind that claimed real source_types — which the NAN-2247
/// collision guard then correctly refused to deploy, wedging Vector
/// reconciliation until they were removed by hand. Rows created here are
/// disabled, so they were only clutter, but clutter is how that started.
async fn cleanup(pool: &sqlx::PgPool, id: Uuid) {
    let _ = sqlx::query("DELETE FROM log_sources WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await;
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

    assert!(
        added,
        "a source_type the log source did not claim is a write"
    );

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

    cleanup(&pool, created.id).await;
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
        .create(&log_source_named(
            &unique("netskope"),
            vec!["netskope_alert".into()],
        ))
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

    cleanup(&pool, created.id).await;
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
        .create(&log_source_named(
            &unique("slack"),
            vec!["slack_access_log".into()],
        ))
        .await
        .expect("create log source");

    let added = service
        .ensure_log_source_claims_source_type(created.id, "slack_access_log", &TargetGrants::none())
        .await
        .expect("a no-op must not require a grant");

    assert!(!added);

    cleanup(&pool, created.id).await;
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
        .create(&log_source_named(
            &unique("gws-denied"),
            vec!["gws_login".into()],
        ))
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

    cleanup(&pool, created.id).await;
}

// =============================================================================
// NAN-2290: parserless collector streams still materialize a Log Source
// =============================================================================

#[tokio::test]
#[ignore]
async fn parserless_collector_gets_a_raw_pass_through_log_source() {
    let pool = common::migrated_pool().await;
    let repo = LogSourceRepository::new(pool.clone());
    let service = ParserRepositoryService::new(pool.clone());
    let source_type = unique("custom-api-events");

    let (id, created) = service
        .ensure_raw_collector_log_source(&source_type, None, &TargetGrants::system())
        .await
        .expect("create raw collector source");

    assert!(created);
    let source = repo
        .find_by_id(id)
        .await
        .expect("created source is visible");
    assert_eq!(source.source_type, "routed");
    assert_eq!(source.parser_vrl.trim(), ". = .");
    assert!(source.validated, "the built-in identity VRL is valid");
    assert_eq!(source.lifecycle_status, "active");
    assert_eq!(source.match_field.as_deref(), Some("source_type"));
    assert_eq!(source.match_values, Some(vec![source_type]));

    cleanup(&pool, id).await;
}

#[tokio::test]
#[ignore]
async fn existing_raw_collector_source_is_reused_without_create_permission() {
    let pool = common::migrated_pool().await;
    let service = ParserRepositoryService::new(pool.clone());
    let source_type = unique("custom-api-reuse");

    let (id, created) = service
        .ensure_raw_collector_log_source(&source_type, None, &TargetGrants::system())
        .await
        .expect("create raw collector source");
    assert!(created);

    let (same_id, created_again) = service
        .ensure_raw_collector_log_source(&source_type, None, &TargetGrants::none())
        .await
        .expect("reuse must be a no-op with no grant");
    assert_eq!(same_id, id);
    assert!(!created_again);

    cleanup(&pool, id).await;
}

#[tokio::test]
#[ignore]
async fn creating_raw_collector_source_requires_log_source_create() {
    let pool = common::migrated_pool().await;
    let service = ParserRepositoryService::new(pool.clone());
    let source_type = unique("custom-api-denied");

    let err = service
        .ensure_raw_collector_log_source(&source_type, None, &TargetGrants::none())
        .await
        .expect_err("creation without log_sources:create must be refused");
    assert!(
        matches!(err, ParserRepositoryError::Forbidden(ref p) if p == TargetEffect::LogSourceCreate.permission()),
        "expected Forbidden(log_sources:create), got {err:?}"
    );
    assert!(
        service
            .find_log_source_claiming_source_type(&source_type)
            .await
            .expect("lookup")
            .is_none(),
        "a refused create must write nothing"
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
        .create(&log_source_named(
            &unique("concurrent"),
            vec!["primary".into()],
        ))
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

    cleanup(&pool, created.id).await;
}

// =============================================================================
// NAN-2268: the whole-list union must not lose a concurrent single append
// =============================================================================

/// `apply_upstream_update` used to read match_values, merge in Rust, and write
/// the array back wholesale. Interleaved with `add_match_value` from collector
/// provisioning, the stale merge simply overwrote the append and that stream
/// silently stopped routing — the narrowing NAN-2249 exists to prevent, arriving
/// by a different door.
///
/// Both writers now do their work in one statement, so they serialize on the row
/// instead of racing through a read.
#[tokio::test]
#[ignore]
async fn union_and_append_cannot_lose_each_other() {
    let pool = common::migrated_pool().await;
    let repo = LogSourceRepository::new(pool.clone());

    let created = repo
        .create(&log_source_named(
            &unique("union-race"),
            vec!["primary".into()],
        ))
        .await
        .expect("create log source");

    // 4 whole-list unions (the upstream-update writer) interleaved with 4 single
    // appends (the collector-provisioning writer), all against one row.
    let mut handles = Vec::new();
    for i in 0..4 {
        let (p1, p2) = (pool.clone(), pool.clone());
        let id = created.id;
        handles.push(tokio::spawn(async move {
            LogSourceRepository::new(p1)
                .union_match_values(id, &[format!("upstream_{i}"), "shared_alias".into()])
                .await
                .map(|_| ())
        }));
        handles.push(tokio::spawn(async move {
            LogSourceRepository::new(p2)
                .add_match_value(id, &format!("stream_{i}"))
                .await
                .map(|_| ())
        }));
    }
    for h in handles {
        h.await.expect("task").expect("write");
    }

    let after = repo.find_by_id(created.id).await.expect("refetch");
    let values = after.match_values.expect("match_values");

    for i in 0..4 {
        assert!(
            values.contains(&format!("upstream_{i}")),
            "upstream_{i} lost to a concurrent write: {values:?}"
        );
        assert!(
            values.contains(&format!("stream_{i}")),
            "stream_{i} lost to a concurrent write: {values:?}"
        );
    }
    assert_eq!(
        values.first().map(String::as_str),
        Some("primary"),
        "the primary must not move — routing rules point at match_values.first()"
    );
    assert_eq!(
        values.iter().filter(|v| *v == "shared_alias").count(),
        1,
        "a value four unions all wanted must appear once: {values:?}"
    );

    cleanup(&pool, created.id).await;
}

/// The union appends to the STORED array, so the primary is untouched by
/// construction — including when the stored primary would not survive today's
/// source_type allow-list, which is where the old Rust merge could reorder.
#[tokio::test]
#[ignore]
async fn union_preserves_a_legacy_primary() {
    let pool = common::migrated_pool().await;
    let repo = LogSourceRepository::new(pool.clone());

    let created = repo
        .create(&log_source_named(
            &unique("legacy-primary"),
            vec!["legacy value with spaces".into(), "apache".into()],
        ))
        .await
        .expect("create log source");

    repo.union_match_values(created.id, &["apache".into(), "apache_access".into()])
        .await
        .expect("union");

    let values = repo
        .find_by_id(created.id)
        .await
        .expect("refetch")
        .match_values
        .expect("match_values");

    assert_eq!(
        values.first().map(String::as_str),
        Some("legacy value with spaces"),
        "an allow-list-failing primary still holds position 0: {values:?}"
    );
    assert_eq!(
        values.iter().filter(|v| *v == "apache").count(),
        1,
        "an already-present value is not re-appended: {values:?}"
    );
    assert!(values.contains(&"apache_access".to_string()));

    cleanup(&pool, created.id).await;
}

/// The NAN-2249 guarantee itself, through the SQL path that now implements it.
///
/// Six unit tests used to assert this against a Rust merge helper that the
/// update path no longer calls; deleting them without this would have left the
/// headline promise — "accepting a parser update never stops your logs
/// routing" — asserted nowhere. The union only ever appends, so narrowing is
/// structurally impossible rather than merely untested, but the property is the
/// point of the change and deserves to fail loudly if the shape regresses.
#[tokio::test]
#[ignore]
async fn an_upstream_update_cannot_drop_an_alias_a_sender_still_uses() {
    let pool = common::migrated_pool().await;
    let repo = LogSourceRepository::new(pool.clone());

    // What an operator is actually routing on today.
    let created = repo
        .create(&log_source_named(
            &unique("no-narrow"),
            vec![
                "apache".into(),
                "apache_access".into(),
                "apache_error".into(),
            ],
        ))
        .await
        .expect("create log source");

    // What upstream now says after the parsers repo collapsed to one canonical
    // value — note it does NOT list apache or apache_error.
    repo.union_match_values(created.id, &["apache_access".into()])
        .await
        .expect("union");

    let values = repo
        .find_by_id(created.id)
        .await
        .expect("refetch")
        .match_values
        .expect("match_values");

    for kept in ["apache", "apache_access", "apache_error"] {
        assert!(
            values.iter().any(|v| v == kept),
            "{kept} was dropped by an upstream update (NAN-2249): {values:?}"
        );
    }
    assert_eq!(
        values.len(),
        3,
        "nothing added, nothing removed: {values:?}"
    );

    cleanup(&pool, created.id).await;
}

/// A log source with no match_values at all — the array is NULL rather than
/// empty, which is a different code path in the COALESCE chain.
#[tokio::test]
#[ignore]
async fn union_onto_a_null_array_seeds_it() {
    let pool = common::migrated_pool().await;
    let repo = LogSourceRepository::new(pool.clone());

    let created = repo
        .create(&log_source_named(&unique("null-mv"), vec![]))
        .await
        .expect("create log source");
    sqlx::query("UPDATE log_sources SET match_values = NULL WHERE id = $1")
        .bind(created.id)
        .execute(&pool)
        .await
        .expect("null the array");

    repo.union_match_values(created.id, &["seeded".into()])
        .await
        .expect("union");

    let values = repo
        .find_by_id(created.id)
        .await
        .expect("refetch")
        .match_values
        .expect("match_values");
    assert_eq!(values, vec!["seeded".to_string()]);

    cleanup(&pool, created.id).await;
}
