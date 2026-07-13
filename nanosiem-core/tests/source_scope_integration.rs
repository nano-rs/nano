// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fail-closed / leak-prevention integration tests for per-source RBAC scoping
//! (NAN-1797 / epic NAN-1789).
//!
//! These are the ONLY guard against schema drift for the source-scope tables and
//! their runtime `sqlx` queries: this repo has no compile-time `sqlx` macros and
//! no `.sqlx` cache, so a column↔struct mismatch in the resolver
//! (`auth::source_scope_resolver`) or the repository
//! (`db::repository::source_scope`) only surfaces when the query is executed
//! against a real, migrated Postgres. Like the sibling DB-backed suites they are
//! `#[ignore]`d — a plain `cargo test` skips them; the `pg-integration-tests` CI
//! lane runs them with `-- --ignored` (locally: `docker compose up -d postgres`).
//!
//! Each test isolates itself with a unique `source_type` / group name / user
//! email suffix, so they run in parallel against the one shared migrated pool
//! (unlike `case_stats_visibility_integration`, no `--test-threads=1` is needed —
//! every assertion is scoped to this test's own source value, robust to rows
//! other tests register concurrently in the shared registry table).

// De-gated like the sibling suites: compiles with every `cargo test` (so the
// contract stays wired), but the DB-backed tests are `#[ignore]`d.

mod common;

use std::time::Duration;

use nanosiem_core::auth::source_scope_resolver::SourceScopeError;
use nanosiem_core::auth::{ScopeSet, SourceScopeResolver};
use nanosiem_core::db::repository::SourceScopeRepository;
use nanosiem_core::search::query_processing::enforce_source_scope;
use sqlx::PgPool;
use uuid::Uuid;

/// Short, collision-free suffix so parallel tests in this binary (and repeated
/// local runs against a persistent DB) never share a `source_type` value, group
/// name, or user email. Lowercase hex, so it survives the resolver's
/// `lower()`/`trim` normalization unchanged (no case drift in assertions).
fn suffix() -> String {
    let id = Uuid::now_v7().simple().to_string();
    id[..16].to_string()
}

/// Mint a real `users` row (grants/created_by carry FKs to it in some paths).
async fn create_user(pool: &PgPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        r#"INSERT INTO users (id, email, name, password_hash, status, created_at, updated_at)
           VALUES ($1, $2, 'Scope Test', 'x', 'active', NOW(), NOW())"#,
    )
    .bind(id)
    .bind(format!("scope-{id}@example.com"))
    .execute(pool)
    .await
    .expect("create user");
    id
}

/// Mint a real `groups` row (`source_type_grants.group_id` FKs to it).
async fn create_group(pool: &PgPool, name: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(r#"INSERT INTO groups (id, name) VALUES ($1, $2)"#)
        .bind(id)
        .bind(name)
        .execute(pool)
        .await
        .expect("create group");
    id
}

async fn add_user_to_group(pool: &PgPool, user_id: Uuid, group_id: Uuid) {
    sqlx::query(r#"INSERT INTO user_groups (user_id, group_id) VALUES ($1, $2)"#)
        .bind(user_id)
        .bind(group_id)
        .execute(pool)
        .await
        .expect("link user to group");
}

/// (1) A restricted source with no grant is denied to a user; granting it to a
/// group that user belongs to un-restricts it (the denied set shrinks).
///
/// Also exercises the repository's runtime `sqlx` (`add_restricted`, `add_grant`
/// with its group-name `LEFT JOIN`, `denied_for_user`) against the live schema —
/// this lane's whole purpose (schema-drift catch).
#[tokio::test]
#[ignore = "db-backed; runs in pg-integration CI (cargo test -- --ignored)"]
async fn grant_to_users_group_unrestricts_a_source() {
    let pool = common::migrated_pool().await;
    let repo = SourceScopeRepository::new(pool.clone());
    let resolver = SourceScopeResolver::new(pool.clone());

    let sfx = suffix();
    let source = format!("insider_{sfx}");
    let group_name = format!("it-team-{sfx}");

    // A user in a group, plus a freshly-restricted source with no grant yet.
    let user = create_user(&pool).await;
    let group = create_group(&pool, &group_name).await;
    add_user_to_group(&pool, user, group).await;

    let stored = repo
        .add_restricted(&source, Some("insider-threat feed"), None)
        .await
        .expect("register restricted source");
    assert_eq!(stored.source_type, source);

    // With no grant, the user is denied the restricted source.
    let scope = resolver.resolve(user, &[]).await.expect("resolve pre-grant");
    assert!(
        scope.deny_set().contains(&source),
        "restricted source with no grant must be denied; deny_set = {:?}",
        scope.deny_set()
    );
    assert!(scope.is_restricted());

    // The admin-view convenience mirrors the live resolver's difference logic.
    let admin_view = repo.denied_for_user(user).await.expect("denied_for_user");
    assert!(admin_view.contains(&source));

    // Grant the source to the user's group → it must drop out of the denied set.
    let grant = repo
        .add_grant(&source, group, None)
        .await
        .expect("grant source to group");
    assert_eq!(grant.source_type, source);
    assert_eq!(grant.group_name.as_deref(), Some(group_name.as_str()));

    // The resolver caches per-user for 60s; a grant mutation must call
    // invalidate() (the admin handler does this after every CRUD).
    resolver.invalidate();

    let scope = resolver.resolve(user, &[]).await.expect("resolve post-grant");
    assert!(
        !scope.deny_set().contains(&source),
        "granting the source to the user's group must un-restrict it; deny_set = {:?}",
        scope.deny_set()
    );

    let admin_view = repo
        .denied_for_user(user)
        .await
        .expect("denied_for_user post-grant");
    assert!(!admin_view.contains(&source));

    // Best-effort cleanup (cascades the grant); keeps the shared registry small
    // across local reruns. Ignored on failure — CI uses a throwaway Postgres.
    let _ = repo.remove_restricted(&source).await;
}

/// (2) FAIL-CLOSED: when the restricted registry has never loaded and Postgres
/// is unreachable, `resolve()` must surface an error — NEVER an empty
/// (fail-open) `ScopeSet`, which would show a scoped user every restricted row —
/// and must not cache a fail-open value that leaks on the next call.
#[tokio::test]
#[ignore = "db-backed; runs in pg-integration CI (cargo test -- --ignored)"]
async fn resolver_fails_closed_when_registry_never_loaded_and_pg_down() {
    // A pool that never connects (nothing listens on the discard port). Mirrors
    // the fail-closed pool pattern in `leader.rs`. The restricted registry has
    // never loaded, so there is no safe deny set to fall back to.
    let bad = sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(Duration::from_secs(3))
        .connect_lazy("postgres://nanosiem:nanosiem@127.0.0.1:9/nanosiem")
        .expect("build lazy pool");
    let resolver = SourceScopeResolver::new(bad);

    let err = resolver
        .resolve(Uuid::now_v7(), &[])
        .await
        .expect_err("resolve against a down PG must fail closed, not return a scope");
    assert!(
        matches!(err, SourceScopeError::Unavailable),
        "never-loaded registry + PG down must be Unavailable (fail closed), got {err:?}"
    );

    // A second call must ALSO fail — the resolver must not have cached a
    // fail-open empty deny-set that would leak on the next request.
    let err2 = resolver
        .resolve(Uuid::now_v7(), &[])
        .await
        .expect_err("second resolve must still fail closed (no cached fail-open value)");
    assert!(
        matches!(err2, SourceScopeError::Unavailable),
        "fail-open value must never be cached; got {err2:?}"
    );
}

/// (3) A demo user (`demo_analyst`) is always deny-all-restricted: it has no
/// group assignments and can hold no grant, so every restricted source is denied
/// regardless of DB state — never unrestricted.
#[tokio::test]
#[ignore = "db-backed; runs in pg-integration CI (cargo test -- --ignored)"]
async fn demo_user_is_deny_all_restricted() {
    let pool = common::migrated_pool().await;
    let repo = SourceScopeRepository::new(pool.clone());
    let resolver = SourceScopeResolver::new(pool.clone());

    let sfx = suffix();
    let source = format!("demo_scope_{sfx}");
    repo.add_restricted(&source, None, None)
        .await
        .expect("register restricted source");

    // The demo user id need not exist — the demo bypass returns
    // deny-all-restricted before any group lookup.
    let scope = resolver
        .resolve(Uuid::now_v7(), &["demo_analyst".to_string()])
        .await
        .expect("resolve demo user");
    assert!(
        scope.is_restricted(),
        "demo user must be scoped, never unrestricted"
    );
    assert!(
        scope.deny_set().contains(&source),
        "demo user must be denied every restricted source; deny_set = {:?}",
        scope.deny_set()
    );

    let _ = repo.remove_restricted(&source).await;
}

/// (4) End-to-end: a resolved deny-set threaded through the injector rewrites the
/// query to exclude the restricted source at the base-table scan
/// (`source_type NOT IN ("…")`), while preserving the analyst's own terms.
#[tokio::test]
#[ignore = "db-backed; runs in pg-integration CI (cargo test -- --ignored)"]
async fn resolved_scope_injects_source_type_not_in() {
    let pool = common::migrated_pool().await;
    let repo = SourceScopeRepository::new(pool.clone());
    let resolver = SourceScopeResolver::new(pool.clone());

    let sfx = suffix();
    let source = format!("e2e_{sfx}");
    repo.add_restricted(&source, None, None)
        .await
        .expect("register restricted source");

    // A user with no grants (random id => no group rows) is denied the source.
    let scope = resolver
        .resolve(Uuid::now_v7(), &[])
        .await
        .expect("resolve");
    assert!(
        scope.deny_set().contains(&source),
        "ungranted user must be denied the restricted source; deny_set = {:?}",
        scope.deny_set()
    );

    // Threading that deny-set through the injector rewrites the query to exclude
    // the source at the scan. (Multiple restricted sources may co-exist in the
    // shared registry; assert on this test's own value being present in the
    // negated IN-list, which is robust to that.)
    let rewritten = enforce_source_scope("error", scope.deny_set()).expect("inject source scope");
    assert!(
        rewritten.contains("source_type NOT IN ("),
        "expected a negated source_type IN-list, got: {rewritten}"
    );
    assert!(
        rewritten.contains(&format!("\"{source}\"")),
        "the restricted source must appear in the exclusion list, got: {rewritten}"
    );
    assert!(
        rewritten.contains("error"),
        "the analyst's own search term must survive the rewrite, got: {rewritten}"
    );

    let _ = repo.remove_restricted(&source).await;
}

/// (5) Back-compat: an empty deny-set — exactly what the resolver returns as
/// `ScopeSet::unrestricted()` for an empty registry — leaves the query
/// byte-identical (the zero-restricted-sources guarantee: unrestricted callers
/// pay nothing).
///
/// Asserts against `unrestricted()` directly rather than truthfully emptying the
/// shared registry, which parallel tests in this binary keep populating; the
/// guarantee under test is the empty deny-set path, which that value reproduces.
#[tokio::test]
#[ignore = "db-backed; runs in pg-integration CI (cargo test -- --ignored)"]
async fn empty_registry_leaves_query_byte_identical() {
    let scope = ScopeSet::unrestricted();
    assert!(scope.deny_set().is_empty());
    assert!(!scope.is_restricted());

    let query = "user=alice failed | stats count by src_ip | where count > 10 | sort -count";
    let out = enforce_source_scope(query, scope.deny_set()).expect("no-op enforce");
    assert_eq!(
        out, query,
        "empty deny set must return the query byte-identical (back-compat)"
    );
}
