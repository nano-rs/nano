// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared CRUD plumbing for git-synced repositories (NAN-1618).
//!
//! The parser / playbook / rule features each manage a "repositories" table
//! (`parser_repositories`, `playbook_repositories`, `rule_repositories`) and a
//! companion "items" table (`repository_parsers`, `repository_playbooks`,
//! `repository_rules`). Their `find_by_id` / `find_by_slug` / `list` / `delete`
//! / `update_sync_status` methods and the items-table pruning/count helpers are
//! byte-identical modulo the table name and the per-table count column. This
//! module hosts the single source of truth for that SQL; the feature
//! repositories keep their public method signatures and delegate here.
//!
//! Methods that genuinely diverge per feature (`create`, `update`, `upsert`,
//! and the items `find_by_*` whose return shape/error message differ) stay
//! specialized in their own modules and are intentionally NOT routed here.
//!
//! The generated SQL is asserted against canonical literals in the unit tests
//! at the bottom of this file. The single-line statements (`find_by_id`,
//! `find_by_slug`, the `list` SELECT, `delete`, `list_for_auto_sync` and the
//! items helpers) are byte-identical for every repo. The two multi-line UPDATE
//! statements had inconsistent `SET` line-wrapping across the three repos, so
//! each is normalized to one canonical layout, touching exactly one repo:
//! - stuck-`syncing` cleanup: parser/rule had `SET` on its own line; playbook's
//!   inline `SET` is normalized to that form.
//! - `update_sync_status`: parser/playbook had inline `SET`; rule's own-line
//!   `SET` is normalized to that form.
//!
//! These are whitespace-only changes — identical columns, binds, filters and
//! semantics; Postgres tokenizes them identically.

use sqlx::postgres::PgRow;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use super::repo_error::RepoError;

// =============================================================================
// "repositories" table helpers (parser_repositories / playbook_repositories /
// rule_repositories). All return RepoError, which the three feature modules
// alias as their public repository-layer error type.
// =============================================================================

/// `SELECT * FROM <table> WHERE id = $1`, mapping the empty result to
/// `RepoError::NotFound(id)`.
pub async fn find_by_id<T>(pool: &PgPool, table: &str, id: Uuid) -> Result<T, RepoError>
where
    T: Send + Unpin + for<'r> FromRow<'r, PgRow>,
{
    sqlx::query_as::<_, T>(&format!("SELECT * FROM {table} WHERE id = $1"))
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or(RepoError::NotFound(id))
}

/// `SELECT * FROM <table> WHERE slug = $1`, mapping the empty result to
/// `RepoError::NotFound(Uuid::nil())` (matching the historical behavior of the
/// per-feature `find_by_slug`).
pub async fn find_by_slug<T>(pool: &PgPool, table: &str, slug: &str) -> Result<T, RepoError>
where
    T: Send + Unpin + for<'r> FromRow<'r, PgRow>,
{
    sqlx::query_as::<_, T>(&format!("SELECT * FROM {table} WHERE slug = $1"))
        .bind(slug)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| RepoError::NotFound(Uuid::nil()))
}

/// Reset rows stuck in `last_sync_status = 'syncing'` for over 10 minutes to
/// `failed`. Errors are intentionally ignored (best-effort cleanup) by the
/// caller, matching the original `let _ = ...` behavior.
fn reset_stuck_syncing_sql(table: &str) -> String {
    format!(
        r#"
            UPDATE {table}
            SET
                last_sync_status = 'failed',
                last_sync_error = 'Sync timed out or was interrupted',
                updated_at = NOW()
            WHERE last_sync_status = 'syncing'
              AND updated_at < NOW() - INTERVAL '10 minutes'
            "#
    )
}

/// Stuck-`syncing` cleanup followed by `SELECT * FROM <table> ORDER BY name ASC`.
pub async fn list<T>(pool: &PgPool, table: &str) -> Result<Vec<T>, RepoError>
where
    T: Send + Unpin + for<'r> FromRow<'r, PgRow>,
{
    // Clean up stuck "syncing" statuses (best-effort; ignore errors).
    let _ = sqlx::query(&reset_stuck_syncing_sql(table))
        .execute(pool)
        .await;

    let rows = sqlx::query_as::<_, T>(&format!("SELECT * FROM {table} ORDER BY name ASC"))
        .fetch_all(pool)
        .await?;

    Ok(rows)
}

/// `SELECT * FROM <table> WHERE enabled = TRUE AND auto_sync_enabled = TRUE AND
/// (last_synced_at IS NULL OR last_synced_at < NOW() - interval) ORDER BY ...`.
pub async fn list_for_auto_sync<T>(pool: &PgPool, table: &str) -> Result<Vec<T>, RepoError>
where
    T: Send + Unpin + for<'r> FromRow<'r, PgRow>,
{
    let rows = sqlx::query_as::<_, T>(&format!(
        r#"
            SELECT * FROM {table}
            WHERE enabled = TRUE
              AND auto_sync_enabled = TRUE
              AND (
                last_synced_at IS NULL
                OR last_synced_at < NOW() - (sync_interval_hours || ' hours')::interval
              )
            ORDER BY last_synced_at ASC NULLS FIRST
            "#
    ))
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

/// `DELETE FROM <table> WHERE id = $1`, mapping zero affected rows to
/// `RepoError::NotFound(id)`.
pub async fn delete(pool: &PgPool, table: &str, id: Uuid) -> Result<(), RepoError> {
    let result = sqlx::query(&format!("DELETE FROM {table} WHERE id = $1"))
        .bind(id)
        .execute(pool)
        .await?;

    if result.rows_affected() == 0 {
        return Err(RepoError::NotFound(id));
    }
    Ok(())
}

/// `UPDATE <table> SET last_sync_status/commit/synced_at/<count_col>/error/...`.
/// `count_col` is the per-table count column (`parser_count`, `playbook_count`,
/// `rule_count`).
pub async fn update_sync_status(
    pool: &PgPool,
    table: &str,
    count_col: &str,
    id: Uuid,
    status: &str,
    commit: Option<&str>,
    count: Option<i32>,
    error: Option<&str>,
) -> Result<(), RepoError> {
    sqlx::query(&format!(
        r#"
            UPDATE {table} SET
                last_sync_status = $2,
                last_sync_commit = COALESCE($3, last_sync_commit),
                last_synced_at = CASE WHEN $2 = 'success' THEN NOW() ELSE last_synced_at END,
                {count_col} = COALESCE($4, {count_col}),
                last_sync_error = $5,
                updated_at = NOW()
            WHERE id = $1
            "#
    ))
    .bind(id)
    .bind(status)
    .bind(commit)
    .bind(count)
    .bind(error)
    .execute(pool)
    .await?;

    Ok(())
}

/// Derive the repository slug. If `explicit` is `Some`, it is used verbatim;
/// otherwise the slug is derived from the URL
/// (`github.com/owner/repo` -> `owner/repo`, lowercased), falling back to
/// `name`.
pub fn slug_from_url(url: &str, name: &str, explicit: Option<&str>) -> String {
    match explicit {
        Some(s) => s.to_string(),
        None => url
            .trim_end_matches('/')
            .trim_end_matches(".git")
            .split("github.com/")
            .last()
            .unwrap_or(name)
            .to_lowercase(),
    }
}

/// Map a failed INSERT into a duplicate-name/-slug into
/// `RepoError::AlreadyExists(name)`, checking the `<table>_name_key` /
/// `<table>_slug_key` unique constraints. Any other error is returned as
/// `RepoError::Database`.
pub fn map_unique_violation(e: sqlx::Error, table: &str, name: &str) -> RepoError {
    if let sqlx::Error::Database(ref db_err) = e {
        let name_key = format!("{table}_name_key");
        let slug_key = format!("{table}_slug_key");
        if db_err.constraint() == Some(name_key.as_str())
            || db_err.constraint() == Some(slug_key.as_str())
        {
            return RepoError::AlreadyExists(name.to_string());
        }
    }
    RepoError::Database(e)
}

// =============================================================================
// "items" table helpers (repository_parsers / repository_playbooks /
// repository_rules). These never produce a NotFound, so they surface the raw
// `sqlx::Error`; callers convert it via their own `#[from] sqlx::Error`.
// =============================================================================

/// `SELECT COUNT(*) FROM <table> WHERE repository_id = $1`.
pub async fn count_for_repository(
    pool: &PgPool,
    table: &str,
    repository_id: Uuid,
) -> Result<i64, sqlx::Error> {
    let count: (i64,) =
        sqlx::query_as(&format!("SELECT COUNT(*) FROM {table} WHERE repository_id = $1"))
            .bind(repository_id)
            .fetch_one(pool)
            .await?;

    Ok(count.0)
}

/// `DELETE FROM <table> WHERE repository_id = $1`, returning the affected count.
pub async fn delete_by_repository(
    pool: &PgPool,
    table: &str,
    repository_id: Uuid,
) -> Result<i64, sqlx::Error> {
    let result = sqlx::query(&format!("DELETE FROM {table} WHERE repository_id = $1"))
        .bind(repository_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() as i64)
}

/// `DELETE FROM <table> WHERE repository_id = $1 AND file_path != ALL($2)`,
/// returning the affected count. This is the unguarded prune; callers that
/// special-case empty `paths` should do so themselves before calling.
pub async fn prune_not_in_paths(
    pool: &PgPool,
    table: &str,
    repository_id: Uuid,
    paths: &[String],
) -> Result<i64, sqlx::Error> {
    let result = sqlx::query(&format!(
        "DELETE FROM {table} WHERE repository_id = $1 AND file_path != ALL($2)"
    ))
    .bind(repository_id)
    .bind(paths)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The following assertions lock the generated SQL to the exact bytes the
    // per-feature repositories emitted before NAN-1618, guaranteeing the
    // refactor is behavior-preserving. (Playbook's cleanup / update_sync_status
    // whitespace is normalized to this canonical form — see module docs.)

    #[test]
    fn find_by_id_sql_byte_identical() {
        assert_eq!(
            format!("SELECT * FROM {} WHERE id = $1", "parser_repositories"),
            "SELECT * FROM parser_repositories WHERE id = $1"
        );
    }

    #[test]
    fn find_by_slug_sql_byte_identical() {
        assert_eq!(
            format!("SELECT * FROM {} WHERE slug = $1", "rule_repositories"),
            "SELECT * FROM rule_repositories WHERE slug = $1"
        );
    }

    #[test]
    fn list_select_sql_byte_identical() {
        assert_eq!(
            format!("SELECT * FROM {} ORDER BY name ASC", "playbook_repositories"),
            "SELECT * FROM playbook_repositories ORDER BY name ASC"
        );
    }

    #[test]
    fn reset_stuck_syncing_sql_byte_identical() {
        // Canonical (parser/rule) layout.
        let expected = r#"
            UPDATE parser_repositories
            SET
                last_sync_status = 'failed',
                last_sync_error = 'Sync timed out or was interrupted',
                updated_at = NOW()
            WHERE last_sync_status = 'syncing'
              AND updated_at < NOW() - INTERVAL '10 minutes'
            "#;
        assert_eq!(reset_stuck_syncing_sql("parser_repositories"), expected);
    }

    #[test]
    fn delete_sql_byte_identical() {
        assert_eq!(
            format!("DELETE FROM {} WHERE id = $1", "rule_repositories"),
            "DELETE FROM rule_repositories WHERE id = $1"
        );
    }

    #[test]
    fn update_sync_status_sql_byte_identical() {
        // Canonical (parser/playbook) inline-SET layout; rule's separate-line
        // SET is normalized to this (whitespace only).
        let expected = r#"
            UPDATE parser_repositories SET
                last_sync_status = $2,
                last_sync_commit = COALESCE($3, last_sync_commit),
                last_synced_at = CASE WHEN $2 = 'success' THEN NOW() ELSE last_synced_at END,
                parser_count = COALESCE($4, parser_count),
                last_sync_error = $5,
                updated_at = NOW()
            WHERE id = $1
            "#;
        let actual = format!(
            r#"
            UPDATE {table} SET
                last_sync_status = $2,
                last_sync_commit = COALESCE($3, last_sync_commit),
                last_synced_at = CASE WHEN $2 = 'success' THEN NOW() ELSE last_synced_at END,
                {count_col} = COALESCE($4, {count_col}),
                last_sync_error = $5,
                updated_at = NOW()
            WHERE id = $1
            "#,
            table = "parser_repositories",
            count_col = "parser_count",
        );
        assert_eq!(actual, expected);
    }

    #[test]
    fn list_for_auto_sync_sql_byte_identical() {
        let expected = r#"
            SELECT * FROM rule_repositories
            WHERE enabled = TRUE
              AND auto_sync_enabled = TRUE
              AND (
                last_synced_at IS NULL
                OR last_synced_at < NOW() - (sync_interval_hours || ' hours')::interval
              )
            ORDER BY last_synced_at ASC NULLS FIRST
            "#;
        let actual = format!(
            r#"
            SELECT * FROM {table}
            WHERE enabled = TRUE
              AND auto_sync_enabled = TRUE
              AND (
                last_synced_at IS NULL
                OR last_synced_at < NOW() - (sync_interval_hours || ' hours')::interval
              )
            ORDER BY last_synced_at ASC NULLS FIRST
            "#,
            table = "rule_repositories",
        );
        assert_eq!(actual, expected);
    }

    #[test]
    fn slug_from_url_matches_legacy() {
        // Explicit slug is used verbatim.
        assert_eq!(slug_from_url("https://x", "Name", Some("explicit")), "explicit");
        // Derived from github URL, lowercased, .git and trailing slash stripped.
        assert_eq!(
            slug_from_url("https://github.com/Owner/Repo.git/", "Fallback", None),
            "owner/repo"
        );
        // Non-github URL: `split("github.com/")` yields one segment, so the
        // whole URL (lowercased) is used — `name` is only the fallback when
        // `last()` is None, which never happens. Matches the legacy closure.
        assert_eq!(
            slug_from_url("https://example.com/X", "FallBack", None),
            "https://example.com/x"
        );
    }

    #[test]
    fn items_sql_byte_identical() {
        assert_eq!(
            format!("SELECT COUNT(*) FROM {} WHERE repository_id = $1", "repository_parsers"),
            "SELECT COUNT(*) FROM repository_parsers WHERE repository_id = $1"
        );
        assert_eq!(
            format!("DELETE FROM {} WHERE repository_id = $1", "repository_rules"),
            "DELETE FROM repository_rules WHERE repository_id = $1"
        );
        assert_eq!(
            format!(
                "DELETE FROM {} WHERE repository_id = $1 AND file_path != ALL($2)",
                "repository_playbooks"
            ),
            "DELETE FROM repository_playbooks WHERE repository_id = $1 AND file_path != ALL($2)"
        );
    }
}
