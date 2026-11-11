// SPDX-License-Identifier: AGPL-3.0-or-later

//! PostgreSQL compatibility preflight (NAN-5260).
//!
//! Runs before the migrator applies anything. Managed PostgreSQL services
//! (AWS RDS, Google Cloud SQL, Azure Database for PostgreSQL flexible server)
//! fail a fresh install part-way through the open-init snapshot when the
//! server is too old or an extension is not allow-listed, leaving every app
//! pod in `Init:Error` with a raw SQL error. This check turns both cases into
//! one actionable message before any DDL runs.
//!
//! It also checks that the connected role can `CREATE` in schema `public`.
//! PostgreSQL 15+ no longer grants that to every role, and Azure flexible
//! server makes `azure_pg_admin` (not the database owner) the owner of
//! `public` in new databases, so the snapshot failed with "permission denied
//! for schema public" after every other check had passed (NAN-5269).
//!
//! The extension probe is side-effect free: every `CREATE EXTENSION` runs
//! inside a transaction that is always rolled back, so it tests the real
//! permission and allow-list path without installing anything.

use sqlx::PgPool;
use thiserror::Error;

/// Lowest PostgreSQL major version the migrations and runtime SQL are tested
/// against, as a `server_version_num` value.
///
/// The open-init snapshot, every post-baseline migration and the enterprise
/// overlay apply cleanly on 16, 17 and 18 (NAN-5260). Cloud SQL and RDS may
/// create 16 by default, so it is the floor customers hit first. Installs still
/// on 15 or older are refused before any DDL and must upgrade PostgreSQL first.
pub const MIN_POSTGRES_VERSION_NUM: i32 = 160_000;

/// Human-readable form of [`MIN_POSTGRES_VERSION_NUM`] for messages.
pub const MIN_POSTGRES_VERSION: &str = "16";

/// Every extension the PostgreSQL migrations create (open and enterprise).
///
/// - `pg_trgm`   — trigram GIN indexes for substring search over metadata.
/// - `pgcrypto`  — `gen_random_bytes` / `digest` in defaults and backfills.
/// - `uuid-ossp` — `uuid_generate_v4()` column defaults.
///
/// All three are "trusted" extensions (PostgreSQL 13+), so any role with
/// `CREATE` on the database can install them once the managed service
/// allows them. `postgres_preflight_tests` fails if a migration starts
/// creating an extension that is not listed here.
pub const REQUIRED_POSTGRES_EXTENSIONS: &[&str] = &["pg_trgm", "pgcrypto", "uuid-ossp"];

/// Managed PostgreSQL service the preflight detected, used only to put the
/// relevant fix first in the error message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostgresPlatform {
    AzureFlexibleServer,
    CloudSql,
    Rds,
    Other,
}

impl PostgresPlatform {
    fn label(self) -> &'static str {
        match self {
            Self::AzureFlexibleServer => "Azure Database for PostgreSQL flexible server",
            Self::CloudSql => "Google Cloud SQL for PostgreSQL",
            Self::Rds => "Amazon RDS / Aurora PostgreSQL",
            Self::Other => "PostgreSQL",
        }
    }
}

/// One extension that could not be created, with the server's reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingExtension {
    pub name: String,
    pub reason: String,
}

#[derive(Debug, Error)]
pub enum PostgresPreflightError {
    #[error("PostgreSQL preflight query failed: {0}")]
    Query(#[from] sqlx::Error),

    #[error(
        "PostgreSQL {found} is not supported: nano requires PostgreSQL {min} or newer. \
         Upgrade the server (or create a new {min}+ instance) before installing."
    )]
    UnsupportedVersion { found: String, min: &'static str },

    #[error("{}", schema_create_message(.platform, .access))]
    NoCreateOnPublicSchema {
        platform: PostgresPlatform,
        access: PublicSchemaAccess,
    },

    #[error("{}", missing_extensions_message(.platform, .missing))]
    MissingExtensions {
        platform: PostgresPlatform,
        missing: Vec<MissingExtension>,
    },
}

/// What the connected role can do in schema `public`, as the server reports it.
/// Identifiers are already quoted with `quote_ident`, ready to paste into SQL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicSchemaAccess {
    pub user: String,
    pub database: String,
    /// `None` when schema `public` does not exist in the database.
    pub owner: Option<String>,
    pub can_create: bool,
}

/// Builds the operator-facing message for [`PostgresPreflightError::NoCreateOnPublicSchema`].
pub fn schema_create_message(platform: &PostgresPlatform, access: &PublicSchemaAccess) -> String {
    let user = &access.user;
    let db = &access.database;
    let admin = match platform {
        PostgresPlatform::AzureFlexibleServer => "the server admin user",
        PostgresPlatform::CloudSql => "the `postgres` user",
        PostgresPlatform::Rds => "the master user",
        PostgresPlatform::Other => "a superuser or the schema owner",
    };
    match &access.owner {
        None => format!(
            "PostgreSQL preflight failed on {}: database {db} has no schema `public`, and nano \
             creates its tables there. Nothing was applied.\n\
             Fix: as {admin}, connected to database {db}, run:\n  \
             CREATE SCHEMA public AUTHORIZATION {user};\n\
             then rerun.",
            platform.label(),
        ),
        Some(owner) => format!(
            "PostgreSQL preflight failed on {}: the database user {user} cannot create objects in \
             schema `public` of database {db} (schema owner: {owner}). PostgreSQL 15 and newer no \
             longer let every role create in `public`, and Azure flexible server makes \
             azure_pg_admin its owner in new databases. Nothing was applied.\n\
             Fix: as {admin}, connected to database {db}, run:\n  \
             ALTER SCHEMA public OWNER TO {user};\n\
             or, to leave the owner as it is:\n  \
             GRANT ALL ON SCHEMA public TO {user};\n\
             then rerun. (ALTER SCHEMA ... OWNER needs the admin to be a member of {user}: \
             GRANT {user} TO <admin>.)",
            platform.label(),
        ),
    }
}

/// Builds the operator-facing message for [`PostgresPreflightError::MissingExtensions`].
pub fn missing_extensions_message(
    platform: &PostgresPlatform,
    missing: &[MissingExtension],
) -> String {
    let names: Vec<&str> = missing.iter().map(|m| m.name.as_str()).collect();
    let all = REQUIRED_POSTGRES_EXTENSIONS.join(",");
    let mut msg = format!(
        "PostgreSQL preflight failed on {}: the database user cannot create required \
         extension(s): {}. nano needs: {}. Nothing was applied.\n",
        platform.label(),
        names.join(", "),
        REQUIRED_POSTGRES_EXTENSIONS.join(", "),
    );
    for m in missing {
        msg.push_str(&format!("  - {}: {}\n", m.name, m.reason));
    }
    let azure = format!(
        "Azure flexible server: add the extensions to the `azure.extensions` server parameter \
         (az postgres flexible-server parameter set --name azure.extensions --value <existing>,{all} ...; append to the current value), \
         then rerun. No restart is needed."
    );
    let cloud_sql = "Google Cloud SQL: these extensions need no database flags; connect as a \
                     user with the cloudsqlsuperuser role (the default `postgres` user, or any \
                     user created with `gcloud sql users create`) that has CREATE on the database; roles \
                     created with CREATE ROLE in SQL cannot create extensions."
        .to_string();
    let rds = format!(
        "Amazon RDS: if the parameter group sets `rds.allowed_extensions`, include {all} \
         (the default `*` allows them); the user needs CREATE on the database."
    );
    let generic = "Self-managed PostgreSQL: install the contrib package (postgresql-contrib) \
                   and grant the nano user CREATE on the database, or pre-create the \
                   extensions as a superuser."
        .to_string();
    let mut fixes = vec![azure, cloud_sql, rds, generic];
    let first = match platform {
        PostgresPlatform::AzureFlexibleServer => 0,
        PostgresPlatform::CloudSql => 1,
        PostgresPlatform::Rds => 2,
        PostgresPlatform::Other => 3,
    };
    let lead = fixes.remove(first);
    msg.push_str("Fix: ");
    msg.push_str(&lead);
    msg.push_str("\nOther platforms:");
    for f in fixes {
        msg.push_str("\n  * ");
        msg.push_str(&f);
    }
    msg
}

/// Result of a passing preflight, logged by the migrator.
#[derive(Debug, Clone)]
pub struct PostgresPreflightReport {
    pub server_version: String,
    pub server_version_num: i32,
    pub platform: PostgresPlatform,
    /// Required extensions that were not yet installed but can be created.
    pub creatable: Vec<String>,
    /// Set when the role lacks `CREATE` on schema `public` but no migration is
    /// pending, so nothing needs it now: the caller logs it as a warning and
    /// carries on. The next release with a new migration would fail on it.
    pub schema_warning: Option<String>,
}

/// Checks the server version, that the connected role can create objects in
/// schema `public`, and that every required extension is installed or
/// creatable by the connected role. Never changes the database.
///
/// A missing `CREATE` on `public` fails only when `migrations_pending` (a fresh
/// install, or an upgrade that brings new migrations): then the run would fail
/// part-way. With nothing to apply, a working install must keep starting, so
/// it is returned as [`PostgresPreflightReport::schema_warning`] instead.
pub async fn check_postgres_compatibility(
    pool: &PgPool,
    migrations_pending: bool,
) -> Result<PostgresPreflightReport, PostgresPreflightError> {
    let (server_version, version_num): (String, String) = sqlx::query_as(
        "SELECT current_setting('server_version'), current_setting('server_version_num')",
    )
    .fetch_one(pool)
    .await?;
    let server_version_num: i32 = version_num.trim().parse().unwrap_or(0);
    if server_version_num < MIN_POSTGRES_VERSION_NUM {
        return Err(PostgresPreflightError::UnsupportedVersion {
            found: server_version,
            min: MIN_POSTGRES_VERSION,
        });
    }

    let platform = detect_platform(pool).await?;

    // Before the extension probe: without CREATE on `public` that probe can
    // fail too, and its allow-list advice would point at the wrong fix.
    let access = public_schema_access(pool).await?;
    let mut schema_warning = None;
    if !access.can_create {
        if migrations_pending {
            return Err(PostgresPreflightError::NoCreateOnPublicSchema { platform, access });
        }
        schema_warning = Some(schema_create_message(&platform, &access).replacen(
            "PostgreSQL preflight failed",
            "PostgreSQL preflight warning (no migration pending, continuing; the next \
             release that adds a migration will stop here)",
            1,
        ));
    }

    let installed: Vec<String> = sqlx::query_scalar("SELECT extname::text FROM pg_extension")
        .fetch_all(pool)
        .await?;

    let mut tx = pool.begin().await?;
    let mut missing = Vec::new();
    let mut creatable = Vec::new();
    for ext in REQUIRED_POSTGRES_EXTENSIONS {
        if installed.iter().any(|i| i == ext) {
            continue;
        }
        sqlx::query("SAVEPOINT nano_ext_probe")
            .execute(&mut *tx)
            .await?;
        // Identifier comes from the compile-time allow-list above, never from
        // user input; quoting handles the dash in uuid-ossp.
        // WITH SCHEMA public matches the migrations exactly.
        let create = format!("CREATE EXTENSION IF NOT EXISTS \"{ext}\" WITH SCHEMA public");
        match sqlx::query(&create).execute(&mut *tx).await {
            Ok(_) => creatable.push((*ext).to_string()),
            Err(err) => missing.push(MissingExtension {
                name: (*ext).to_string(),
                reason: match &err {
                    sqlx::Error::Database(db) => db.message().to_string(),
                    other => other.to_string(),
                },
            }),
        }
        sqlx::query("ROLLBACK TO SAVEPOINT nano_ext_probe")
            .execute(&mut *tx)
            .await?;
    }
    tx.rollback().await?;

    if !missing.is_empty() {
        return Err(PostgresPreflightError::MissingExtensions { platform, missing });
    }
    Ok(PostgresPreflightReport {
        server_version,
        server_version_num,
        platform,
        creatable,
        schema_warning,
    })
}

/// Reads whether `current_user` holds CREATE on schema `public` (directly,
/// through a role, or as its owner) plus the names the fix message needs.
async fn public_schema_access(pool: &PgPool) -> Result<PublicSchemaAccess, sqlx::Error> {
    let (user, database, owner, can_create): (String, String, Option<String>, Option<bool>) =
        sqlx::query_as(
            "SELECT quote_ident(current_user::text), quote_ident(current_database()::text), \
                    (SELECT quote_ident(pg_get_userbyid(n.nspowner)::text) \
                       FROM pg_namespace n WHERE n.nspname = 'public'), \
                    (SELECT has_schema_privilege(current_user, n.oid, 'CREATE') \
                       FROM pg_namespace n WHERE n.nspname = 'public')",
        )
        .fetch_one(pool)
        .await?;
    Ok(PublicSchemaAccess {
        user,
        database,
        can_create: owner.is_some() && can_create.unwrap_or(false),
        owner,
    })
}

/// Identifies the managed service from its provider-specific admin role or
/// setting. `current_setting(name, true)` returns NULL instead of erroring
/// when the parameter does not exist; the roles are created by each service
/// on every instance.
async fn detect_platform(pool: &PgPool) -> Result<PostgresPlatform, sqlx::Error> {
    let (azure, rds, cloud_sql): (bool, bool, bool) = sqlx::query_as(
        "SELECT \
            current_setting('azure.extensions', true) IS NOT NULL \
              OR EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'azure_pg_admin'), \
            current_setting('rds.extensions', true) IS NOT NULL \
              OR EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rds_superuser'), \
            EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cloudsqlsuperuser')",
    )
    .fetch_one(pool)
    .await?;
    Ok(platform_from_markers(azure, rds, cloud_sql))
}

/// Pure mapping from the provider markers to a platform; split out for tests.
pub fn platform_from_markers(azure: bool, rds: bool, cloud_sql: bool) -> PostgresPlatform {
    if azure {
        PostgresPlatform::AzureFlexibleServer
    } else if rds {
        PostgresPlatform::Rds
    } else if cloud_sql {
        PostgresPlatform::CloudSql
    } else {
        PostgresPlatform::Other
    }
}

#[cfg(test)]
#[path = "postgres_preflight_tests.rs"]
mod tests;
