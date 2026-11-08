// SPDX-License-Identifier: AGPL-3.0-or-later

//! Every install follows the first-party content catalogs (NAN-4940, a port
//! of main's NAN-3758 / NAN-3897 without the hosted platform mirror).
//!
//! The open edition ships no parser or rule content: every install pulls it
//! from `nano-rs/parsers` and `nano-rs/rules` straight from GitHub through the
//! existing repository sync path.
//!
//! [`ensure_first_party_catalogs`] runs from the leader's repository sync
//! schedulers on every start, so it covers a first boot and an upgrade. The
//! target branch is the active schema profile's content channel
//! ([`crate::schema::content_branch_for`]): OCSF follows `main`, UDM follows
//! the frozen `legacy/clickhouse` branch.
//!
//! * **Missing** catalog row, not yet adopted: registered at the content
//!   branch with auto-sync on and an hourly cadence, so the schedulers sync it
//!   straight away and the full catalog is there at first login.
//! * **Existing, enabled** row on another first-party channel (`main`,
//!   `legacy/clickhouse`, the retired `ocsf-1.9`) or an empty branch: moved to
//!   the content branch. Auto-sync off on a not-yet-adopted row (the old
//!   one-click add created rows with it off): switched on. Either change
//!   clears `last_synced_at` / `last_sync_commit` so the row is due on the
//!   next scheduler pass.
//! * **Disabled** row (`enabled = false`): the operator's opt-out. Left alone.
//! * Any other branch (an explicit pin or fork branch): kept.
//!
//! Adoption (`first_party_content_catalogs`, migration 302) is recorded the
//! first time the reconcile registers or adopts a catalog. After that the
//! operator owns it: a deleted catalog is NOT re-created and auto-sync turned
//! off is NOT turned back on. (Main re-created deleted rows and re-enabled
//! auto-sync on every start, and its UI exposes neither `enabled` nor any
//! other opt-out, so those were the only ways to stop following.)
//!
//! Syncing only refreshes the catalog (`repository_parsers` /
//! `repository_rules`). Nothing is imported, enabled or promoted
//! automatically, and an upstream change to content the operator already
//! imported only flags it `upstream_changed`: customised parsers and rules are
//! never overwritten.
//!
//! The same reconcile is generic over [`CatalogSpec`]: the enterprise overlay
//! registers `nano-rs/playbooks` through [`ensure_catalog`] (NAN-4947) with
//! the same adoption marker and opt-out rules, without this open module
//! naming the enterprise table.
//!
//! Air-gapped installs (`AIRGAP_MODE`) never call this: their egress
//! schedulers do not start. An install that is merely offline registers the
//! rows and every failed pull is recorded on the row. Neither ever blocks boot.

use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::schema::SchemaId;

/// Hourly cadence for registered first-party catalogs. An unchanged rule
/// catalog costs one GitHub API call per check, a parser catalog three.
pub const FIRST_PARTY_SYNC_INTERVAL_HOURS: i32 = 1;

/// Serializes concurrent reconciles (parser and rule schedulers, replicas).
const RECONCILE_LOCK_KEY: i64 = 0x6e61_6e6f_3735_38;

/// One first-party catalog the reconcile follows: which repository, which
/// repository table, and how a fresh row is registered (NAN-4947: generic, so
/// the enterprise overlay registers `nano-rs/playbooks` through the same
/// reconcile without the open core naming it).
#[derive(Debug, PartialEq, Eq)]
pub struct CatalogSpec {
    key: &'static str,
    repo: &'static str,
    name: &'static str,
    description: &'static str,
    table: &'static str,
    insert_sql: &'static str,
    sync_interval_hours: i32,
}

impl CatalogSpec {
    /// A catalog definition.
    ///
    /// * `key`: the `first_party_content_catalogs.catalog` value (the column's
    ///   CHECK must admit it).
    /// * `repo`: lowercase `owner/repo` on github.com.
    /// * `insert_sql`: one `INSERT INTO <table> ... ON CONFLICT DO NOTHING
    ///   RETURNING id` binding `$1` name, `$2` slug, `$3` description, `$4`
    ///   url, `$5` branch and `$6` sync interval (hours), with auto-sync on.
    pub const fn new(
        key: &'static str,
        repo: &'static str,
        name: &'static str,
        description: &'static str,
        table: &'static str,
        insert_sql: &'static str,
        sync_interval_hours: i32,
    ) -> Self {
        Self { key, repo, name, description, table, insert_sql, sync_interval_hours }
    }

    /// Canonical `https://github.com/<repo>` URL a fresh row is registered at.
    pub fn url(&self) -> String {
        format!("https://github.com/{}", self.repo)
    }

    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// Key in `first_party_content_catalogs`.
    pub const fn key(&self) -> &'static str {
        self.key
    }

    pub const fn table(&self) -> &'static str {
        self.table
    }

    pub const fn sync_interval_hours(&self) -> i32 {
        self.sync_interval_hours
    }

    /// Whether a stored repository URL is this catalog (scheme, `www.`, case,
    /// `.git` and a trailing slash ignored; credentials, ports, queries and
    /// fragments never match).
    pub fn matches_url(&self, url: &str) -> bool {
        crate::schema::github_repo_path(url).as_deref() == Some(self.repo)
    }
}

static PARSERS: CatalogSpec = CatalogSpec::new(
    "parsers",
    "nano-rs/parsers",
    "nano parsers",
    "Official nano parsers for common log sources",
    "parser_repositories",
    "INSERT INTO parser_repositories (name, slug, description, url, branch, parsers_path, \
        auto_sync_enabled, sync_interval_hours) \
     VALUES ($1,$2,$3,$4,$5,'parsers/',TRUE,$6) ON CONFLICT DO NOTHING RETURNING id",
    FIRST_PARTY_SYNC_INTERVAL_HOURS,
);

// Native nPL rules at the repository root, like the one-click add.
static RULES: CatalogSpec = CatalogSpec::new(
    "rules",
    "nano-rs/rules",
    "nano rules",
    "Official nano detection rules in native nPL format",
    "rule_repositories",
    "INSERT INTO rule_repositories (name, slug, description, url, branch, rules_path, rule_format, \
        auto_sync_enabled, sync_interval_hours) \
     VALUES ($1,$2,$3,$4,$5,'','nanosiem',TRUE,$6) ON CONFLICT DO NOTHING RETURNING id",
    FIRST_PARTY_SYNC_INTERVAL_HOURS,
);

/// NAN-4947 (11-03 decision): every parser, rule and playbook repository is a
/// nano first-party source. A repository row is admissible only when its URL
/// is one of the `allowed` first-party GitHub repositories (`owner/repo`,
/// matched like [`CatalogSpec::matches_url`]) or the synthetic repository
/// signed air-gap bundles are applied to (`airgap_url`, e.g.
/// `airgap://rules`). Anything else (SigmaHQ, forks, customer repositories)
/// is refused on create, update, sync, browse and import, and hidden from
/// listings; migration 305 / 9000085 disabled such rows on upgrade.
pub fn is_allowed_repository(url: &str, allowed: &[&str], airgap_url: &str) -> bool {
    url.trim() == airgap_url
        || crate::schema::github_repo_path(url).is_some_and(|path| allowed.contains(&path.as_str()))
}

/// The open edition's first-party catalogs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirstPartyCatalog {
    Parsers,
    Rules,
}

impl FirstPartyCatalog {
    pub const ALL: [Self; 2] = [Self::Parsers, Self::Rules];

    pub fn spec(self) -> &'static CatalogSpec {
        match self {
            Self::Parsers => &PARSERS,
            Self::Rules => &RULES,
        }
    }

    pub fn url(self) -> String {
        self.spec().url()
    }

    pub fn name(self) -> &'static str {
        self.spec().name()
    }

    /// Key in `first_party_content_catalogs`.
    pub fn key(self) -> &'static str {
        self.spec().key()
    }

    /// The first-party catalog a repository URL names, if any.
    pub fn from_url(url: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|catalog| catalog.matches_url(url))
    }

    /// Whether a stored repository URL is this first-party catalog.
    pub fn matches_url(self, url: &str) -> bool {
        self.spec().matches_url(url)
    }
}

/// The stored state of an existing catalog row that the reconcile reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExistingCatalog {
    pub id: Uuid,
    pub name: String,
    pub branch: String,
    pub enabled: bool,
    pub auto_sync_enabled: bool,
}

/// What the reconcile does for one catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogPlan {
    Create { branch: String },
    /// Move the branch and/or switch auto-sync on.
    Update { id: Uuid, branch: Option<String>, enable_auto_sync: bool },
    Current(Uuid),
    Disabled(Uuid),
    /// Adopted earlier and since deleted by the operator: not re-created.
    Removed,
}

/// Pure reconcile decision, given the target content branch for this install
/// and whether the catalog was already adopted (see the module docs).
pub fn plan(existing: Option<&ExistingCatalog>, target_branch: &str, adopted: bool) -> CatalogPlan {
    let Some(row) = existing else {
        return if adopted {
            CatalogPlan::Removed
        } else {
            CatalogPlan::Create { branch: target_branch.to_owned() }
        };
    };
    if !row.enabled {
        return CatalogPlan::Disabled(row.id);
    }
    let stored = row.branch.trim();
    let branch = (crate::schema::is_known_content_channel(stored) && stored != target_branch)
        .then(|| target_branch.to_owned());
    let enable_auto_sync = !adopted && !row.auto_sync_enabled;
    if branch.is_none() && !enable_auto_sync {
        return CatalogPlan::Current(row.id);
    }
    CatalogPlan::Update { id: row.id, branch, enable_auto_sync }
}

/// One reconciled catalog, for logging and audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogReconcile {
    pub catalog: &'static CatalogSpec,
    /// `None` only for [`CatalogPlan::Removed`].
    pub repository_id: Option<Uuid>,
    pub name: String,
    pub plan: CatalogPlan,
    pub previous_branch: Option<String>,
}

impl CatalogReconcile {
    /// Whether the reconcile changed anything (and so must be audited).
    pub fn changed(&self) -> bool {
        matches!(self.plan, CatalogPlan::Create { .. } | CatalogPlan::Update { .. })
    }

    pub fn audit_details(&self) -> serde_json::Value {
        let mut details = serde_json::json!({
            "automatic": true,
            "issue": "NAN-4940",
            "catalog": self.catalog.key(),
            "url": self.catalog.url(),
        });
        match &self.plan {
            CatalogPlan::Create { branch } => {
                details["branch"] = branch.clone().into();
                details["auto_sync_enabled"] = true.into();
                details["sync_interval_hours"] = self.catalog.sync_interval_hours().into();
            }
            CatalogPlan::Update { branch, enable_auto_sync, .. } => {
                if let Some(branch) = branch {
                    details["branch"] = branch.clone().into();
                    details["previous_branch"] = self.previous_branch.clone().into();
                }
                if *enable_auto_sync {
                    details["auto_sync_enabled"] = true.into();
                }
            }
            CatalogPlan::Current(_) | CatalogPlan::Disabled(_) | CatalogPlan::Removed => {}
        }
        details
    }
}

/// Register or reconcile both first-party catalogs for the given schema
/// profile. Idempotent and safe to run concurrently. Never touches GitHub.
pub async fn ensure_first_party_catalogs(
    pool: &PgPool,
    profile: SchemaId,
) -> Result<Vec<CatalogReconcile>, sqlx::Error> {
    let target = crate::schema::content_branch_for(profile);
    let mut tx = pool.begin().await?;
    lock_first_party_catalogs(&mut tx).await?;
    let mut outcomes = Vec::with_capacity(FirstPartyCatalog::ALL.len());
    for catalog in FirstPartyCatalog::ALL {
        outcomes.push(reconcile_one(&mut tx, catalog.spec(), target).await?);
    }
    tx.commit().await?;
    Ok(outcomes)
}

/// Register or reconcile one first-party catalog at `target_branch`, under the
/// same lock and adoption rules as [`ensure_first_party_catalogs`]. The entry
/// point for a catalog the open edition does not ship (NAN-4947: the
/// enterprise overlay's `nano-rs/playbooks`); the caller's schema must admit
/// `spec.key()` in `first_party_content_catalogs`.
pub async fn ensure_catalog(
    pool: &PgPool,
    spec: &'static CatalogSpec,
    target_branch: &str,
) -> Result<CatalogReconcile, sqlx::Error> {
    let mut tx = pool.begin().await?;
    lock_first_party_catalogs(&mut tx).await?;
    let outcome = reconcile_one(&mut tx, spec, target_branch).await?;
    tx.commit().await?;
    Ok(outcome)
}

/// Take the transaction-scoped lock that serializes every write that can
/// register a first-party catalog: the boot reconcile and the repository create
/// APIs (codex review of NAN-4940). Without it a concurrent API create and the
/// reconcile could each see no catalog and both insert one.
pub async fn lock_first_party_catalogs(tx: &mut Transaction<'_, Postgres>) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock($1)").bind(RECONCILE_LOCK_KEY).execute(&mut **tx).await?;
    Ok(())
}

/// The stored row of a first-party catalog, locked `FOR UPDATE`. When the
/// operator registered it twice (possible only before migration 302), an
/// enabled row wins, then the oldest.
pub async fn find_first_party_catalog(
    tx: &mut Transaction<'_, Postgres>,
    catalog: &CatalogSpec,
) -> Result<Option<ExistingCatalog>, sqlx::Error> {
    let rows: Vec<(Uuid, String, String, String, bool, bool)> = sqlx::query_as(&format!(
        "SELECT id, name, url, branch, COALESCE(enabled, TRUE), COALESCE(auto_sync_enabled, FALSE) \
         FROM {} ORDER BY created_at, id FOR UPDATE",
        catalog.table()
    ))
    .fetch_all(&mut **tx)
    .await?;
    let mut matches: Vec<ExistingCatalog> = rows
        .into_iter()
        .filter(|(_, _, url, ..)| catalog.matches_url(url))
        .map(|(id, name, _, branch, enabled, auto_sync_enabled)| ExistingCatalog {
            id,
            name,
            branch,
            enabled,
            auto_sync_enabled,
        })
        .collect();
    Ok(match matches.iter().position(|row| row.enabled) {
        Some(index) => Some(matches.swap_remove(index)),
        None => matches.into_iter().next(),
    })
}

async fn reconcile_one(
    tx: &mut Transaction<'_, Postgres>,
    catalog: &'static CatalogSpec,
    target: &str,
) -> Result<CatalogReconcile, sqlx::Error> {
    let table = catalog.table();
    let adopted: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM first_party_content_catalogs WHERE catalog = $1)",
    )
    .bind(catalog.key())
    .fetch_one(&mut **tx)
    .await?;
    let mut existing = find_first_party_catalog(tx, catalog).await?;
    let mut plan = plan(existing.as_ref(), target, adopted);
    let (repository_id, name) = match &plan {
        CatalogPlan::Create { branch } => match insert_catalog(tx, catalog, branch).await? {
            InsertOutcome::Inserted(id) => (Some(id), catalog.name().to_owned()),
            // Registered concurrently by a writer that did not hold the lock
            // (an older replica): adopt that row as the operator left it
            // rather than registering a second copy.
            InsertOutcome::Existing(row) => {
                plan = if row.enabled { CatalogPlan::Current(row.id) } else { CatalogPlan::Disabled(row.id) };
                let adopted_row = (Some(row.id), row.name.clone());
                existing = Some(row);
                adopted_row
            }
        },
        CatalogPlan::Update { id, branch, enable_auto_sync } => {
            sqlx::query(&format!(
                "UPDATE {table} SET branch = COALESCE($2, branch), \
                    auto_sync_enabled = COALESCE(auto_sync_enabled, FALSE) OR $3, \
                    last_synced_at = NULL, last_sync_commit = NULL, updated_at = NOW() WHERE id = $1"
            ))
            .bind(id)
            .bind(branch.as_deref())
            .bind(*enable_auto_sync)
            .execute(&mut **tx)
            .await?;
            (Some(*id), existing.as_ref().map(|row| row.name.clone()).unwrap_or_default())
        }
        CatalogPlan::Current(id) | CatalogPlan::Disabled(id) => {
            (Some(*id), existing.as_ref().map(|row| row.name.clone()).unwrap_or_default())
        }
        CatalogPlan::Removed => (None, catalog.name().to_owned()),
    };
    // NAN-4947: the stored URL is the canonical spelling the sync parses
    // (`https://github.com/<owner>/<repo>`), whatever form an older build or
    // the operator stored (`www.`, `.git`, case, trailing slash).
    if let Some(id) = repository_id {
        sqlx::query(&format!("UPDATE {table} SET url = $2, updated_at = NOW() WHERE id = $1 AND url <> $2"))
            .bind(id)
            .bind(catalog.url())
            .execute(&mut **tx)
            .await?;
    }
    if !adopted {
        sqlx::query(
            "INSERT INTO first_party_content_catalogs (catalog, repository_id) VALUES ($1, $2) \
             ON CONFLICT (catalog) DO NOTHING",
        )
        .bind(catalog.key())
        .bind(repository_id)
        .execute(&mut **tx)
        .await?;
    }
    Ok(CatalogReconcile {
        catalog,
        repository_id,
        name,
        plan,
        previous_branch: existing.map(|row| row.branch),
    })
}

/// Result of registering a catalog row.
enum InsertOutcome {
    Inserted(Uuid),
    /// The catalog already exists (it committed after this transaction's read).
    Existing(ExistingCatalog),
}

/// Insert the catalog row. `name`, `slug` and (migration 302) the normalized
/// first-party URL are unique. After any conflict the catalog is looked up by
/// URL first and adopted if present; only when an UNRELATED repository holds
/// the default name is the row registered under a `(nano-rs)` suffix, instead
/// of failing the reconcile on every start.
async fn insert_catalog(
    tx: &mut Transaction<'_, Postgres>,
    catalog: &CatalogSpec,
    branch: &str,
) -> Result<InsertOutcome, sqlx::Error> {
    let fallback_name = format!("{} (nano-rs)", catalog.name());
    for name in [catalog.name(), fallback_name.as_str()] {
        let explicit_slug = (name != catalog.name()).then(|| format!("nano-rs-{}", catalog.key()));
        let url = catalog.url();
        let slug = crate::db::repo_store::slug_from_url(&url, name, explicit_slug.as_deref());
        let id: Option<Uuid> = sqlx::query_scalar(catalog.insert_sql)
            .bind(name)
            .bind(&slug)
            .bind(catalog.description)
            .bind(&url)
            .bind(branch)
            .bind(catalog.sync_interval_hours)
            .fetch_optional(&mut **tx)
            .await?;
        if let Some(id) = id {
            return Ok(InsertOutcome::Inserted(id));
        }
        if let Some(row) = find_first_party_catalog(tx, catalog).await? {
            return Ok(InsertOutcome::Existing(row));
        }
    }
    Err(sqlx::Error::Protocol(format!(
        "first-party catalog {}: name and slug taken by other repositories",
        catalog.url()
    )))
}
