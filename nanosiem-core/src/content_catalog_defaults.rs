// SPDX-License-Identifier: AGPL-3.0-or-later

//! Open core and dedicated installs follow the first-party catalogs (NAN-3758).
//!
//! The open edition ships no parser or rule content: every install pulls it
//! from `nano-rs/parsers` and `nano-rs/rules`. Hosted-shared tenants get that
//! from the platform catalog follow (`shared_catalog_follow`). This
//! is the single-tenant equivalent, with no platform mirror: the install pulls
//! GitHub directly through the existing repository sync apply path.
//!
//! [`ensure_first_party_catalogs`] runs from the leader's repository sync
//! schedulers on every start, so it covers both a first boot and an upgrade:
//!
//! * **Missing** catalog row: registered at the content branch (`main`, which
//!   carries the OCSF 1.9 content since NAN-3897) with auto-sync on and an
//!   hourly cadence, so the schedulers sync it straight away and the full
//!   catalog is there at first login.
//! * **Existing, enabled** row on the retired `ocsf-1.9` default (NAN-3758)
//!   or an empty branch: moved to `main`. Auto-sync off: switched on, exactly
//!   like the hosted `ensure_default_catalog` reconcile. Either change clears
//!   `last_synced_at` so the row is due on the next scheduler pass.
//! * **Disabled** row: the operator's opt-out. Left alone.
//! * Any other branch (an explicit pin or fork branch): kept.
//!
//! Syncing only refreshes the catalog (`repository_parsers` /
//! `repository_rules`). As in hosted follow, nothing is imported, enabled or
//! promoted automatically, and an upstream change to content the operator
//! already imported only flags it `upstream_changed`: customised parsers and
//! rules are never overwritten.
//!
//! Air-gapped installs (`AIRGAP_MODE`) never call this: their egress
//! schedulers do not start, and the repository pages show the air-gap bundle
//! import state instead. An install that is merely offline registers the rows
//! and every failed pull is recorded on the row (`last_sync_status='failed'`
//! plus the error), which the repository pages show. Neither ever blocks boot.

use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

/// Hourly cadence for registered first-party catalogs. An unchanged rule
/// catalog costs one GitHub API call per check, a parser catalog three.
pub const FIRST_PARTY_SYNC_INTERVAL_HOURS: i32 = 1;

/// Serializes concurrent reconciles (parser and rule schedulers, replicas).
const RECONCILE_LOCK_KEY: i64 = 0x6e61_6e6f_3735_38;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirstPartyCatalog {
    Parsers,
    Rules,
}

impl FirstPartyCatalog {
    pub const ALL: [Self; 2] = [Self::Parsers, Self::Rules];

    pub const fn url(self) -> &'static str {
        match self {
            Self::Parsers => "https://github.com/nano-rs/parsers",
            Self::Rules => "https://github.com/nano-rs/rules",
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Parsers => "nano parsers",
            Self::Rules => "nano rules",
        }
    }

    const fn description(self) -> &'static str {
        match self {
            Self::Parsers => "Official nano parsers for common log sources",
            Self::Rules => "Official nano detection rules in native nPL format",
        }
    }

    const fn table(self) -> &'static str {
        match self {
            Self::Parsers => "parser_repositories",
            Self::Rules => "rule_repositories",
        }
    }

    /// Whether a stored repository URL is this first-party catalog.
    pub fn matches_url(self, url: &str) -> bool {
        crate::schema::is_first_party_content_url(url)
            && url
                .trim_end_matches('/')
                .trim_end_matches(".git")
                .to_ascii_lowercase()
                .ends_with(match self {
                    Self::Parsers => "/parsers",
                    Self::Rules => "/rules",
                })
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
}

/// Pure reconcile decision, given the target content branch for this install.
pub fn plan(existing: Option<&ExistingCatalog>, target_branch: &str) -> CatalogPlan {
    let Some(row) = existing else {
        return CatalogPlan::Create { branch: target_branch.to_owned() };
    };
    if !row.enabled {
        return CatalogPlan::Disabled(row.id);
    }
    let stored = row.branch.trim();
    let retired = stored.is_empty() || stored == crate::schema::RETIRED_OCSF_CONTENT_BRANCH;
    let branch = (retired && stored != target_branch).then(|| target_branch.to_owned());
    if branch.is_none() && row.auto_sync_enabled {
        return CatalogPlan::Current(row.id);
    }
    CatalogPlan::Update { id: row.id, branch, enable_auto_sync: !row.auto_sync_enabled }
}

/// One reconciled catalog, for logging and audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogReconcile {
    pub catalog: FirstPartyCatalog,
    pub repository_id: Uuid,
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
            // mirror-gate: wire (persisted audit detail)
            "issue": "NAN-3758",
            "url": self.catalog.url(),
        });
        match &self.plan {
            CatalogPlan::Create { branch } => {
                details["branch"] = branch.clone().into();
                details["auto_sync_enabled"] = true.into();
                details["sync_interval_hours"] = FIRST_PARTY_SYNC_INTERVAL_HOURS.into();
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
            CatalogPlan::Current(_) | CatalogPlan::Disabled(_) => {}
        }
        details
    }
}

/// Register or reconcile both first-party catalogs. Idempotent and safe to
/// run concurrently. Never touches GitHub.
pub async fn ensure_first_party_catalogs(pool: &PgPool) -> Result<Vec<CatalogReconcile>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)").bind(RECONCILE_LOCK_KEY).execute(&mut *tx).await?;
    let mut outcomes = Vec::with_capacity(FirstPartyCatalog::ALL.len());
    for catalog in FirstPartyCatalog::ALL {
        outcomes.push(reconcile_one(&mut tx, catalog).await?);
    }
    tx.commit().await?;
    Ok(outcomes)
}

async fn reconcile_one(
    tx: &mut Transaction<'_, Postgres>,
    catalog: FirstPartyCatalog,
) -> Result<CatalogReconcile, sqlx::Error> {
    let table = catalog.table();
    let rows: Vec<(Uuid, String, String, String, bool, bool)> = sqlx::query_as(&format!(
        "SELECT id, name, url, branch, enabled, auto_sync_enabled FROM {table} ORDER BY created_at, id FOR UPDATE"
    ))
    .fetch_all(&mut **tx)
    .await?;
    let existing = rows
        .into_iter()
        .find(|(_, _, url, ..)| catalog.matches_url(url))
        .map(|(id, name, _, branch, enabled, auto_sync_enabled)| ExistingCatalog {
            id,
            name,
            branch,
            enabled,
            auto_sync_enabled,
        });
    let target = crate::schema::default_content_branch(catalog.url(), None);
    let plan = plan(existing.as_ref(), &target);
    let (repository_id, name) = match &plan {
        CatalogPlan::Create { branch } => {
            let slug = crate::db::repo_store::slug_from_url(catalog.url(), catalog.name(), None);
            let id: Uuid = match catalog {
                FirstPartyCatalog::Parsers => sqlx::query_scalar(
                    "INSERT INTO parser_repositories (name, slug, description, url, branch, parsers_path, \
                        auto_sync_enabled, sync_interval_hours) \
                     VALUES ($1,$2,$3,$4,$5,'parsers/',TRUE,$6) RETURNING id",
                ),
                // Native nPL rules at the repository root, like the hosted
                // catalog and the one-click add.
                FirstPartyCatalog::Rules => sqlx::query_scalar(
                    "INSERT INTO rule_repositories (name, slug, description, url, branch, rules_path, rule_format, \
                        auto_sync_enabled, sync_interval_hours) \
                     VALUES ($1,$2,$3,$4,$5,'','nanosiem',TRUE,$6) RETURNING id",
                ),
            }
            .bind(catalog.name())
            .bind(&slug)
            .bind(catalog.description())
            .bind(catalog.url())
            .bind(branch)
            .bind(FIRST_PARTY_SYNC_INTERVAL_HOURS)
            .fetch_one(&mut **tx)
            .await?;
            (id, catalog.name().to_owned())
        }
        CatalogPlan::Update { id, branch, enable_auto_sync } => {
            sqlx::query(&format!(
                "UPDATE {table} SET branch = COALESCE($2, branch), \
                    auto_sync_enabled = auto_sync_enabled OR $3, \
                    last_synced_at = NULL, updated_at = NOW() WHERE id = $1"
            ))
            .bind(id)
            .bind(branch.as_deref())
            .bind(*enable_auto_sync)
            .execute(&mut **tx)
            .await?;
            (*id, existing.as_ref().map(|row| row.name.clone()).unwrap_or_default())
        }
        CatalogPlan::Current(id) | CatalogPlan::Disabled(id) => {
            (*id, existing.as_ref().map(|row| row.name.clone()).unwrap_or_default())
        }
    };
    Ok(CatalogReconcile {
        catalog,
        repository_id,
        name,
        plan,
        previous_branch: existing.map(|row| row.branch),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(branch: &str, enabled: bool, auto: bool) -> ExistingCatalog {
        ExistingCatalog { id: Uuid::nil(), name: "x".into(), branch: branch.into(), enabled, auto_sync_enabled: auto }
    }

    #[test]
    fn fresh_install_registers_main() {
        assert_eq!(crate::schema::default_content_branch(FirstPartyCatalog::Rules.url(), None), "main");
        assert_eq!(plan(None, "main"), CatalogPlan::Create { branch: "main".into() });
    }

    /// NAN-3897: the retired `ocsf-1.9` default (or an unset branch) moves to `main`.
    #[test]
    fn upgrade_moves_ocsf19_or_unset_to_main_and_enables_auto_sync() {
        for stored in ["ocsf-1.9", "", " ocsf-1.9 "] {
            assert_eq!(
                plan(Some(&row(stored, true, false)), "main"),
                CatalogPlan::Update { id: Uuid::nil(), branch: Some("main".into()), enable_auto_sync: true }
            );
        }
        assert_eq!(
            plan(Some(&row("ocsf-1.9", true, true)), "main"),
            CatalogPlan::Update { id: Uuid::nil(), branch: Some("main".into()), enable_auto_sync: false }
        );
        assert_eq!(
            plan(Some(&row("main", true, false)), "main"),
            CatalogPlan::Update { id: Uuid::nil(), branch: None, enable_auto_sync: true }
        );
    }

    #[test]
    fn main_pins_and_opt_outs_are_kept() {
        assert_eq!(plan(Some(&row("main", true, true)), "main"), CatalogPlan::Current(Uuid::nil()));
        assert_eq!(plan(Some(&row("my-fork", true, true)), "main"), CatalogPlan::Current(Uuid::nil()));
        assert_eq!(plan(Some(&row("legacy/clickhouse", true, true)), "main"), CatalogPlan::Current(Uuid::nil()));
        assert_eq!(plan(Some(&row("ocsf-1.9", false, false)), "main"), CatalogPlan::Disabled(Uuid::nil()));
    }

    #[test]
    fn catalog_urls_match_only_their_own_repository() {
        assert!(FirstPartyCatalog::Parsers.matches_url("https://github.com/nano-rs/parsers"));
        assert!(FirstPartyCatalog::Parsers.matches_url("https://github.com/NANO-RS/Parsers.git"));
        assert!(!FirstPartyCatalog::Parsers.matches_url("https://github.com/nano-rs/rules"));
        assert!(FirstPartyCatalog::Rules.matches_url("github.com/nano-rs/rules/"));
        assert!(!FirstPartyCatalog::Rules.matches_url("https://github.com/someone/rules"));
        assert!(!FirstPartyCatalog::Rules.matches_url("https://github.com/SigmaHQ/sigma"));
    }
}
