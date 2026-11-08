// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2225 — fresh↔legacy seeded-state parity.
//!
//! A fresh install and a legacy install run *different* migration paths:
//!
//!   fresh   snapshot `postgres-open/000_open_init.sql`, then `_sqlx_migrations`
//!           backfilled for 1..=`OPEN_INIT_BASELINE_VERSION` WITHOUT executing
//!           those bodies, then everything above the baseline runs normally.
//!   legacy  every migration from 001 runs for real.
//!
//! So any INSERT/UPDATE/DELETE in a pre-baseline migration happens only on the
//! legacy path unless `177_seed_open_baseline.sql` replays it. When a replay is
//! missed the two paths diverge silently, and the divergence surfaces much
//! later as a feature that is simply absent on one class of install.
//!
//! That has now happened at least four times:
//!
//!   NAN-2212  `settings:ai_providers` / `settings:agent_models` never seeded
//!             (040 carved out of 177) → AI settings tabs vanished on upgrade.
//!   NAN-2218  `credentials:rotate` never seeded (165 simply missed) →
//!             credential rotation dead for everyone including Admin.
//!   NAN-2221  177 re-seeded six permissions 058 had deliberately revoked →
//!             every authenticated user could enumerate cloud credentials.
//!   NAN-2229-adjacent: the same re-seed/clobber shape in 047→115, 150→180,
//!             185→186, all caught only after the fact.
//!
//! Every one of those was found by a human reading migrations, not by a test.
//! `migration_fresh_init.rs` checks that the fresh path produces the right
//! TABLES; nothing checked that it produces the right ROWS. This does.
//!
//! Prerequisites: Postgres at `TEST_DATABASE_URL`, plus the NAN-2215
//! destructive opt-in. `#[ignore]`d so a plain `cargo test` skips it; the
//! `pg-integration-tests` job runs it with `-- --ignored --test-threads=1`
//! (single-threaded: the scenarios share process env to force the path).

use sqlx::postgres::PgPoolOptions;
use sqlx::{Executor, PgPool, Row};

mod common;

const FRESH_DB: &str = "nanosiem_parity_fresh";
const LEGACY_DB: &str = "nanosiem_parity_legacy";

/// Seeded state that legitimately differs between a fresh OPEN install and a
/// legacy one, with the reason. **Every entry is a hole in this test**, so each
/// must be justified here and re-justified if it ever changes.
///
/// `playbooks:*` / `playbook_repositories:*` — seeded by `157_playbooks.sql`,
/// which lives in the open series and therefore runs on the legacy path, but is
/// NOT replayed by 177. On a fresh install they arrive only via the enterprise
/// overlay (`postgres-enterprise/9000004_seed_playbook_permissions.sql`), so a
/// fresh OPEN install legitimately lacks them. That is consistent with the
/// runtime gate: the playbooks nav is double-gated on a build-time `playbooks`
/// capability that open-core does not have, and the routes fail closed at 403.
const EXPECTED_OPEN_TIER_DIVERGENCE: &[&str] = &[
    "playbooks:view",
    "playbooks:run",
    "playbooks:manage",
    "playbooks:publish",
    "playbook_repositories:view",
    "playbook_repositories:sync",
    "playbook_repositories:import",
    "playbook_repositories:manage",
];

/// Groups that legitimately differ, same enterprise-only reasoning.
///
/// The four queue groups are created by `154_queues.sql` (open series, so the
/// legacy path runs it) and re-seeded on the enterprise path by
/// `postgres-enterprise/9000008_seed_baseline_queues.sql`. Queues and cases are
/// enterprise-only, so a fresh OPEN install correctly has neither.
///
/// Note the reason 177 gives for carving 154/155 out is WRONG: it claims "Cases
/// UI bootstraps queue groups on first use", and no such bootstrap exists — the
/// only `INSERT INTO queues` in the tree is the admin CRUD handler. The carve-out
/// happens to be harmless anyway because 9000008 covers the tier that needs
/// them, but do not rely on 177's stated justification; it does not hold.
const EXPECTED_OPEN_TIER_GROUP_DIVERGENCE: &[&str] = &[
    "Triage",
    "Tier 1 SOC",
    "Tier 2 Investigation",
    "Tier 3 IR / Forensics",
];

fn admin_url() -> String {
    std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://nanosiem:nanosiem@localhost:5432/postgres".to_string())
}

fn url_for(db: &str) -> String {
    let admin = admin_url();
    let last_slash = admin.rfind('/').expect("admin url must contain '/'");
    format!("{}/{}", &admin[..last_slash], db)
}

async fn recreate(db: &str) -> PgPool {
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&admin_url())
        .await
        .expect("connect admin db");
    let _ = admin
        .execute(
            format!(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
                 WHERE datname = '{db}' AND pid <> pg_backend_pid()"
            )
            .as_str(),
        )
        .await;
    admin
        .execute(format!("DROP DATABASE IF EXISTS {db}").as_str())
        .await
        .expect("drop test db");
    admin
        .execute(format!("CREATE DATABASE {db}").as_str())
        .await
        .expect("create test db");
    PgPoolOptions::new()
        .max_connections(2)
        .connect(&url_for(db))
        .await
        .expect("connect test db")
}

/// `id` set of a single-column query, sorted.
async fn scalars(pool: &PgPool, sql: &str) -> Vec<String> {
    let rows = sqlx::query(sql).fetch_all(pool).await.expect("query");
    let mut out: Vec<String> = rows.iter().map(|r| r.get::<String, _>(0)).collect();
    out.sort();
    out
}

/// The seeded state this test compares. Deliberately the RBAC core: it is what
/// every silent-divergence bug so far has landed in, and it is what decides
/// whether a UI surface renders at all.
const PERMISSION_IDS: &str = "SELECT id FROM permissions";
const ROLE_GRANTS: &str = "SELECT r.name || ' -> ' || rp.permission_id \
                           FROM role_permissions rp JOIN roles r ON r.id = rp.role_id";
const ROLE_NAMES: &str = "SELECT name FROM roles";
const GROUP_NAMES: &str = "SELECT name FROM groups";
const GROUP_ROLE_BINDINGS: &str = "SELECT g.name || ' -> ' || r.name \
                                   FROM group_roles gr \
                                   JOIN groups g ON g.id = gr.group_id \
                                   JOIN roles r ON r.id = gr.role_id";

fn diff<'a>(legacy: &'a [String], fresh: &'a [String]) -> (Vec<&'a String>, Vec<&'a String>) {
    let legacy_only: Vec<&String> = legacy.iter().filter(|v| !fresh.contains(v)).collect();
    let fresh_only: Vec<&String> = fresh.iter().filter(|v| !legacy.contains(v)).collect();
    (legacy_only, fresh_only)
}

/// Does this divergence mention an allowlisted permission id?
fn is_expected(entry: &str) -> bool {
    EXPECTED_OPEN_TIER_DIVERGENCE
        .iter()
        .chain(EXPECTED_OPEN_TIER_GROUP_DIVERGENCE.iter())
        .any(|allowed| entry.ends_with(allowed) || entry == *allowed)
}

#[tokio::test]
#[ignore = "DB-backed; run with --ignored in pg-integration-tests"]
async fn nan2225_fresh_and_legacy_paths_seed_identical_state() {
    common::assert_destructive_opt_in(&admin_url());

    // ---- build both paths -------------------------------------------------
    // Legacy first: it sets the process env, and the fresh run must clear it.
    let legacy = recreate(LEGACY_DB).await;
    std::env::set_var("NANOSIEM_MIGRATION_MODE", "legacy");
    nanosiem_core::db::run_postgres_migrations(&legacy)
        .await
        .expect("legacy path: every migration from 001 applies to an empty database");

    let fresh = recreate(FRESH_DB).await;
    std::env::remove_var("NANOSIEM_MIGRATION_MODE");
    nanosiem_core::db::run_postgres_migrations(&fresh)
        .await
        .expect("fresh path: snapshot + backfill + post-baseline migrations");

    // Guard against a vacuous pass: if either path produced nothing, the
    // comparisons below would trivially agree.
    let legacy_perms = scalars(&legacy, PERMISSION_IDS).await;
    let fresh_perms = scalars(&fresh, PERMISSION_IDS).await;
    assert!(
        legacy_perms.len() > 100 && fresh_perms.len() > 100,
        "one of the paths seeded almost nothing (legacy={}, fresh={}) — the \
         migration run probably failed silently, and a parity assertion over \
         two empty sets proves nothing",
        legacy_perms.len(),
        fresh_perms.len()
    );

    // ---- compare ----------------------------------------------------------
    let mut unexpected: Vec<String> = Vec::new();

    for (label, sql) in [
        ("permissions", PERMISSION_IDS),
        ("role_permissions", ROLE_GRANTS),
        ("roles", ROLE_NAMES),
        ("groups", GROUP_NAMES),
        ("group_roles", GROUP_ROLE_BINDINGS),
    ] {
        let l = scalars(&legacy, sql).await;
        let f = scalars(&fresh, sql).await;
        let (legacy_only, fresh_only) = diff(&l, &f);
        for e in legacy_only {
            if !is_expected(e) {
                unexpected.push(format!("{label}: LEGACY-only  {e}"));
            }
        }
        for e in fresh_only {
            if !is_expected(e) {
                unexpected.push(format!("{label}: FRESH-only   {e}"));
            }
        }
    }

    assert!(
        unexpected.is_empty(),
        "fresh and legacy installs seed DIFFERENT state. Each line is a feature \
         that behaves differently depending on how the tenant was installed — \
         the NAN-2212 / NAN-2218 / NAN-2221 failure mode.\n\n{}\n\n\
         Fix by adding a forward migration that reconciles the two paths (never \
         by editing an applied migration — sqlx checksums them). Only add an \
         entry to EXPECTED_OPEN_TIER_DIVERGENCE if the difference is genuinely \
         intended, with the reason written down.",
        unexpected.join("\n")
    );

    // ---- the allowlist must not outlive its justification -----------------
    // A stale exemption is how NAN-2228 stayed hidden: something was excluded
    // because it "never ships", the world changed, and nothing re-checked. If
    // an allowlisted permission has since converged, this test should stop
    // exempting it rather than silently continuing to.
    let still_divergent: Vec<&str> = EXPECTED_OPEN_TIER_DIVERGENCE
        .iter()
        .copied()
        .filter(|p| legacy_perms.iter().any(|v| v == p) && !fresh_perms.iter().any(|v| v == p))
        .collect();
    assert_eq!(
        still_divergent.len(),
        EXPECTED_OPEN_TIER_DIVERGENCE.len(),
        "EXPECTED_OPEN_TIER_DIVERGENCE is stale — these entries no longer diverge \
         and should be removed from the allowlist: {:?}",
        EXPECTED_OPEN_TIER_DIVERGENCE
            .iter()
            .filter(|p| !still_divergent.contains(p))
            .collect::<Vec<_>>()
    );
}
