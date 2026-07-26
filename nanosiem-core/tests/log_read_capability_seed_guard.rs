// SPDX-License-Identifier: AGPL-3.0-or-later

//! Seed guard for the log-read capability raise (NAN-2055 / NAN-2058 / NAN-2060).
//!
//! Those findings moved several log-DATA reads off weaker capabilities and onto
//! the ones canonical search already requires:
//!
//! * `GET /api/fields/{name}/values` and `GET /api/fields/ext`: `search:view`
//!   → `search:execute`;
//! * `GET /api/source-types`: `search:view` → `search:execute` OR a
//!   content-management capability (`log_sources:view` /
//!   `rule_repositories:view`), because the AddFeed and RuleRepositories source
//!   pickers need the inventory without being able to run searches;
//! * `POST /api/log-sources/test-live`: added `search:execute` alongside
//!   `log_sources:view`;
//! * `GET /api/system/overview`: added `search:execute` + `alerts:view` +
//!   `detections:view` alongside `settings:view`.
//!
//! Every one of those raises was justified by a claim about the SEEDED roles —
//! that no shipped role would lose a surface it has today. That claim is a fact
//! about migration SQL, not about Rust, so nothing else in the tree would notice
//! if a future seed broke it. These tests read the seeds and assert it directly.
//!
//! A failure here does NOT necessarily mean the handler gates are wrong — it
//! means a seeded role now sits on the losing side of one of those raises, and
//! that trade needs re-deciding rather than silently shipping.
//!
//! DB-free: pure text analysis of the checked-in migrations.

use std::collections::{HashMap, HashSet};

/// The role-permission seeds. `001` is the original bootstrap; `177` re-seeds
/// the same three system roles for open-core installs. Both must satisfy the
/// invariants, since either can be the one a given tenant booted from.
const INIT_SEED: &str = include_str!("../../migrations/postgres/001_init_postgres.sql");
const OPEN_BASELINE_SEED: &str =
    include_str!("../../migrations/postgres/177_seed_open_baseline.sql");

/// Well-known system role UUIDs (see the `INSERT INTO roles` blocks in `001`).
const ADMIN: &str = "00000000-0000-0000-0000-000000000001";
const EDITOR: &str = "00000000-0000-0000-0000-000000000002";
const READONLY: &str = "00000000-0000-0000-0000-000000000003";

/// Extract `(role_id, permission_id)` grants from the `role_permissions` seed
/// tuples, which are written as `('<uuid>', '<perm>')`.
///
/// Deliberately shape-based rather than a SQL parse: it over-matches harmlessly
/// (any `('uuid', 'string')` pair) and under-matches never, which is the safe
/// direction for a guard whose failure mode is "missed a grant".
fn grants(sql: &str) -> HashMap<String, HashSet<String>> {
    let mut out: HashMap<String, HashSet<String>> = HashMap::new();
    for raw in sql.split('(').skip(1) {
        let Some(close) = raw.find(')') else { continue };
        let tuple = &raw[..close];
        let parts: Vec<&str> = tuple.split(',').collect();
        if parts.len() != 2 {
            continue;
        }
        let role = parts[0].trim().trim_matches('\'');
        let perm = parts[1].trim().trim_matches('\'');
        // Role ids are UUIDs; permissions are `area:verb`.
        if role.len() == 36 && role.matches('-').count() == 4 && perm.contains(':') {
            out.entry(role.to_string())
                .or_default()
                .insert(perm.to_string());
        }
    }
    out
}

fn seeds() -> [(&'static str, HashMap<String, HashSet<String>>); 2] {
    [
        ("001_init_postgres.sql", grants(INIT_SEED)),
        ("177_seed_open_baseline.sql", grants(OPEN_BASELINE_SEED)),
    ]
}

#[test]
fn seeded_roles_are_actually_parsed() {
    // Guard the guard: if the seed format ever changes shape, the assertions
    // below would vacuously pass over an empty map.
    for (file, g) in seeds() {
        assert!(
            g.contains_key(EDITOR),
            "{file}: parsed no grants for the Editor role — the seed format changed \
             and every assertion in this file just became vacuous"
        );
        assert!(
            g[EDITOR].len() > 10,
            "{file}: suspiciously few Editor grants ({})",
            g[EDITOR].len()
        );
    }
}

#[test]
fn every_seeded_role_with_search_view_also_has_search_execute() {
    // NAN-2055: `/api/fields/{name}/values` and `/api/fields/ext` were raised
    // from `search:view` to `search:execute`. That is behavior-preserving ONLY
    // while no seeded role holds view without execute. The principals the raise
    // is meant to stop — custom roles and API keys issued `search:view` alone —
    // are created at runtime and are correctly outside this guarantee.
    //
    // `/api/source-types` is deliberately NOT covered here — it accepts a
    // content-management capability as an alternative, so a role can lose
    // `search:execute` and still reach it. See the NOTE below on why no seed
    // guard for that route is meaningful.
    for (file, g) in seeds() {
        for (role, perms) in &g {
            if perms.contains("search:view") {
                assert!(
                    perms.contains("search:execute"),
                    "{file}: role {role} is seeded with search:view but NOT \
                     search:execute — it would lose /api/source-types and \
                     /api/fields/*/values to the NAN-2055 capability raise"
                );
            }
        }
    }
}

// NOTE: there is deliberately NO seed guard for `/api/source-types`.
//
// An earlier revision had one, and it was vacuous: it selected roles by the same
// predicates it then asserted, so it could never fail — and it modelled a
// capability list that had already been corrected out of the handler, so it
// would not have caught drift either.
//
// The property is structural rather than seed-dependent. That gate accepts
// exactly the capabilities that ROUTE its consumer pages (`log_sources:create`
// for AddFeed, `detections:view` for RuleRepositories, `source_scopes:view` for
// Settings/SourceScopes, `search:execute` for search), so any role that can
// reach a consumer page satisfies the gate by construction. What can actually
// drift is the handler's accepted list, and that is pinned directly in
// `nanosiem-api/src/handlers/fields.rs::authz_parity_tests`.
//
// The guards below are kept because each relates two INDEPENDENT capability
// sets, where a seed really can fall on the wrong side.

#[test]
fn log_source_viewers_can_still_run_the_live_vrl_test() {
    // NAN-2058: `POST /api/log-sources/test-live` now requires `search:execute`
    // in addition to `log_sources:view`, so it can never be a looser raw-log
    // read than `/api/search`. Any seeded role that can see log sources must
    // still be able to use the parser test lab.
    for (file, g) in seeds() {
        for (role, perms) in &g {
            if perms.contains("log_sources:view") {
                assert!(
                    perms.contains("search:execute"),
                    "{file}: role {role} holds log_sources:view without \
                     search:execute — the NAN-2058 gate would take the live VRL \
                     test lab away from it"
                );
            }
        }
    }
}

#[test]
fn system_overview_capability_conjunction_holds_for_seeded_roles() {
    // NAN-2060: `GET /api/system/overview` now requires the conjunction of every
    // domain it reports on. Assert the two roles that can reach it today keep
    // it, and document ReadOnly's pre-existing exclusion so a future reader does
    // not mistake it for fallout from this change.
    const REQUIRED: [&str; 4] = [
        "settings:view",
        "search:execute",
        "alerts:view",
        "detections:view",
    ];

    for (file, g) in seeds() {
        for perm in REQUIRED {
            assert!(
                g[EDITOR].contains(perm),
                "{file}: Editor lost {perm} — it would 403 on /api/system/overview"
            );
        }

        // Admin is seeded by permission-table sweep rather than explicit tuples
        // in every file, so only assert the negative that matters: it must never
        // be *missing* a required cap while holding settings:view.
        if g.get(ADMIN).map(|p| p.contains("settings:view")) == Some(true) {
            for perm in REQUIRED {
                assert!(
                    g[ADMIN].contains(perm),
                    "{file}: Admin holds settings:view but not {perm}"
                );
            }
        }

        // ReadOnly's exclusion is PRE-EXISTING (it has never held
        // `settings:view`), not something NAN-2060 introduced. If that ever
        // changes, the conjunction has to be re-evaluated for it.
        assert!(
            !g[READONLY].contains("settings:view"),
            "{file}: ReadOnly gained settings:view — re-check whether the \
             NAN-2060 conjunction (alerts:view + detections:view + \
             search:execute) is satisfied for it"
        );
    }
}
