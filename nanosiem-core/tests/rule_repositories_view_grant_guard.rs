// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5709 seed guard: the Rules > Repositories rail item and route gate on
//! `rule_repositories:view` (the permission every repository read endpoint
//! checks), and migration 394 grants it to the built-in Editor and ReadOnly
//! roles, so the roles that see Rules keep the page. ReadOnly is bound to the
//! Everyone group, so this is what keeps the page for every user.
//!
//! DB-free: text analysis of the checked-in migration. The route / rail / API
//! agreement is pinned by nanosiem-web/src/routes.rule-repositories-gate.test.ts.

const GRANT: &str =
    include_str!("../../migrations/postgres/394_rule_repositories_view_for_readonly.sql");

const EDITOR: &str = "00000000-0000-0000-0000-000000000002";
const READONLY: &str = "00000000-0000-0000-0000-000000000003";

/// The SQL with `--` comments stripped, so a commented-out grant does not pass.
fn code(sql: &str) -> String {
    sql.lines()
        .map(|l| l.split("--").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn migration_grants_view_to_editor_and_readonly() {
    let sql = code(GRANT);
    assert!(sql.contains("INSERT INTO role_permissions"), "394 must insert role grants");
    assert!(sql.contains("'rule_repositories:view'"), "394 must grant rule_repositories:view");
    assert!(sql.contains(EDITOR), "394 must grant Editor");
    assert!(sql.contains(READONLY), "394 must grant ReadOnly");
    assert!(sql.contains("ON CONFLICT DO NOTHING"), "394 must be idempotent");
    // View only: never manage / sync / import.
    for broader in ["rule_repositories:manage", "rule_repositories:sync", "rule_repositories:import"] {
        assert!(!sql.contains(broader), "394 must not grant {broader}");
    }
    // Scoped API keys are an explicit grant by their creator: not backfilled.
    assert!(!sql.contains("api_keys"), "394 must not touch api_keys");
}
