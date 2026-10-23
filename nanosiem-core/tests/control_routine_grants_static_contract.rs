// SPDX-License-Identifier: Proprietary

//! NAN-4146: the region app activation revokes every routine grant held by
//! `nano_shared_app_control` and re-grants only an allowlist. A routine a
//! migration grants to control but the allowlist omits is silently lost on
//! every freshly activated region; that is how owner/member activation
//! (`activate_member_invitation`) broke in every new region.
//!
//! The allowlist is `control-routine-grants.txt`, derived here from the
//! migrations: every routine whose final migration-issued EXECUTE state for
//! `nano_shared_app_control` is granted. A new migration that grants control a
//! routine fails this test until the routine is added to the list (and to the
//! hosted control plane's `CONTROL_ROUTINE_GRANTS`, which pins this file's sha256).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const CONTROL: &str = "nano_shared_app_control";
const GRANTS_FILE: &str = "deploy/hosted-shared-fixtures/hosted-shared-app-postgres18/control-routine-grants.txt";
const ACTIVATION_FIXTURE: &str = "deploy/hosted-shared-fixtures/hosted-shared-app-postgres18/activation.yaml.in";
const REPAIR_MIGRATION: &str = "migrations/postgres-enterprise/9014060_control_routine_grants_repair.sql";

/// Definers re-owned to the NOLOGIN data owner after activation; the
/// activation's owner-window path grants them, not the postgres allowlist.
const OWNER_HELD: &[&str] = &["nano_shared.resolve_sso_member"];

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// `nano_shared.f( UUID, TIMESTAMPTZ )` → `nano_shared.f(uuid,timestamp with time zone)`.
fn canonical(signature: &str) -> String {
    let signature = signature.trim();
    let open = signature.find('(').expect("routine signature has an argument list");
    let name = signature[..open].trim().to_ascii_lowercase();
    let name = if name.contains('.') { name } else { format!("public.{name}") };
    let args = signature[open + 1..signature.rfind(')').expect("closing paren")].trim();
    let args: Vec<String> = if args.is_empty() {
        Vec::new()
    } else {
        args.split(',')
            .map(|arg| {
                let arg = arg.split_whitespace().collect::<Vec<_>>().join(" ").to_ascii_lowercase();
                match arg.as_str() {
                    "timestamptz" => "timestamp with time zone".to_string(),
                    "int" | "int4" => "integer".to_string(),
                    "int8" => "bigint".to_string(),
                    "bool" => "boolean".to_string(),
                    "text []" => "text[]".to_string(),
                    other => other.to_string(),
                }
            })
            .collect()
    };
    format!("{name}({})", args.join(","))
}

/// Split a GRANT/REVOKE routine list on top-level commas.
fn routines(list: &str) -> Vec<String> {
    let (mut out, mut depth, mut current) = (Vec::new(), 0usize, String::new());
    for ch in list.chars() {
        match ch {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                out.push(std::mem::take(&mut current));
                continue;
            }
            _ => {}
        }
        current.push(ch);
    }
    out.push(current);
    out.into_iter().map(|s| s.trim().to_string()).filter(|s| s.contains('(')).collect()
}

fn strip_comments(sql: &str) -> String {
    sql.lines().map(|line| line.split("--").next().unwrap_or("")).collect::<Vec<_>>().join("\n")
}

/// Final migration-issued EXECUTE state for control, in migration order.
fn migration_control_grants() -> BTreeSet<String> {
    let statement = regex::Regex::new(
        r"(?is)\b(GRANT|REVOKE)\s+(?:ALL(?:\s+PRIVILEGES)?|EXECUTE)\s+ON\s+(?:FUNCTION|ROUTINE)\s+(.*?)\s+(?:TO|FROM)\s+([^;]*?)(?:;|\$|\bEND\b)",
    )
    .unwrap();
    let role = regex::Regex::new(&format!(r"\b{CONTROL}\b")).unwrap();
    let mut files: Vec<(u64, PathBuf)> = std::fs::read_dir(repo().join("migrations/postgres-enterprise"))
        .unwrap()
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            let name = path.file_name()?.to_str()?.to_string();
            let version = name.split('_').next()?.parse().ok()?;
            name.ends_with(".sql").then_some((version, path))
        })
        .collect();
    files.sort();
    let mut state: BTreeMap<String, bool> = BTreeMap::new();
    for (_, path) in files {
        let sql = strip_comments(&std::fs::read_to_string(&path).unwrap());
        for found in statement.captures_iter(&sql) {
            let (kind, list, grantees) = (&found[1], &found[2], &found[3]);
            // Dynamic (format/EXECUTE) and ALL FUNCTIONS IN SCHEMA forms are
            // not static grants of a named routine.
            if !role.is_match(grantees) || list.contains('\'') || list.contains('%') || list.to_ascii_uppercase().contains("IN SCHEMA") {
                continue;
            }
            for routine in routines(list) {
                state.insert(canonical(&routine), kind.eq_ignore_ascii_case("GRANT"));
            }
        }
    }
    state
        .into_iter()
        .filter(|(routine, granted)| *granted && !OWNER_HELD.iter().any(|owner| routine.starts_with(&format!("{owner}("))))
        .map(|(routine, _)| routine)
        .collect()
}

fn listed() -> Vec<String> {
    std::fs::read_to_string(repo().join(GRANTS_FILE))
        .unwrap()
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect()
}

#[test]
fn control_routine_grant_list_matches_the_migrations() {
    let listed = listed();
    let unique: BTreeSet<String> = listed.iter().cloned().collect();
    assert_eq!(unique.len(), listed.len(), "control-routine-grants.txt has duplicates");
    for routine in &listed {
        assert_eq!(&canonical(routine), routine, "list entries must be canonical regprocedure text");
    }
    let derived = migration_control_grants();
    let missing: Vec<_> = derived.difference(&unique).collect();
    let stale: Vec<_> = unique.difference(&derived).collect();
    assert!(
        missing.is_empty(),
        "migrations grant these routines to {CONTROL} but control-routine-grants.txt (and the hosted \
         CONTROL_ROUTINE_GRANTS) omit them, so region app activation would revoke them: {missing:?}"
    );
    assert!(stale.is_empty(), "control-routine-grants.txt lists routines no migration grants to {CONTROL}: {stale:?}");
}

#[test]
fn the_lost_activation_and_scheduler_routines_are_listed() {
    let listed = listed();
    for routine in [
        "nano_shared.activate_member_invitation(bytea,text)",
        "nano_shared.apply_managed_platform_ai_provider(text,bytea,jsonb,timestamp with time zone,text)",
        "nano_shared.platform_ai_availability()",
        "nano_shared.sync_platform_ai_provider_credentials(uuid,boolean)",
        "nano_shared.list_due_report_definitions(uuid,bigint)",
        "nano_shared.feed_staleness_recipients(uuid)",
    ] {
        assert!(listed.iter().any(|r| r == routine), "{routine} missing from control-routine-grants.txt");
    }
}

#[test]
fn activation_fixture_and_repair_migration_grant_every_listed_routine() {
    let fixture = std::fs::read_to_string(repo().join(ACTIVATION_FIXTURE)).unwrap();
    let repair = std::fs::read_to_string(repo().join(REPAIR_MIGRATION)).unwrap();
    let reset = fixture.find("REVOKE ALL ON ROUTINE").expect("fixture resets control routine grants");
    for routine in listed() {
        let at = fixture.rfind(&routine).unwrap_or_else(|| panic!("activation fixture never grants {routine}"));
        assert!(at > reset, "activation fixture grants {routine} before the routine reset");
        assert!(repair.contains(&format!("'{routine}'")), "repair migration omits {routine}");
    }
    // The repair is additive and fails loudly on a shared deployment without the role.
    assert!(!strip_comments(&repair).to_ascii_uppercase().contains("REVOKE"));
    assert!(repair.contains("RLS contract is enabled but nano_shared_app_control does not exist"));
    assert!(repair.contains("still lacks EXECUTE"));
}

// ---------------------------------------------------------------------------
// Table / column / sequence privileges (NAN-4146 follow-up). The same reset
// revokes every table privilege held by control; control-table-grants.txt is
// the migration-derived set the activation must restore.
// ---------------------------------------------------------------------------

const TABLE_GRANTS_FILE: &str = "deploy/hosted-shared-fixtures/hosted-shared-app-postgres18/control-table-grants.txt";
const TABLE_REPAIR_MIGRATION: &str = "migrations/postgres-enterprise/9014070_control_table_grants_repair.sql";
const TABLE_PRIVILEGES: &[&str] = &["SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"];
const SEQUENCE_PRIVILEGES: &[&str] = &["SELECT", "UPDATE", "USAGE"];

fn relation(name: &str) -> String {
    let name = name.trim().trim_matches('"').to_ascii_lowercase();
    if name.contains('.') { name } else { format!("public.{name}") }
}

/// Final static migration-issued table/column/sequence privilege state for
/// control, as `<table|column|sequence> <object> <PRIVILEGE>` lines.
fn migration_control_table_grants() -> BTreeSet<String> {
    let statement = regex::Regex::new(
        r"(?i)\b(GRANT|REVOKE)\s+((?:(?:ALL(?:\s+PRIVILEGES)?|SELECT|INSERT|UPDATE|DELETE|TRUNCATE|REFERENCES|TRIGGER|USAGE)(?:\s*\([^)]*\))?\s*,?\s*)+)\s+ON\s+(TABLE\s+|SEQUENCE\s+)?((?:[^;]*?))\s+(TO|FROM)\s+([^;]*?)(?:;|\$|\bEND\b)",
    )
    .unwrap();
    let privilege = regex::Regex::new(
        r"(?i)(ALL(?:\s+PRIVILEGES)?|SELECT|INSERT|UPDATE|DELETE|TRUNCATE|REFERENCES|TRIGGER|USAGE)\s*(\(([^)]*)\))?",
    )
    .unwrap();
    let skip = regex::Regex::new(r"(?i)'|%|\|\||\bALL\s+(TABLES|SEQUENCES)\b|\bSCHEMA\b|\bFUNCTION\b|\bROUTINE\b|\bDATABASE\b").unwrap();
    let ident = regex::Regex::new(r"^[a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*$").unwrap();
    let role = regex::Regex::new(&format!(r"\b{CONTROL}\b")).unwrap();
    let mut files: Vec<(u64, PathBuf)> = std::fs::read_dir(repo().join("migrations/postgres-enterprise"))
        .unwrap()
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            let name = path.file_name()?.to_str()?.to_string();
            let version = name.split('_').next()?.parse().ok()?;
            name.ends_with(".sql").then_some((version, path))
        })
        .collect();
    files.sort();
    let mut state: BTreeMap<String, bool> = BTreeMap::new();
    for (_, path) in files {
        let sql = strip_comments(&std::fs::read_to_string(&path).unwrap());
        for found in statement.captures_iter(&sql) {
            let (kind, privileges, on, objects, grantees) =
                (&found[1], &found[2], found.get(3).map(|m| m.as_str()), &found[4], &found[6]);
            if !role.is_match(grantees) || skip.is_match(&format!("{objects} {privileges}")) {
                continue;
            }
            let sequence = on.is_some_and(|on| on.trim().eq_ignore_ascii_case("SEQUENCE"));
            let objects: Vec<String> = objects.split(',').filter(|o| !o.trim().is_empty()).map(relation).collect();
            if objects.iter().any(|o| !ident.is_match(o)) {
                continue;
            }
            let mut entries = Vec::new();
            for p in privilege.captures_iter(privileges) {
                let name = p[1].split_whitespace().next().unwrap().to_ascii_uppercase();
                let names: Vec<&str> = if name == "ALL" {
                    if sequence { SEQUENCE_PRIVILEGES.to_vec() } else { TABLE_PRIVILEGES.to_vec() }
                } else {
                    vec![TABLE_PRIVILEGES.iter().chain(SEQUENCE_PRIVILEGES).find(|n| **n == name).copied().unwrap()]
                };
                for n in names {
                    match p.get(3) {
                        Some(columns) => {
                            for c in columns.as_str().split(',') {
                                entries.push((n, Some(c.trim().to_ascii_lowercase())));
                            }
                        }
                        None => entries.push((n, None)),
                    }
                }
            }
            let grant = kind.eq_ignore_ascii_case("GRANT");
            for object in &objects {
                for (n, column) in &entries {
                    let line = match (column, sequence) {
                        (Some(c), _) => format!("column {object}({c}) {n}"),
                        (None, true) => format!("sequence {object} {n}"),
                        (None, false) => format!("table {object} {n}"),
                    };
                    if grant {
                        state.insert(line, true);
                    } else {
                        state.remove(&line);
                        if column.is_none() {
                            let prefix = format!("column {object}(");
                            state.retain(|k, _| !(k.starts_with(&prefix) && k.ends_with(&format!(" {n}"))));
                        }
                    }
                }
            }
        }
    }
    state.into_keys().collect()
}

fn listed_table_grants() -> Vec<String> {
    std::fs::read_to_string(repo().join(TABLE_GRANTS_FILE))
        .unwrap()
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect()
}

#[test]
fn control_table_grant_list_matches_the_migrations() {
    let listed = listed_table_grants();
    let unique: BTreeSet<String> = listed.iter().cloned().collect();
    assert_eq!(unique.len(), listed.len(), "control-table-grants.txt has duplicates");
    let derived = migration_control_table_grants();
    let missing: Vec<_> = derived.difference(&unique).collect();
    let stale: Vec<_> = unique.difference(&derived).collect();
    assert!(
        missing.is_empty(),
        "migrations grant these privileges to {CONTROL} but control-table-grants.txt (and the hosted \
         CONTROL_TABLE_GRANTS) omit them, so region app activation would revoke them: {missing:?}"
    );
    assert!(stale.is_empty(), "control-table-grants.txt lists privileges no migration grants to {CONTROL}: {stale:?}");
}

#[test]
fn the_lost_control_table_privileges_are_listed() {
    let listed = listed_table_grants();
    for line in [
        "table public.enterprise_shared_tenant_ai_allowances SELECT",
        "table public.enterprise_shared_oidc_providers SELECT",
        "table public.enterprise_shared_oidc_auth_transactions INSERT",
        "table public.platform_repository_sync_requests UPDATE",
        "table public.enrichment_marketplace_repos SELECT",
        "table public.marketplace_catalog SELECT",
    ] {
        assert!(listed.iter().any(|l| l == line), "{line} missing from control-table-grants.txt");
    }
}

#[test]
fn activation_fixture_and_table_repair_restore_every_listed_privilege() {
    let fixture = std::fs::read_to_string(repo().join(ACTIVATION_FIXTURE)).unwrap();
    let repair = std::fs::read_to_string(repo().join(TABLE_REPAIR_MIGRATION)).unwrap();
    let block = &fixture[fixture.find("NAN-4146: restore the migration-granted control table").expect("fixture table grant block")..];
    // Granted by a migration recorded after 9014070 (on regions activated
    // earlier the granting migration itself applies the privilege), so the
    // frozen 9014070 repair cannot and need not list them.
    const AFTER_TABLE_REPAIR: &[(&str, &str)] = &[
        ("table public.enterprise_shared_tenant_path_aliases SELECT", "9014220_tenant_path_alias.sql"),
    ];
    for (line, migration) in AFTER_TABLE_REPAIR {
        let sql = std::fs::read_to_string(repo().join("migrations/postgres-enterprise").join(migration)).unwrap();
        let (_, object, privilege) = { let mut p = line.split(' '); (p.next().unwrap(), p.next().unwrap(), p.next().unwrap()) };
        assert!(sql.contains(&format!("GRANT {privilege} ON TABLE {object} TO {CONTROL}")), "{migration} grants {line}");
    }
    for line in listed_table_grants() {
        assert!(
            AFTER_TABLE_REPAIR.iter().any(|(l, _)| *l == line) || repair.contains(&format!("'{line}'")),
            "table repair migration omits {line}"
        );
        let mut parts = line.split(' ');
        let (kind, object, privilege) = (parts.next().unwrap(), parts.next().unwrap(), parts.next().unwrap());
        let granted = match kind {
            "column" => {
                let (table, column) = object.trim_end_matches(')').split_once('(').unwrap();
                block.lines().any(|l| l.contains(&format!("GRANT {privilege} (")) && l.contains(&format!("ON TABLE {table} "))
                    && l.split_once('(').unwrap().1.split(')').next().unwrap().split(", ").any(|c| c == column))
            }
            "sequence" => block.lines().any(|l| l.contains(&format!(" ON SEQUENCE {object} ")) && l.contains(privilege)),
            _ => block.lines().any(|l| l.contains(&format!(" ON TABLE {object} ")) && l.trim_start().starts_with("GRANT ")
                && l.trim_start()["GRANT ".len()..].split(" ON ").next().unwrap().split(", ").any(|p| p == privilege)),
        };
        assert!(granted, "activation fixture never restores {line}");
    }
    assert!(block.contains("SELECT nano_shared.reconcile_runtime_sequence_grants();"));
    // NAN-4146: activation narrows its blanket runtime DML to the 9014250 ceilings.
    assert!(block.contains("PERFORM nano_shared.reconcile_runtime_table_ceiling();"));
    assert!(block.contains("FROM nano_shared.audit_runtime_table_ceiling('nano_shared_app_runtime'::name)) THEN"));
    // Additive: the only REVOKE closes the repair's own owner window.
    assert_eq!(strip_comments(&repair).to_ascii_uppercase().matches("REVOKE").count(), 1);
    // The region migrator authenticates as the provider login (pscale_api_*)
    // with current_user postgres; begin_managed_owner_bootstrap() (and so
    // reconcile_runtime_sequence_grants()) rejects that identity. The repair
    // must open its own INHERIT-only window and close it again.
    let body = strip_comments(&repair);
    assert!(!body.contains("reconcile_runtime_sequence_grants"), "region migrations cannot use the session-postgres-only reconcile");
    assert!(!body.contains("begin_managed_owner_bootstrap"), "region migrations cannot use the session-postgres-only owner bootstrap");
    assert!(body.contains("starts_with(session_user::text, 'pscale_api_')"));
    assert!(body.contains("nano_is_managed_bootstrap_membership(m)"));
    assert!(body.contains("WITH ADMIN FALSE, INHERIT TRUE, SET FALSE GRANTED BY postgres"));
    assert!(body.contains("REVOKE %I FROM postgres GRANTED BY postgres"));
    assert!(repair.contains("audit_runtime_sequence_grants"));
    assert!(repair.contains("audit_control_role_grants"));
}
