// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5338: every GRANT / REVOKE a numbered ClickHouse migration issues to a
//! user that `clickhouse/users.d/nanosiem-users.xml` defines must already be
//! reflected in that XML.
//!
//! Users defined in users.d (Compose mounts the file, the Helm chart ships it
//! as `files/clickhouse/users.json` via `scripts/sync-files.sh`) live in
//! ClickHouse's read-only `users_xml` access storage. A SQL GRANT to them
//! fails with Code 495 ACCESS_STORAGE_READONLY, and the migrator logs that and
//! moves on (the statement still applies to SQL-created users, e.g. BYOC).
//! That is only honest when the XML already confers the privilege (GRANT) or
//! already omits it (REVOKE). This guard makes that a build-time invariant, so
//! a new migration grant without its XML counterpart fails here instead of
//! surfacing as ACCESS_DENIED on a fresh install.

use std::path::{Path, PathBuf};

const USERS_XML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/users.d/nanosiem-users.xml"
));

/// The runtime user the Compose and Helm installs run as (`CLICKHOUSE_USER`).
const RUNTIME_USER: &str = "nanosiem";
const DATABASE: &str = "nanosiem";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// Numbered migration files the migrator applies (shared + OCSF profile).
fn migration_files() -> Vec<(String, String)> {
    let mut out = Vec::new();
    for dir in ["clickhouse", "clickhouse/ocsf/migrations"] {
        let mut entries: Vec<_> = std::fs::read_dir(repo_root().join(dir))
            .unwrap_or_else(|e| panic!("read {dir}: {e}"))
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                p.extension().is_some_and(|x| x == "sql")
                    && p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.as_bytes()[0].is_ascii_digit())
            })
            .collect();
        entries.sort();
        for p in entries {
            let name = format!("{dir}/{}", p.file_name().unwrap().to_string_lossy());
            out.push((name, std::fs::read_to_string(&p).unwrap()));
        }
    }
    out
}

/// Statements with `--` line comments stripped (as the migrator does).
fn statements(sql: &str) -> Vec<String> {
    let stripped: String = sql
        .lines()
        .map(|l| l.find("--").map_or(l, |i| &l[..i]))
        .collect::<Vec<_>>()
        .join("\n");
    stripped
        .split(';')
        .map(|s| s.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|s| !s.is_empty())
        .collect()
}

/// Split on commas that are not inside parentheses.
fn split_top_level(s: &str) -> Vec<String> {
    let (mut out, mut cur, mut depth) = (Vec::new(), String::new(), 0i32);
    for c in s.chars() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => {
                out.push(cur.trim().to_string());
                cur.clear();
                continue;
            }
            _ => {}
        }
        cur.push(c);
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

#[derive(Debug)]
struct Grant {
    privileges: Vec<String>,
    target: String,
    user: String,
}

/// Parse `GRANT <privs> ON <target> TO <user>` / `REVOKE <privs> ON <target>
/// FROM <user>`, with the migrator's placeholders resolved the way they are on
/// a Compose / Helm install.
fn parse(stmt: &str, keyword: &str, joiner: &str) -> Option<Grant> {
    let s = stmt
        .replace("{grant_on_cluster}", "")
        .replace("{clickhouse_runtime_user}", RUNTIME_USER);
    let rest = s.strip_prefix(keyword)?.trim_start();
    let (privs, rest) = rest.split_once(" ON ")?;
    let (target, user) = rest.split_once(joiner)?;
    let target = target.trim().to_string();
    let target = if target.contains('.') { target } else { format!("{DATABASE}.{target}") };
    Some(Grant {
        privileges: split_top_level(privs).into_iter().map(|p| p.to_uppercase()).collect(),
        target,
        user: user.trim().trim_matches('`').to_string(),
    })
}

/// `<query>` grants of one users.d user, or `None` when the XML does not
/// define that user (a SQL-created user: the migration GRANT applies).
fn xml_grants(user: &str) -> Option<Vec<Grant>> {
    let block = USERS_XML
        .split(&format!("<{user}>"))
        .nth(1)?
        .split(&format!("</{user}>"))
        .next()?;
    Some(
        block
            .split("<query>")
            .skip(1)
            .filter_map(|q| q.split("</query>").next())
            .map(|q| q.split_whitespace().collect::<Vec<_>>().join(" "))
            .filter_map(|q| parse(&format!("{q} TO {user}"), "GRANT", " TO "))
            .collect(),
    )
}

fn target_covers(have: &str, want: &str) -> bool {
    have == want
        || have == "*.*"
        || have
            .strip_suffix(".*")
            .is_some_and(|db| want.split_once('.').is_some_and(|(d, _)| d == db))
}

/// `ALTER` covers `ALTER DELETE`; a column-restricted privilege only covers
/// itself.
fn privilege_covers(have: &str, want: &str) -> bool {
    have == want || have == "ALL" || (!have.contains('(') && want.starts_with(&format!("{have} ")))
}

fn covered(grants: &[Grant], privilege: &str, target: &str) -> bool {
    grants.iter().any(|g| {
        target_covers(&g.target, target) && g.privileges.iter().any(|p| privilege_covers(p, privilege))
    })
}

#[test]
fn migration_grants_to_users_xml_users_are_carried_by_the_xml() {
    let mut checked = 0;
    let mut missing = Vec::new();
    for (file, sql) in migration_files() {
        for stmt in statements(&sql) {
            let upper = stmt.to_uppercase();
            if upper.starts_with("GRANT") {
                let g = parse(&stmt, "GRANT", " TO ")
                    .unwrap_or_else(|| panic!("{file}: unparsed GRANT: {stmt}"));
                let Some(xml) = xml_grants(&g.user) else { continue };
                for p in &g.privileges {
                    checked += 1;
                    if !covered(&xml, p, &g.target) {
                        missing.push(format!("{file}: {p} ON {} for {}", g.target, g.user));
                    }
                }
            } else if upper.starts_with("REVOKE") {
                let g = parse(&stmt, "REVOKE", " FROM ")
                    .unwrap_or_else(|| panic!("{file}: unparsed REVOKE: {stmt}"));
                let Some(xml) = xml_grants(&g.user) else { continue };
                for p in &g.privileges {
                    checked += 1;
                    if covered(&xml, p, &g.target) {
                        missing.push(format!("{file}: users.d still grants revoked {p} ON {} to {}", g.target, g.user));
                    }
                }
            }
        }
    }
    // 173 (2) + 183 (1) + 185 (1 REVOKE) + 188 (4) at the time of writing.
    assert!(checked >= 8, "parsed only {checked} migration GRANT/REVOKE privileges");
    assert!(
        missing.is_empty(),
        "users.d XML users ignore SQL GRANT/REVOKE (ACCESS_STORAGE_READONLY), so \
         clickhouse/users.d/nanosiem-users.xml must carry the change (then run \
         deploy/helm/nano/scripts/sync-files.sh):\n{}",
        missing.join("\n")
    );
}

#[test]
fn coverage_rules_are_not_vacuous() {
    let xml = xml_grants("nanosiem").expect("nanosiem user");
    assert!(covered(&xml, "ALTER DELETE", "nanosiem.lookup_rows"));
    assert!(covered(&xml, "SELECT", "system.processes"));
    // Column-restricted SELECT on system.parts is not a full SELECT.
    assert!(!covered(&xml, "SELECT", "system.parts"));
    assert!(!covered(&xml, "SELECT", "system.users"));
    let ingest = xml_grants("nanosiem_ingest").expect("nanosiem_ingest user");
    assert!(!covered(&ingest, "DICTGET", "nanosiem.ip_enrichment_dict"));
    assert!(xml_grants("some_sql_created_user").is_none());
}
