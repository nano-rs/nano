// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3782: core migrations must alter RLS-registered tables inside the
//! 9000140 managed-owner bootstrap window.
//!
//! Core migrations (`migrations/postgres`) also run on the activated hosted
//! hosted shared database, where every table in
//! `nano_shared.rls_table_registry` / `rls_read_table_registry` is owned by
//! the NOLOGIN data owner. The migrator holds that role only as a creator
//! grant (`INHERIT FALSE, SET FALSE`), so plain DDL on such a table fails
//! with "must be owner of table ..." (r49 staging, migration 354). The
//! fresh-DB and open-core proofs never see this.
//!
//! This scan collects the registered tables from every registry INSERT in
//! the core and enterprise migrations, then fails when a core migration at or
//! after [`FIRST_CHECKED_VERSION`] runs ALTER TABLE / COMMENT ON / DROP TABLE /
//! trigger / policy / index / GRANT / REVOKE DDL on one of them outside a
//! `DO` block that either opens the window
//! (`nano_shared.begin_managed_owner_bootstrap` ... `end_managed_owner_bootstrap`,
//! as 341 / 346 / 360 do) or skips when the migrator does not own the table
//! (`pg_has_role(current_user, <owner>, 'USAGE')` early return, deferring to
//! an enterprise twin, as 350 / 352 do). Tables created in the same file are
//! exempt: the migrator owns what it just created.
//!
//! Function bodies (`CREATE FUNCTION ... AS $$ ... $$`) are skipped: they run
//! later as their caller, not as the migrator.
//!
//! NAN-4265: `scripts/check-core-migration-owner-window.py` is a port of this
//! scan that `scripts/build-publish-control.sh` runs on every control build,
//! because core 373 failed this test and still reached a live control migrate
//! while CI tests were on hold. Change both together.

use regex::Regex;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Earlier core migrations are applied on the live hosted database and are
/// immutable; 340 / 350 / 352 used the ownership-skip pattern. 354 and 357
/// were the first two to break the rule and are retired by NAN-3782.
const FIRST_CHECKED_VERSION: u64 = 354;

/// NAN-4340: enterprise migrations are scanned from the first one applied in
/// no region. 9014400 created triggers on the owner-held alerts / cases /
/// case_workflow_events outside the window and failed FP-T75 with
/// "permission denied for table alerts". Never lower this floor: older
/// enterprise migrations are applied and immutable.
const FIRST_CHECKED_ENTERPRISE_VERSION: u64 = 9_014_400;

fn migrations_dir(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../migrations").join(name)
}

fn sql_files(dir: &Path) -> Vec<(u64, String, String)> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display())) {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("sql") {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let Some(version) = name.split('_').next().and_then(|v| v.parse::<u64>().ok()) else {
            continue;
        };
        out.push((version, name, std::fs::read_to_string(&path).unwrap()));
    }
    out.sort();
    out
}

/// Lowercase and drop `--` line comments (headers quote DDL in prose).
fn normalize(sql: &str) -> String {
    sql.lines()
        .map(|line| match line.find("--") {
            Some(i) => &line[..i],
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n")
        .to_lowercase()
}

#[derive(Debug, PartialEq)]
enum SegmentKind {
    TopLevel,
    /// A `DO` body that opens the owner window or skips non-owned tables.
    GuardedDo,
    UnguardedDo,
}

/// Split normalized SQL into top-level text and `DO` bodies; dollar-quoted
/// bodies of anything other than `DO` (function / procedure bodies) are dropped.
fn segments(sql: &str) -> Vec<(SegmentKind, String)> {
    let tag_re = Regex::new(r"\$[a-z0-9_]*\$").unwrap();
    let do_tail = Regex::new(r"\bdo\s*$").unwrap();
    let mut out = Vec::new();
    let mut top = String::new();
    let mut pos = 0;
    while let Some(open) = tag_re.find_at(sql, pos) {
        let tag = open.as_str();
        let Some(close_rel) = sql[open.end()..].find(tag) else {
            break;
        };
        let before = &sql[pos..open.start()];
        top.push_str(before);
        top.push('\n');
        let body = &sql[open.end()..open.end() + close_rel];
        if do_tail.is_match(before) {
            let windowed = body.contains("nano_shared.begin_managed_owner_bootstrap")
                && body.contains("nano_shared.end_managed_owner_bootstrap");
            let ownership_skip = body.contains("pg_has_role(current_user")
                && body.contains("'usage'")
                && body.contains("return;");
            let kind = if windowed || ownership_skip {
                SegmentKind::GuardedDo
            } else {
                SegmentKind::UnguardedDo
            };
            out.push((kind, body.to_owned()));
        }
        pos = open.end() + close_rel + tag.len();
    }
    top.push_str(&sql[pos..]);
    out.push((SegmentKind::TopLevel, top));
    out
}

fn created_tables(sql: &str) -> BTreeSet<String> {
    let re = Regex::new(
        r#"create\s+(?:unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?(?:public\.)?"?([a-z_][a-z0-9_]*)"#,
    )
    .unwrap();
    re.captures_iter(sql).map(|c| c[1].to_owned()).collect()
}

/// Every table a registry INSERT names, in either registry, across core and
/// enterprise migrations. Literal names are matched against tables some
/// migration creates, which drops `'public'` / `'tenant_id'` and friends.
fn registered_tables(files: &[(u64, String, String)]) -> BTreeSet<String> {
    let all_created: BTreeSet<String> =
        files.iter().flat_map(|(_, _, sql)| created_tables(&normalize(sql))).collect();
    let insert_re =
        Regex::new(r"insert\s+into\s+nano_shared\.rls_(?:read_)?table_registry").unwrap();
    let literal_re = Regex::new(r"'([a-z_][a-z0-9_]*)'").unwrap();
    let tag_re = Regex::new(r"\$[a-z0-9_]*\$").unwrap();
    let mut registered = BTreeSet::new();
    let mut take = |text: &str| {
        for c in literal_re.captures_iter(text) {
            if all_created.contains(&c[1]) {
                registered.insert(c[1].to_owned());
            }
        }
    };
    for (_, _, raw) in files {
        let sql = normalize(raw);
        // Plain statements: `INSERT INTO nano_shared.rls_table_registry ... VALUES (...);`
        for stmt in sql.split(';') {
            if insert_re.is_match(stmt) {
                take(stmt);
            }
        }
        // Blocks that loop a table array into the registry with a variable.
        let mut pos = 0;
        while let Some(open) = tag_re.find_at(&sql, pos) {
            let Some(close_rel) = sql[open.end()..].find(open.as_str()) else {
                break;
            };
            let body = &sql[open.end()..open.end() + close_rel];
            if insert_re.is_match(body) {
                take(body);
            }
            pos = open.end() + close_rel + open.as_str().len();
        }
    }
    registered
}

fn ddl_re() -> Regex {
    Regex::new(
        r#"\b(alter\s+table(?:\s+if\s+exists)?(?:\s+only)?|comment\s+on\s+(?:table|column)|drop\s+table(?:\s+if\s+exists)?|(?:create|drop)\s+(?:or\s+replace\s+)?(?:constraint\s+)?trigger\b[^;]*?\bon|(?:create|drop)\s+policy\b[^;]*?\bon|create\s+(?:unique\s+)?index\b[^;]*?\bon(?:\s+only)?|grant\b[^;]*?\bon(?:\s+table)?|revoke\b[^;]*?\bon(?:\s+table)?)\s+(?:public\.)?"?([a-z_][a-z0-9_]*)"#,
    )
    .unwrap()
}

/// `(statement head, table)` for each owner-only DDL on a registered table
/// that runs outside the window.
fn violations(sql: &str, registered: &BTreeSet<String>) -> Vec<(String, String)> {
    let sql = normalize(sql);
    let own = created_tables(&sql);
    let ddl = ddl_re();
    let mut found = Vec::new();
    for (kind, text) in segments(&sql) {
        if kind == SegmentKind::GuardedDo {
            continue;
        }
        for c in ddl.captures_iter(&text) {
            let table = c[2].to_owned();
            if registered.contains(&table) && !own.contains(&table) {
                let head: String = c[1].split_whitespace().take(2).collect::<Vec<_>>().join(" ");
                found.push((head, table));
            }
        }
    }
    found
}

fn all_files() -> (Vec<(u64, String, String)>, BTreeSet<String>) {
    let core = sql_files(&migrations_dir("postgres"));
    let mut every = core.clone();
    every.extend(sql_files(&migrations_dir("postgres-enterprise")));
    let registered = registered_tables(&every);
    (core, registered)
}

#[test]
fn registry_scan_finds_the_known_owner_held_tables() {
    let (_, registered) = all_files();
    for table in ["cloud_credentials", "parser_repositories", "rule_repositories", "connector_feeds", "retro_hunt_rule_state"] {
        assert!(registered.contains(table), "registry scan lost {table}");
    }
    assert!(registered.len() > 100, "registry scan found only {} tables", registered.len());
}

#[test]
fn core_migrations_alter_registered_tables_only_inside_the_owner_window() {
    let (core, registered) = all_files();
    let mut failures = Vec::new();
    for (version, name, sql) in &core {
        if *version < FIRST_CHECKED_VERSION {
            continue;
        }
        for (head, table) in violations(sql, &registered) {
            failures.push(format!("{name}: {head} {table}"));
        }
    }
    assert!(
        failures.is_empty(),
        "core migrations run owner-only DDL on RLS-registered tables outside the \
         managed-owner bootstrap window (wrap it in a DO block that calls \
         nano_shared.begin_managed_owner_bootstrap / end_managed_owner_bootstrap \
         when nano_shared.rls_role_contract is enabled; see 360):\n  {}",
        failures.join("\n  ")
    );
}

#[test]
fn unapplied_enterprise_migrations_alter_registered_tables_only_inside_the_owner_window() {
    let (_, registered) = all_files();
    let mut failures = Vec::new();
    let enterprise = sql_files(&migrations_dir("postgres-enterprise"));
    for (version, name, sql) in &enterprise {
        if *version < FIRST_CHECKED_ENTERPRISE_VERSION {
            continue;
        }
        for (head, table) in violations(sql, &registered) {
            failures.push(format!("{name}: {head} {table}"));
        }
    }
    assert!(
        failures.is_empty(),
        "enterprise migrations run owner-only DDL on RLS-registered tables outside the \
         managed-owner bootstrap window (wrap it in a DO block that opens \
         begin/end_managed_owner_bootstrap, as 9014700 does):\n  {}",
        failures.join("\n  ")
    );
    // The shipped 9014400 trigger statement that failed FP-T75 is caught.
    let shipped_9014400 = "CREATE TRIGGER soar_alert_committed AFTER INSERT ON public.alerts \
        FOR EACH ROW EXECUTE FUNCTION nano_shared.enqueue_soar_source_event();";
    assert_eq!(violations(shipped_9014400, &registered), vec![("create trigger".to_string(), "alerts".to_string())]);
}

/// The two bodies NAN-3782 retired must be caught, and their replacements pass.
#[test]
fn scan_rejects_the_retired_354_and_357_bodies() {
    let (_, registered) = all_files();
    let retired_354 = "SET LOCAL lock_timeout = '5s';
ALTER TABLE public.cloud_credentials
    DROP CONSTRAINT IF EXISTS cloud_credentials_provider_check;
ALTER TABLE public.cloud_credentials
    ADD CONSTRAINT cloud_credentials_provider_check
    CHECK (provider IN ('aws_s3', 'azure_event_hubs'));
COMMENT ON COLUMN public.cloud_credentials.provider IS 'x';";
    assert_eq!(
        violations(retired_354, &registered),
        vec![
            ("alter table".to_owned(), "cloud_credentials".to_owned()),
            ("alter table".to_owned(), "cloud_credentials".to_owned()),
            ("comment on".to_owned(), "cloud_credentials".to_owned()),
        ]
    );
    let retired_357 = "CREATE OR REPLACE FUNCTION public.f() RETURNS trigger LANGUAGE plpgsql AS $function$
BEGIN ALTER TABLE public.rule_repositories ALTER COLUMN branch DROP DEFAULT; RETURN NEW; END
$function$;
ALTER TABLE public.parser_repositories ALTER COLUMN branch DROP DEFAULT;
DROP TRIGGER IF EXISTS t ON public.parser_repositories;
CREATE TRIGGER t BEFORE INSERT ON public.rule_repositories FOR EACH ROW EXECUTE FUNCTION public.f();";
    // The ALTER inside the function body is not reported: it is not migration DDL.
    assert_eq!(
        violations(retired_357, &registered),
        vec![
            ("alter table".to_owned(), "parser_repositories".to_owned()),
            ("drop trigger".to_owned(), "parser_repositories".to_owned()),
            ("create trigger".to_owned(), "rule_repositories".to_owned()),
        ]
    );

    let unguarded_do = "DO $x$ BEGIN ALTER TABLE public.cloud_credentials ADD COLUMN y INT; END $x$;";
    assert_eq!(violations(unguarded_do, &registered).len(), 1);
    let created_here = "CREATE TABLE IF NOT EXISTS public.cloud_credentials (id INT);
ALTER TABLE public.cloud_credentials ADD COLUMN y INT;";
    assert!(violations(created_here, &registered).is_empty());

    // NAN-4265: the 373 body #7238 shipped (hosted roll: "must be owner of
    // table retro_hunt_rule_state").
    let shipped_373 = "ALTER TABLE retro_hunt_rule_state
    ADD COLUMN IF NOT EXISTS platform_revisions JSONB;";
    assert_eq!(
        violations(shipped_373, &registered),
        vec![("alter table".to_owned(), "retro_hunt_rule_state".to_owned())]
    );

    for file in [
        "352_connector_feed_pending_delete.sql",
        "360_cloud_credentials_azure_event_hubs.sql",
        "361_first_party_ocsf_content_defaults.sql",
        "367_first_party_content_follows_main.sql",
        "373_retro_hunt_platform_revisions.sql",
    ] {
        let sql = std::fs::read_to_string(migrations_dir("postgres").join(file)).unwrap();
        assert!(violations(&sql, &registered).is_empty(), "{file}");
    }
}

/// NAN-4265: core 373 skips an owner-held retro_hunt_rule_state and defers to
/// enterprise 9014295, which must apply the SAME body inside the window.
#[test]
fn retro_hunt_platform_revisions_twin_bodies_match() {
    let body = |dir: &str, file: &str| {
        let sql = std::fs::read_to_string(migrations_dir(dir).join(file)).unwrap();
        let (begin, end) = ("-- BEGIN retro_hunt_platform_revisions body", "-- END retro_hunt_platform_revisions body");
        let start = sql.find(begin).unwrap_or_else(|| panic!("{file}: no body start marker")) + begin.len();
        let stop = sql.find(end).unwrap_or_else(|| panic!("{file}: no body end marker"));
        sql[start..stop].to_owned()
    };
    let core = body("postgres", "373_retro_hunt_platform_revisions.sql");
    assert!(core.contains("ADD COLUMN IF NOT EXISTS platform_revisions JSONB"), "{core}");
    assert_eq!(core, body("postgres-enterprise", "9014295_retro_hunt_platform_revisions.sql"));
}
