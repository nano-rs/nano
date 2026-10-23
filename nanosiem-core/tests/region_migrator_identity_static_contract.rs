// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4146: migrations must run under the managed-region migrator identity.
//!
//! A managed (PlanetScale) region migrates as a provider login
//! (`pscale_api_*`, a member of postgres) whose per-role default is
//! `role=postgres`. So `current_user` is postgres but `session_user` is not.
//! Once a region is activated, every migration that opens the data owner's
//! window goes through `nano_shared.begin_managed_owner_bootstrap`, either
//! directly or via `reconcile_runtime_sequence_grants()` and friends. While
//! that window demanded `session_user = 'postgres'`, 9014070 and then 9014200
//! each stopped East's roll with "managed owner bootstrap identity rejected".
//! Fresh-DB and session-postgres proofs never see it.
//!
//! The lint:
//! 1. The newest definitions of begin/end_managed_owner_bootstrap gate on
//!    `nano_shared.migrator_session_attested()`, never on a session-postgres
//!    equality.
//! 2. `migrator_session_attested()` keeps the 9013920 provider-login branch.
//! 3. Any migration that calls a window helper (or a reconcile built on it)
//!    is numbered after the 9014240 fix, or is frozen at or below 9014230.
//! 4. No migration after 9014240 hand-rolls a session-postgres-only identity
//!    gate. Use `nano_shared.migrator_session_attested()` instead.
//!
//! `scripts/nan4146-region-migrator/run.sh` is the runtime proof: a
//! throwaway PG18 with the managed role layout and the provider-login
//! migrator.

use std::path::{Path, PathBuf};

/// 9014240 makes the managed-owner window accept the region migrator.
const REGION_SAFE_WINDOW_VERSION: u64 = 9_014_240;
/// Last enterprise number reserved before the fix. Every file at or below it
/// opens the owner window through its own region-safe gate (9014070's inline
/// window, 9014200's landing_source_owner_window_*) or ran before activation.
/// 9014230 is reserved by a concurrent lane.
const FROZEN_BEFORE_FIX: u64 = 9_014_230;
/// Core migrations after this one are new and get the gate scan (rule 4).
const CORE_FROZEN_THROUGH: u64 = 372;

/// Calls that open the managed-owner window, directly or through a reconcile.
const WINDOW_CALLS: &[&str] = &[
    "begin_managed_owner_bootstrap(",
    "end_managed_owner_bootstrap(",
    "reconcile_runtime_sequence_grants(",
    "reconcile_runtime_table_ceiling(",
];

/// Identity gates that reject the provider-login migrator.
const SESSION_POSTGRES_GATES: &[&str] = &[
    "session_user <> current_user",
    "session_user != current_user",
    "session_user = current_user",
    "current_user <> session_user",
    "current_user = session_user",
    "session_user = 'postgres'",
    "session_user <> 'postgres'",
    "session_user != 'postgres'",
];

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

/// Lowercase, drop `--` line comments, collapse whitespace.
fn normalize(sql: &str) -> String {
    let stripped: Vec<&str> = sql.lines().map(|line| line.split("--").next().unwrap_or("")).collect();
    stripped.join(" ").to_lowercase().split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The body of the newest `CREATE [OR REPLACE] FUNCTION <name>(` across the
/// enterprise migrations, with its version.
fn newest_definition(name: &str) -> (u64, String) {
    let needle = format!("function {name}(");
    let mut found = None;
    for (version, _, sql) in sql_files(&migrations_dir("postgres-enterprise")) {
        let text = normalize(&sql);
        let definition = text.match_indices(&needle).map(|(start, _)| start).filter(|&start| {
            let head = &text[..start];
            head.ends_with("create ") || head.ends_with("create or replace ")
        });
        if let Some(start) = definition.last() {
            let body = &text[start..];
            let end = body.find("revoke all on function").unwrap_or(body.len());
            found = Some((version, body[..end].to_string()));
        }
    }
    found.unwrap_or_else(|| panic!("{name} is defined by some migration"))
}

#[test]
fn managed_owner_window_accepts_the_region_migrator() {
    for name in ["nano_shared.begin_managed_owner_bootstrap", "nano_shared.end_managed_owner_bootstrap"] {
        let (version, body) = newest_definition(name);
        assert!(
            version >= REGION_SAFE_WINDOW_VERSION,
            "{name}: newest definition is {version}, older than the region-safe {REGION_SAFE_WINDOW_VERSION}"
        );
        assert!(
            body.contains("nano_shared.migrator_session_attested()"),
            "{name} (migration {version}) must gate on nano_shared.migrator_session_attested()"
        );
        for gate in SESSION_POSTGRES_GATES {
            assert!(!body.contains(gate), "{name} (migration {version}) reintroduced `{gate}`");
        }
        assert!(body.contains("security invoker"), "{name} stays SECURITY INVOKER");
    }
}

#[test]
fn migrator_identity_keeps_the_provider_login_branch() {
    let (version, body) = newest_definition("nano_shared.migrator_session_attested");
    for required in [
        "current_user = 'postgres'",
        "session_user = 'postgres'",
        "session_user <> 'pscale_admin'",
        "starts_with(session_user::text, 'pscale_api_')",
        "rolcanlogin",
        "pg_has_role(session_user, 'postgres', 'member')",
    ] {
        assert!(body.contains(required), "migrator_session_attested (migration {version}) lost `{required}`");
    }
}

#[test]
fn window_callers_run_after_the_region_safe_window() {
    let mut offenders = Vec::new();
    for (version, name, sql) in sql_files(&migrations_dir("postgres-enterprise")) {
        if version <= FROZEN_BEFORE_FIX || version >= REGION_SAFE_WINDOW_VERSION {
            continue;
        }
        let text = normalize(&sql);
        if WINDOW_CALLS.iter().any(|call| text.contains(call)) {
            offenders.push(name);
        }
    }
    assert!(
        offenders.is_empty(),
        "these migrations open the managed-owner window before {REGION_SAFE_WINDOW_VERSION} makes it \
         region-migrator safe; renumber them above it: {offenders:?}"
    );
}

#[test]
fn new_migrations_do_not_hand_roll_session_postgres_gates() {
    let mut offenders = Vec::new();
    let scans = [
        ("postgres-enterprise", REGION_SAFE_WINDOW_VERSION),
        ("postgres", CORE_FROZEN_THROUGH),
    ];
    for (dir, after) in scans {
        for (version, name, sql) in sql_files(&migrations_dir(dir)) {
            if version <= after {
                continue;
            }
            let text = normalize(&sql);
            for gate in SESSION_POSTGRES_GATES {
                if text.contains(gate) {
                    offenders.push(format!("{dir}/{name}: `{gate}`"));
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "a session-postgres identity gate rejects the managed-region migrator (provider login with \
         default role postgres); gate on nano_shared.migrator_session_attested() instead:\n  {}",
        offenders.join("\n  ")
    );
}

/// The lint must actually see the files it reasons about.
#[test]
fn lint_inputs_are_present() {
    let enterprise = sql_files(&migrations_dir("postgres-enterprise"));
    for version in [9_014_070, 9_014_200, REGION_SAFE_WINDOW_VERSION] {
        assert!(enterprise.iter().any(|(v, _, _)| *v == version), "migration {version} exists");
    }
    assert!(
        enterprise.iter().any(|(v, _, sql)| *v > REGION_SAFE_WINDOW_VERSION
            && normalize(sql).contains("begin_managed_owner_bootstrap(")),
        "a later migration (9014250) calls the window and is covered by the scan"
    );
    assert!(sql_files(&migrations_dir("postgres")).iter().any(|(v, _, _)| *v == CORE_FROZEN_THROUGH));
}
