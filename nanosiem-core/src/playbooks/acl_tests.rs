// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unit tests for the per-playbook ACL policy (NAN-2097).
//!
//! These pin the SQL *shape* of the predicate. The end-to-end behaviour (a
//! `can_view = FALSE` row actually hiding a playbook from list and get) is
//! covered by the `#[ignore]`d Postgres integration tests in
//! `nanosiem-core/tests/playbook_acl_integration.rs`.

use super::*;

fn builder_sql(action: PlaybookAction, principal: &PlaybookPrincipal) -> String {
    let mut qb: QueryBuilder<Postgres> = QueryBuilder::new("");
    push_acl(&mut qb, "playbooks.id", action, principal);
    qb.into_sql()
}

/// Placeholder numbering differs between the two builders (the `QueryBuilder`
/// form binds the role array once per clause), so normalise `$1`/`$2`/… to `$?`
/// before comparing. Everything structural — subquery form, column names,
/// AND/OR nesting — still has to match exactly.
fn normalize(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len());
    let mut chars = sql.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '$' {
            while matches!(chars.peek(), Some(d) if d.is_ascii_digit()) {
                chars.next();
            }
            out.push_str("$?");
        } else {
            out.push(c);
        }
    }
    out
}

#[test]
fn each_action_maps_to_its_permission_column() {
    assert_eq!(PlaybookAction::View.column(), "can_view");
    assert_eq!(PlaybookAction::Run.column(), "can_run");
    assert_eq!(PlaybookAction::Edit.column(), "can_edit");
    assert_eq!(PlaybookAction::Publish.column(), "can_publish");
}

#[test]
fn all_covers_every_action_exactly_once() {
    let unique: std::collections::BTreeSet<PlaybookAction> =
        PlaybookAction::ALL.into_iter().collect();
    assert_eq!(unique.len(), PlaybookAction::ALL.len());
}

/// The two spellings of the predicate must never drift — the repository uses
/// `acl_sql` for hand-written `$n` statements and `push_acl` for the
/// dynamically-filtered list/count queries, and a divergence would mean the
/// collection is filtered by a different rule than the object read.
#[test]
fn both_predicate_builders_agree() {
    let principal = PlaybookPrincipal::from_role_ids(vec![Uuid::from_u128(2)]);
    for action in PlaybookAction::ALL {
        let hand = acl_sql("playbooks.id", action, "$1", "$2", "$3");
        let built = builder_sql(action, &principal);
        assert_eq!(
            normalize(&hand),
            normalize(&built),
            "predicate builders disagree for {action:?}"
        );
    }
}

/// An un-ACL'd playbook stays visible: the `NOT EXISTS` half is what keeps
/// enforcement strictly additive on every existing deployment.
#[test]
fn predicate_is_open_when_the_playbook_has_no_acl_rows() {
    for action in PlaybookAction::ALL {
        let sql = acl_sql("playbooks.id", action, "$1", "$2", "$3");
        assert!(
            sql.contains("NOT EXISTS (SELECT 1 FROM playbook_permissions pp WHERE pp.playbook_id = playbooks.id)"),
            "{action:?} predicate must treat an empty ACL as open"
        );
    }
}

/// `can_view` is the floor for every other action — a `can_run`-only row must
/// not let a caller read the steps it would have to render to run them.
#[test]
fn non_view_actions_require_can_view_as_well() {
    for action in [
        PlaybookAction::Run,
        PlaybookAction::Edit,
        PlaybookAction::Publish,
    ] {
        let sql = acl_sql("playbooks.id", action, "$1", "$2", "$3");
        assert!(
            sql.contains("pp.can_view"),
            "{action:?} must conjoin the can_view floor"
        );
        assert!(
            sql.contains(&format!("pp.{}", action.column())),
            "{action:?} must test its own column"
        );
        assert!(sql.contains(" AND "), "{action:?} must be a conjunction");
    }
}

/// codex round 6 (P1): `can_view` and the action flag must sit on ONE row.
///
/// The earlier form emitted two independent `EXISTS` clauses, so grants composed
/// across rows: role A granting only `can_view`, plus role B granting `can_edit`
/// with `can_view = FALSE`, authorized editing. Exactly ONE `EXISTS` subquery may
/// appear per predicate, and it must carry both flags.
#[test]
fn view_and_action_flags_must_share_a_single_exists_subquery() {
    for action in [
        PlaybookAction::Run,
        PlaybookAction::Edit,
        PlaybookAction::Publish,
    ] {
        let sql = acl_sql("playbooks.id", action, "$1", "$2", "$3");
        assert_eq!(
            sql.matches("OR EXISTS (SELECT 1 FROM playbook_permissions pp").count(),
            1,
            "{action:?} must use a single grant subquery, not one per flag: {sql}"
        );
        assert!(
            sql.contains(&format!("pp.can_view AND pp.{}", action.column())),
            "{action:?} must require both flags on the same row: {sql}"
        );
        // And exactly one "no ACL rows" escape, so the open-by-default branch
        // cannot be satisfied independently per flag either.
        assert_eq!(
            sql.matches("NOT EXISTS (SELECT 1 FROM playbook_permissions pp").count(),
            1,
            "{action:?}: {sql}"
        );
    }
}

/// The View predicate must NOT drag in any other column — otherwise a plain
/// read would silently demand run/edit/publish.
#[test]
fn view_predicate_tests_only_can_view() {
    let sql = acl_sql("playbooks.id", PlaybookAction::View, "$1", "$2", "$3");
    assert!(sql.contains("pp.can_view"));
    assert!(!sql.contains("pp.can_run"));
    assert!(!sql.contains("pp.can_edit"));
    assert!(!sql.contains("pp.can_publish"));
}

/// The SYSTEM bypass has to be the FIRST disjunct so a background caller is
/// never blocked by a tenant ACL it has no way to satisfy.
#[test]
fn system_placeholder_short_circuits_the_predicate() {
    for action in PlaybookAction::ALL {
        let sql = acl_sql("playbooks.id", action, "$7", "$8", "$9");
        assert!(
            sql.starts_with("($7 OR "),
            "{action:?} must lead with the SYSTEM bypass, got: {sql}"
        );
    }
}

/// An API key holds NO real role ids — only the synthetic label. That is what
/// makes a tenant role named `api_key` unable to satisfy an entry meant for keys:
/// such a role resolves to an id and matches the `role_id` branch, never the
/// `role_id IS NULL AND role = ANY(...)` branch.
#[test]
fn api_key_principal_carries_only_the_synthetic_label() {
    let principal = PlaybookPrincipal::api_key();
    assert!(principal.role_ids().is_empty());
    assert_eq!(principal.synthetic_roles(), &["api_key".to_string()]);
    assert!(!principal.is_system());
    assert_eq!(API_KEY_ROLE, "api_key");
}

#[test]
fn both_synthetic_labels_are_recognised_and_nothing_else_is() {
    assert!(is_synthetic_role(API_KEY_ROLE));
    assert!(is_synthetic_role(DEMO_ROLE));
    assert!(!is_synthetic_role("Editor"));
    assert!(!is_synthetic_role("soc-leads"));
    assert!(!is_synthetic_role(""));
    assert_eq!(SYNTHETIC_ROLES.len(), 2);
}

/// The predicate must match real roles on `role_id` and synthetic principals on
/// the `role` TEXT with `role_id IS NULL` — never a bare name comparison, which
/// is what let a rename orphan a grant and a look-alike role capture one.
#[test]
fn real_roles_match_on_role_id_and_synthetics_on_a_null_keyed_label() {
    for action in PlaybookAction::ALL {
        let sql = acl_sql("playbooks.id", action, "$1", "$2", "$3");
        assert!(sql.contains("pp.role_id = ANY($2)"), "{action:?}: {sql}");
        assert!(
            sql.contains("pp.role_id IS NULL AND pp.role = ANY($3)"),
            "{action:?}: {sql}"
        );
        // No unqualified name comparison may remain.
        assert!(
            !sql.contains("pp.role = ANY($2)"),
            "{action:?} still compares the role NAME against the id set: {sql}"
        );
    }
}

#[test]
fn system_principal_is_system_and_has_no_grants() {
    let principal = PlaybookPrincipal::System;
    assert!(principal.is_system());
    assert!(principal.role_ids().is_empty());
    assert!(principal.synthetic_roles().is_empty());
}

/// A principal with no resolved grants is fail-closed: it matches no ACL row, so
/// any playbook carrying an ACL denies it. (Both `= ANY('{}')` tests are false
/// for every row.)
#[test]
fn grantless_principal_is_not_system() {
    let principal = PlaybookPrincipal::from_role_ids(Vec::new());
    assert!(!principal.is_system());
    assert!(principal.role_ids().is_empty());
    assert!(principal.synthetic_roles().is_empty());
}

/// The predicate must be parenthesised as a single unit so callers can `AND` it
/// onto an existing WHERE without its `OR`s escaping and widening the query —
/// the "appending a gate to SQL is not enforcement" failure mode from NAN-2158.
#[test]
fn predicate_is_a_self_contained_parenthesised_unit() {
    for action in PlaybookAction::ALL {
        let sql = acl_sql("playbooks.id", action, "$1", "$2", "$3");
        assert!(sql.starts_with('('), "{action:?}: {sql}");
        assert!(sql.ends_with(')'), "{action:?}: {sql}");
        let mut depth = 0i32;
        for (i, c) in sql.chars().enumerate() {
            match c {
                '(' => depth += 1,
                ')' => depth -= 1,
                _ => {}
            }
            // Depth may only return to 0 at the very last character; if it hit
            // zero earlier the trailing text would sit outside the group.
            if depth == 0 {
                assert_eq!(i, sql.len() - 1, "{action:?} closes early: {sql}");
            }
            assert!(depth >= 0, "{action:?} unbalanced: {sql}");
        }
        assert_eq!(depth, 0, "{action:?} unbalanced: {sql}");
    }
}
