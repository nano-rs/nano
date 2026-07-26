// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-playbook role ACL policy (NAN-2097).
//!
//! `playbook_permissions` has existed since migration `157_playbooks.sql`
//! (`COMMENT ON TABLE … 'Per-playbook ACL: which roles can view/run/edit/publish'`)
//! but **nothing ever read it**. Every playbook handler authorized only the
//! tenant-wide coarse capability (`playbooks:view` / `:run` / `:manage` /
//! `:publish`), so a principal explicitly denied by a `can_* = FALSE` row could
//! still list, read, run, edit, publish and delete the playbook. This module is
//! the single authoritative evaluator that closes that gap.
//!
//! # Keyed on `role_id`, not the role name
//!
//! The first cut of this fix matched `playbook_permissions.role` (free-form TEXT)
//! against resolved role NAMES. codex round 5 showed that produces three
//! independent P1 failure modes, all from the same root cause — a role name is
//! neither stable nor reserved:
//!
//! 1. `RoleRepository::update_role` permits renaming any non-system role.
//!    Renaming the sole ACL editor silently orphaned its grant, making the
//!    playbook unrepairable; later re-creating a role with the old name
//!    *transferred* those grants to a different role.
//! 2. `RESERVED_ROLE_NAMES` reserves only `demo_analyst`, so an operator could
//!    create an ordinary tenant role literally named `api_key` whose members
//!    would then match ACL grants meant exclusively for API keys.
//! 3. `DELETE`ing a role left its entries behind as permanent denials.
//!
//! So ordinary real roles are matched on `role_id` (`REFERENCES roles(id) ON
//! DELETE RESTRICT`): stable across renames, collision-proof against any name an
//! operator can type, and explicitly unwound before role deletion. Synthetic
//! principals are matched on `role` with `role_id IS NULL`. A legacy real role
//! already named `demo_analyst` is deliberately mapped to that same synthetic
//! principal because its permissions and source isolation are already derived
//! from the name; renaming it would widen its members' access.
//!
//! # Semantics (the questions NAN-2097 required to be answered explicitly)
//!
//! * **Legacy / un-ACL'd playbooks.** A playbook with **no** `playbook_permissions`
//!   rows is unrestricted: the coarse capability alone governs it. Migration 268
//!   normalizes pre-existing rows so this is the state every deployment starts
//!   from unless somebody deliberately configured a coherent ACL.
//! * **ACL present ⇒ authoritative.** Once a playbook has at least one row, the
//!   caller must hold a role with the requested flag set. The columns default to
//!   `FALSE`, so a row is a *grant* list, not a deny list.
//! * **Multiple roles ⇒ union of grants.** A caller holding several roles is
//!   allowed if **any** of them grants the flag. One role's `FALSE` never vetoes
//!   another role's `TRUE` — matching how the global RBAC permission set is
//!   composed (union across the caller's roles).
//! * **`can_view` is the floor, on the SAME row.** `Run` / `Edit` / `Publish` all
//!   imply reading the playbook's steps, so each requires ONE row granting
//!   `can_view AND can_<action>`. A row granting `can_run` without `can_view`
//!   grants nothing, and the two halves cannot be composed from different rows:
//!   role A's `can_view` plus role B's view-less `can_edit` does NOT authorize
//!   editing (codex round 6). Every entry is therefore a self-contained grant.
//! * **API keys** evaluate against the single synthetic principal
//!   [`API_KEY_ROLE`], the role their `AuthContext` actually carries. A key does
//!   **not** inherit its owner's roles — an API key is its own authorization
//!   principal (NAN-2043), so a restricted key cannot borrow a human's grants.
//! * **Interactive sessions** evaluate against role IDs resolved from the
//!   DATABASE at request time ([`resolve_principal`]), not from `claims.roles`
//!   (except that a legacy name-derived `demo_analyst` database role maps to the
//!   matching synthetic principal).
//!   `TokenClaims::roles` is documented as "used for UI display, not authorization
//!   decisions" and is trusted from a JWT that can be up to `ACCESS_TOKEN_TTL`
//!   (900s) stale — a revoked group membership must take effect immediately.
//! * **Demo sessions** additionally carry [`DEMO_ROLE`], but only after
//!   `demo.sessions` confirms the session is live. Demo users hold no group role
//!   assignments, so without it an ACL could never grant them access.
//! * **Non-disclosure.** Direct object reads return `NotFound` (404) rather than
//!   403 when the ACL denies, so the ACL is not a playbook-existence oracle.
//! * **SYSTEM callers** ([`PlaybookPrincipal::System`]) bypass the ACL. Background
//!   auto-attach on rule fire and shadow-investigation adaptive compose have no
//!   request principal; they already bypass the case-visibility gate the same way
//!   (`user_id = None`, NAN-2044).
//!
//! # SQL shape
//!
//! Reads emit the predicate inside the statement. Multi-statement mutations lock
//! the parent playbook first, then evaluate the ACL in a fresh READ COMMITTED
//! statement snapshot while retaining that lock; this makes a revocation that
//! started first win without opening a check-then-act window. Two predicate
//! spellings exist because the repository uses both hand-written `$n` SQL and
//! `QueryBuilder`; [`tests::both_predicate_builders_agree`] pins them to the same
//! text so they cannot drift.

use sqlx::{PgPool, Postgres, QueryBuilder};
use uuid::Uuid;

/// The synthetic principal an API-key caller is evaluated as.
///
/// Mirrors `AuthContext::from_api_key`, which sets `claims.roles = ["api_key"]`.
/// Matched with `role_id IS NULL`, so a tenant role that happens to be named
/// `api_key` can never satisfy an entry meant for API keys.
pub const API_KEY_ROLE: &str = "api_key";

/// The synthetic principal a verified demo session is evaluated as.
///
/// Demo users normally have NO group role assignments — the role is injected at
/// session creation and re-injected on refresh (`AuthService`, guarded by
/// `demo::is_demo_session_active`). New tenant roles cannot take this reserved
/// name. A legacy database role that already has it remains name-derived and is
/// deliberately resolved to this same principal, preserving its demo permission
/// and source-isolation semantics through the NAN-2097 migration.
pub const DEMO_ROLE: &str = "demo_analyst";

/// Principal labels matched on `role` with `role_id IS NULL`. They normally
/// have no `roles` row; the supported legacy `demo_analyst` database role maps
/// into the same name-derived principal instead of receiving a stable ACL id.
pub const SYNTHETIC_ROLES: [&str; 2] = [API_KEY_ROLE, DEMO_ROLE];

/// True for a reserved synthetic principal label.
pub fn is_synthetic_role(role: &str) -> bool {
    SYNTHETIC_ROLES.contains(&role)
}

/// One per-playbook ACL action, 1:1 with a `playbook_permissions.can_*` column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PlaybookAction {
    /// Read the playbook, its versions, runs, approvals, analytics, ACL rows.
    View,
    /// Attach the playbook to a case and mutate the resulting run.
    Run,
    /// Update / archive / hard-delete / fork / submit-for-review, and administer
    /// the playbook's own ACL rows.
    Edit,
    /// Approve / reject an approval, promote an adaptive playbook.
    Publish,
}

impl PlaybookAction {
    /// The `playbook_permissions` column carrying this action's grant.
    ///
    /// Returns a `&'static str` drawn from a closed set of four literals — it is
    /// never derived from caller input, so it can never become the SQL identifier
    /// injection sink that NAN-2158 / NAN-1992 describe.
    pub const fn column(self) -> &'static str {
        match self {
            PlaybookAction::View => "can_view",
            PlaybookAction::Run => "can_run",
            PlaybookAction::Edit => "can_edit",
            PlaybookAction::Publish => "can_publish",
        }
    }

    /// Every action, for exhaustive tests.
    pub const ALL: [PlaybookAction; 4] = [
        PlaybookAction::View,
        PlaybookAction::Run,
        PlaybookAction::Edit,
        PlaybookAction::Publish,
    ];
}

/// Who is asking, for per-playbook ACL evaluation.
///
/// Default is **not** implemented on purpose: every call site must state whether
/// it is a request principal or an internal SYSTEM path, so a new caller cannot
/// silently inherit an unrestricted default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlaybookPrincipal {
    /// Internal / background caller with no request principal (leader-elected
    /// schedulers, rule-fire auto-attach, shadow-investigation compose). ACLs do
    /// not apply. Never construct this from a request.
    System,
    /// A request principal. Empty on both axes is fail-closed: it matches no ACL
    /// row, so any playbook carrying an ACL denies it.
    Grants {
        /// `roles.id` values the caller holds, resolved from the database.
        role_ids: Vec<Uuid>,
        /// Synthetic principal labels ([`SYNTHETIC_ROLES`]) the caller holds.
        synthetic: Vec<String>,
    },
}

impl PlaybookPrincipal {
    /// The API-key principal: exactly one synthetic label, never the owner's roles.
    pub fn api_key() -> Self {
        PlaybookPrincipal::Grants {
            role_ids: Vec::new(),
            synthetic: vec![API_KEY_ROLE.to_string()],
        }
    }

    /// A principal holding exactly these real roles and no synthetic labels.
    pub fn from_role_ids(role_ids: Vec<Uuid>) -> Self {
        PlaybookPrincipal::Grants {
            role_ids,
            synthetic: Vec::new(),
        }
    }

    /// True for the internal SYSTEM principal.
    pub fn is_system(&self) -> bool {
        matches!(self, PlaybookPrincipal::System)
    }

    /// The `roles.id` values to match ACL entries against. Empty for SYSTEM
    /// (which is allowed by the `is_system` half of the predicate instead).
    pub fn role_ids(&self) -> &[Uuid] {
        match self {
            PlaybookPrincipal::System => &[],
            PlaybookPrincipal::Grants { role_ids, .. } => role_ids,
        }
    }

    /// The synthetic principal labels to match `role_id IS NULL` entries against.
    pub fn synthetic_roles(&self) -> &[String] {
        match self {
            PlaybookPrincipal::System => &[],
            PlaybookPrincipal::Grants { synthetic, .. } => synthetic,
        }
    }
}

/// Resolve an interactive session's ACL principal from the database.
///
/// Same join as `GroupRepository::get_user_roles` (`user_groups → group_roles →
/// roles`), duplicated here for the same reason `PlaybookRepository::case_visible_to`
/// duplicates the case-visibility predicate: the playbook surface is open-core
/// reachable and must not depend on an enterprise-gated repository type. It
/// selects `roles.id` rather than `roles.name` — see the module docs for why the
/// name is not a safe key.
///
/// Resolving per request (rather than reading `claims.roles`) is what makes a
/// group-membership revocation take effect immediately instead of at the next
/// token refresh.
///
/// A legacy database role named `demo_analyst` resolves to the same synthetic
/// principal rather than an ordinary role id. Its platform behavior is already
/// name-derived (`DEMO_PERMISSIONS` plus deny-all source isolation), and keeping
/// that identity preserves those restrictions instead of widening access during
/// migration. For ephemeral demo sessions, the role is checked against
/// `demo.sessions` and NOT taken from the claim: an expired or cleaned-up demo
/// session must lose it at once. `claims_roles` only decides whether that extra
/// probe is worth making, so a normal session pays nothing for it.
pub async fn resolve_principal(
    pool: &PgPool,
    user_id: Uuid,
    claims_roles: &[String],
) -> Result<PlaybookPrincipal, sqlx::Error> {
    let resolved_roles = sqlx::query_as::<_, (Uuid, String)>(
        r#"
        SELECT DISTINCT r.id, r.name
          FROM user_groups ug
          JOIN group_roles gr ON gr.group_id = ug.group_id
          JOIN roles r ON r.id = gr.role_id
         WHERE ug.user_id = $1
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    let mut role_ids = Vec::with_capacity(resolved_roles.len());
    let mut synthetic = Vec::new();
    for (role_id, role_name) in resolved_roles {
        if role_name == DEMO_ROLE {
            synthetic.push(DEMO_ROLE.to_string());
        } else {
            role_ids.push(role_id);
        }
    }
    if claims_roles.iter().any(|r| r == DEMO_ROLE)
        && crate::demo::is_demo_session_active(pool, user_id).await
        && !synthetic.iter().any(|r| r == DEMO_ROLE)
    {
        synthetic.push(DEMO_ROLE.to_string());
    }

    Ok(PlaybookPrincipal::Grants {
        role_ids,
        synthetic,
    })
}

/// The flag test for an action: `can_view` for a read, `can_view AND
/// can_<action>` for anything else — always on the SAME row.
fn flag_test(action: PlaybookAction) -> String {
    match action {
        PlaybookAction::View => "pp.can_view".to_string(),
        other => format!("pp.can_view AND pp.{}", other.column()),
    }
}

/// The grant test: no ACL rows at all, or a SINGLE row for one of the caller's
/// principals carrying every flag the action needs.
///
/// codex round 6 (P1): an earlier form emitted two independent `EXISTS` clauses,
/// one for `can_view` and one for the action. That let grants COMPOSE across
/// rows — role A granting only `can_view`, plus role B granting `can_edit` with
/// `can_view = FALSE`, authorized editing — directly contradicting the documented
/// rule that an action-only row grants nothing. Requiring both flags on one row
/// makes every entry a self-contained, readable grant and removes emergent
/// privileges no administrator pictured.
fn clause(
    playbook_id_expr: &str,
    action: PlaybookAction,
    role_ids_placeholder: &str,
    synthetic_placeholder: &str,
) -> String {
    format!(
        "(NOT EXISTS (SELECT 1 FROM playbook_permissions pp WHERE pp.playbook_id = {id}) \
         OR EXISTS (SELECT 1 FROM playbook_permissions pp \
                     WHERE pp.playbook_id = {id} AND {flags} \
                       AND (pp.role_id = ANY({ids}) \
                            OR (pp.role_id IS NULL AND pp.role = ANY({syn})))))",
        id = playbook_id_expr,
        flags = flag_test(action),
        ids = role_ids_placeholder,
        syn = synthetic_placeholder,
    )
}

/// The ACL predicate for hand-written `$n` SQL.
///
/// Every placeholder argument is `&'static str` **by design**: a runtime-built
/// string (i.e. anything derived from a request) cannot be passed without
/// deliberately leaking it, so this signature makes the SQL-identifier-injection
/// class structurally unreachable.
///
/// Bind `system_placeholder` to [`PlaybookPrincipal::is_system`],
/// `role_ids_placeholder` to [`PlaybookPrincipal::role_ids`] (`uuid[]`) and
/// `synthetic_placeholder` to [`PlaybookPrincipal::synthetic_roles`] (`text[]`).
pub fn acl_sql(
    playbook_id_expr: &'static str,
    action: PlaybookAction,
    system_placeholder: &'static str,
    role_ids_placeholder: &'static str,
    synthetic_placeholder: &'static str,
) -> String {
    let grant = clause(
        playbook_id_expr,
        action,
        role_ids_placeholder,
        synthetic_placeholder,
    );
    format!("({system_placeholder} OR {grant})")
}

/// The same predicate, pushed into a [`QueryBuilder`] with real binds.
///
/// Used by the dynamically-filtered `list` / `count` queries, where placeholder
/// numbering isn't known up front. Kept byte-identical to [`acl_sql`] by
/// `tests::both_predicate_builders_agree`.
pub fn push_acl<'a>(
    qb: &mut QueryBuilder<'a, Postgres>,
    playbook_id_expr: &'static str,
    action: PlaybookAction,
    principal: &'a PlaybookPrincipal,
) {
    qb.push("(");
    qb.push_bind(principal.is_system());
    qb.push(" OR ");
    qb.push(format!(
        "(NOT EXISTS (SELECT 1 FROM playbook_permissions pp WHERE pp.playbook_id = {id}) \
         OR EXISTS (SELECT 1 FROM playbook_permissions pp \
                     WHERE pp.playbook_id = {id} AND {flags} \
                       AND (pp.role_id = ANY(",
        id = playbook_id_expr,
        flags = flag_test(action),
    ));
    qb.push_bind(principal.role_ids());
    qb.push(") OR (pp.role_id IS NULL AND pp.role = ANY(");
    qb.push_bind(principal.synthetic_roles());
    qb.push(")))))");
    qb.push(")");
}

#[cfg(test)]
#[path = "acl_tests.rs"]
mod tests;
