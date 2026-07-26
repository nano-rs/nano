// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fail-closed authorization contract for the search-microservice handlers
//! (NAN-2028 / NAN-2030).
//!
//! `auth_middleware` proves *who* a caller is (a valid token, else 401); it does
//! NOT decide *what* they may do. Every handler that reads log / OTEL data must
//! therefore gate on `search:execute` — via [`super::require_search_execute`] —
//! as its first statement. Eight OTEL handlers (NAN-2030) and the SSE
//! `search_stream` handler shipped without that gate: authenticated but
//! unauthorized, because gating was an easy-to-forget per-handler convention.
//!
//! These tests turn the convention into an enforced contract:
//!
//! 1. [`search_execute_gate_forbids_under_scoped_keys`] — the gate itself
//!    refuses zero-/wrong-permission callers and admits `search:execute`.
//! 2. [`every_handler_is_authorization_accounted_for`] — a source scan over the
//!    whole `handlers/` tree that FAILS if any `pub async fn` route handler
//!    neither performs a `search:execute` check nor is explicitly listed in
//!    [`NON_SEARCH_EXECUTE`] with the alternative authorization it relies on. A
//!    new handler cannot ship without making a *visible* authorization decision.
//!
//! The scan is deliberately static. A true end-to-end router test needs a live
//! `DualPool` (both ClickHouse and PostgreSQL) to build `SearchState`, so it
//! belongs to the integration suite, not `cargo test`. The scan catches the
//! exact regression a helper-only unit test cannot: a handler that never calls
//! the helper at all.

use super::require_search_execute;
use crate::error::SearchError;
use nanosiem_core::auth::{permissions, types::TokenClaims};

fn auth_with(perms: &[&str]) -> crate::AuthContext {
    crate::AuthContext::from_jwt(TokenClaims {
        iss: "test".to_string(),
        aud: "test".to_string(),
        sub: uuid::Uuid::nil(),
        roles: Vec::new(),
        permissions: perms.iter().map(|s| s.to_string()).collect(),
        exp: i64::MAX,
        iat: 0,
        jti: uuid::Uuid::nil(),
        purpose: "access".to_string(),
    })
}

/// NAN-2028/NAN-2030: an under-scoped principal (including zero-permission) is
/// refused by the shared gate; a principal holding `search:execute` passes.
#[test]
fn search_execute_gate_forbids_under_scoped_keys() {
    // Zero permissions — the originally reported repro.
    assert!(matches!(
        require_search_execute(&auth_with(&[])),
        Err(SearchError::Forbidden(_))
    ));
    // Holds an unrelated permission but not search:execute.
    assert!(matches!(
        require_search_execute(&auth_with(&["dashboards:view"])),
        Err(SearchError::Forbidden(_))
    ));
    // A real principal holding search:execute is allowed past the gate.
    assert!(require_search_execute(&auth_with(&[permissions::SEARCH_EXECUTE])).is_ok());
}

/// NAN-2109: the cross-user admin surface requires BOTH capabilities.
///
/// The reported repro is step 5-7: a `settings:system`-only key is refused its
/// OWN job list (`search:execute` gate, NAN-2032) yet could read every other
/// principal's job id, user id and query preview through the admin variant.
/// `settings:system` administers the service; it does not authorize search
/// content.
#[test]
fn admin_job_surface_requires_settings_system_and_search_execute() {
    use super::search_jobs::require_search_admin;

    // Zero permissions.
    assert!(matches!(
        require_search_admin(&auth_with(&[])),
        Err(SearchError::Forbidden(_))
    ));
    // Unrelated permission only.
    assert!(matches!(
        require_search_admin(&auth_with(&["dashboards:view"])),
        Err(SearchError::Forbidden(_))
    ));
    // The reported bypass: settings:system without search:execute.
    assert!(matches!(
        require_search_admin(&auth_with(&[permissions::SETTINGS_SYSTEM])),
        Err(SearchError::Forbidden(_))
    ));
    // search:execute alone is not admin authority either.
    assert!(matches!(
        require_search_admin(&auth_with(&[permissions::SEARCH_EXECUTE])),
        Err(SearchError::Forbidden(_))
    ));
    // Both — the only admitted combination.
    assert!(
        require_search_admin(&auth_with(&[
            permissions::SETTINGS_SYSTEM,
            permissions::SEARCH_EXECUTE
        ]))
        .is_ok()
    );
}

/// NAN-2100: `DELETE /api/search/{request_id}` issues ClickHouse `KILL QUERY`,
/// so revoking `search:execute` must revoke cancellation authority too. The
/// static scan below proves the handler performs the gate; this pins the
/// decision the gate makes for an under-scoped key (the reported repro used a
/// key holding only `enrichments:custom:delete`).
#[test]
fn cancellation_requires_search_execute() {
    assert!(matches!(
        require_search_execute(&auth_with(&["enrichments:custom:delete"])),
        Err(SearchError::Forbidden(_))
    ));
    assert!(require_search_execute(&auth_with(&[permissions::SEARCH_EXECUTE])).is_ok());
}

/// NAN-2100: query ownership is keyed on the CREDENTIAL, so two api keys owned
/// by the same human are two principals and cannot cancel each other's work.
#[test]
fn credential_principal_separates_keys_from_their_owner() {
    use nanosiem_core::auth::ApiKeyInfo;

    let owner = uuid::Uuid::now_v7();
    let key = |id: uuid::Uuid| {
        crate::AuthContext::from_api_key(&ApiKeyInfo {
            id,
            name: "k".to_string(),
            permissions: vec![permissions::SEARCH_EXECUTE.to_string()],
            user_id: Some(owner),
        })
    };

    let key_a = key(uuid::Uuid::now_v7());
    let key_b = key(uuid::Uuid::now_v7());

    // Each key is its own principal…
    assert_eq!(key_a.credential_principal_id(), key_a.api_key_id.unwrap());
    assert_ne!(
        key_a.credential_principal_id(),
        key_b.credential_principal_id()
    );
    // …and neither collapses into the human owner, whose interactive session
    // resolves to the user id.
    assert_ne!(key_a.credential_principal_id(), owner);
    assert_ne!(key_b.credential_principal_id(), owner);

    let mut session_claims = auth_with(&[permissions::SEARCH_EXECUTE]);
    session_claims.claims.sub = owner;
    assert_eq!(session_claims.credential_principal_id(), owner);
}

/// NAN-2096: the unit tests above prove the PREDICATE
/// (`SearchJob::result_visible_under`) is correct, but a predicate nobody calls
/// protects nothing. This scans the handler source so deleting the call from
/// `get_search_job` — or dropping the scope argument from the admin list —
/// fails the suite instead of silently reopening stored-result access.
///
/// Source-level, deliberately: an end-to-end router test needs a live
/// `SearchState` (ClickHouse + Postgres) and belongs to the integration lane.
#[test]
fn stored_result_reads_are_wired_to_the_scope_predicate() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/handlers/search_jobs.rs"
    ))
    .expect("read search_jobs.rs");

    let region = |name: &str| -> String {
        let marker = format!("pub async fn {}(", name);
        let start = src
            .find(&marker)
            .unwrap_or_else(|| panic!("handler {name} not found — did it move or get renamed?"));
        let rest = &src[start + marker.len()..];
        let end = rest.find("pub async fn ").unwrap_or(rest.len());
        rest[..end].to_string()
    };

    // The result-bearing poll route must re-decide source scope on every read.
    let poll = region("get_search_job");
    assert!(
        poll.contains("result_visible_under"),
        "get_search_job no longer applies the NAN-2096 source-scope re-check — a \
         stored result would survive revocation of the caller's source access"
    );

    // The cross-user admin list must pass the viewer's scope into `list_all`,
    // which is where the predicate lives.
    let admin = region("admin_list_search_jobs");
    assert!(
        admin.contains("list_all(super::search::effective_scope(&auth).deny_set())"),
        "admin_list_search_jobs must pass the admin's CURRENT effective scope to \
         list_all — an unscoped call re-exposes every principal's query preview"
    );
}

/// Route handlers that do NOT gate on `search:execute`, each paired with the
/// authorization it relies on instead. This is the search router's authorization
/// ledger: adding a handler forces a choice — gate it, or list it here with a
/// reason. The scan below fails on any unlisted, ungated handler, and on any
/// stale entry here that no longer names a real handler.
///
/// IMPORTANT — an entry here asserts ONLY that the handler does not use the
/// `search:execute` gate. It is NOT a claim that the stated alternative
/// authorization is correct or sufficient; that must be verified per handler.
/// Entries tagged `AUDITED` have an OPEN finding disputing their current
/// authorization — do NOT read them as an all-clear.
const NON_SEARCH_EXECUTE: &[(&str, &str)] = &[
    // Public, unauthenticated liveness / readiness probes.
    ("health", "public health probe — no auth"),
    ("ready", "public readiness probe — no auth"),
    ("livez", "public shallow liveness probe — no auth"),
    // Raw-SQL search is a STRICTER capability (search:sql) than search:execute.
    ("search_sql", "gated on search:sql (stricter raw-SQL capability)"),
    // Identity resolution is an enrichment read, gated on enrichments:view.
    ("resolve_identity", "gated on enrichments:view"),
    // Saved-search surface: create needs search:save; mutations are owner-scoped
    // (owner_id equality); reads return only the caller's own / shared rows.
    ("create_saved_search", "gated on search:save"),
    // Saved-search surface gates on its own feature capabilities (NAN-2033),
    // additive to the repository's per-record ownership/visibility checks. These
    // are not `search:execute`, so they belong here with their real capability.
    ("update_saved_search", "gated on search:save (+ owner-only repo check)"),
    ("delete_saved_search", "gated on search:save (+ owner-only repo check)"),
    ("share_saved_search", "gated on search:share (+ owner-only repo check)"),
    ("list_saved_searches", "gated on search:view (+ per-record visibility)"),
    ("list_shared_searches", "gated on search:view (+ per-record visibility)"),
    ("list_my_saved_searches", "gated on search:view (+ per-record visibility)"),
    ("get_saved_search", "gated on search:view (+ per-record visibility)"),
    // Async-job control now gates on search:execute (NAN-2032) via the shared
    // helper, so get_search_job / cancel_search_job / list_search_jobs are
    // covered by the scan directly and are intentionally NOT listed here.
    //
    // NAN-2100 (cancel_search) and NAN-2109 (the three admin_* handlers) removed
    // the remaining exemptions: cancellation is a destructive search-plane
    // operation and the admin job/stats surface returns other principals' query
    // text, so all four now gate on search:execute — the admin trio via
    // `require_search_admin`, which ANDs it with settings:system.
];

/// A handler "gates on search:execute" if its body calls the shared helper, the
/// composite admin helper (`require_search_admin` = settings:system AND
/// search:execute, NAN-2109), OR checks the `SEARCH_EXECUTE` permission inline
/// (retro / cloud / asset-dossier still gate inline — all three forms are the
/// same positive authorization decision).
fn body_gates_on_search_execute(region: &str) -> bool {
    region.contains("require_search_execute(&auth)")
        || region.contains("require_search_admin(&auth)")
        || region.contains("SEARCH_EXECUTE")
}

/// Every `pub async fn` route handler across `handlers/` must either gate on
/// `search:execute` or be classified in [`NON_SEARCH_EXECUTE`]. Fails closed:
/// an unrecognized handler is a failure, not a silent pass.
#[test]
fn every_handler_is_authorization_accounted_for() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src/handlers");
    let exempt: std::collections::HashMap<&str, &str> =
        NON_SEARCH_EXECUTE.iter().copied().collect();

    let mut discovered: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut ungated: Vec<String> = Vec::new();

    for entry in std::fs::read_dir(dir).expect("read handlers dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let file_name = path.file_name().unwrap().to_str().unwrap().to_string();
        // mod.rs holds the shared gate + re-exports; this file is the contract.
        if file_name == "mod.rs" || file_name == "authz_guard.rs" {
            continue;
        }
        let src = std::fs::read_to_string(&path).expect("read handler file");

        // Split the file into per-handler regions on the `pub async fn` marker.
        // Each region runs to the next handler (or EOF) — enough to see whether
        // that handler's body performs the gate.
        const MARKER: &str = "pub async fn ";
        let starts: Vec<usize> = src.match_indices(MARKER).map(|(i, _)| i).collect();
        for (idx, &start) in starts.iter().enumerate() {
            let end = starts.get(idx + 1).copied().unwrap_or(src.len());
            let region = &src[start..end];

            // Handler name: between the marker and the opening paren.
            let name: String = region[MARKER.len()..]
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            discovered.insert(name.clone());

            if !body_gates_on_search_execute(region) && !exempt.contains_key(name.as_str()) {
                ungated.push(format!("{file_name}::{name}"));
            }
        }
    }

    // Sanity: the scan must actually find the handler corpus. A path/marker
    // change that silently matched nothing would otherwise pass vacuously.
    assert!(
        discovered.len() >= 30,
        "handler scan found only {} handlers — did the path or `pub async fn` marker change?",
        discovered.len()
    );

    assert!(
        ungated.is_empty(),
        "search handler(s) neither gate on search:execute nor are listed in \
         NON_SEARCH_EXECUTE — gate them (require_search_execute(&auth)) or classify \
         them explicitly with their real authorization: {ungated:?}",
    );

    // Keep the ledger honest: every exemption must name a handler that still
    // exists, so a stale entry can't quietly mask a newly-ungated handler that
    // happens to reuse the same name.
    let stale: Vec<&str> = NON_SEARCH_EXECUTE
        .iter()
        .map(|(n, _)| *n)
        .filter(|n| !discovered.contains(*n))
        .collect();
    assert!(
        stale.is_empty(),
        "NON_SEARCH_EXECUTE lists handler(s) that no longer exist: {stale:?}",
    );
}
