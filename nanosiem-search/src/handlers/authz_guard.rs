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

use super::{
    require_search_execute, require_shared_npl_base_search_contract, require_shared_npl_contract,
    require_shared_prevalence_component,
};
use crate::error::SearchError;
use nanosiem_core::auth::{permissions, types::TokenClaims};
use nanosiem_core::search::SearchTenantScope;

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

#[cfg(feature = "enterprise")]
fn shared_auth_with_prevalence(enabled: bool) -> crate::AuthContext {
    let mut auth = auth_with(&[permissions::SEARCH_EXECUTE]);
    auth.tenant_scope = SearchTenantScope::EnterpriseShared(uuid::Uuid::from_u128(0xa));
    auth.shared_search_entitlement_revision = Some(1);
    auth.shared_prevalence_entitled = enabled;
    auth
}

#[cfg(feature = "enterprise")]
#[test]
fn shared_prevalence_requires_its_exact_plan_component() {
    let denied = shared_auth_with_prevalence(false);
    assert!(matches!(
        require_shared_prevalence_component(&denied),
        Err(SearchError::Forbidden(_))
    ));
    assert!(matches!(
        require_shared_npl_contract(
            &denied,
            "metadata.log_source=apache | prevalence enrich=true",
            Some("logs")
        ),
        Err(SearchError::Forbidden(_))
    ));
    assert!(require_shared_npl_contract(
        &denied,
        "metadata.log_source=apache | stats count()",
        Some("logs")
    )
    .is_ok());

    let entitled = shared_auth_with_prevalence(true);
    assert!(require_shared_prevalence_component(&entitled).is_ok());
    assert!(require_shared_npl_contract(
        &entitled,
        "metadata.log_source=apache | prevalence enrich=true",
        Some("logs")
    )
    .is_ok());

    let dedicated = auth_with(&[permissions::SEARCH_EXECUTE]);
    assert!(require_shared_prevalence_component(&dedicated).is_ok());
}

/// NAN-2711: `| risk` RBA rules run on the tenant-pinned lake. The command is a
/// per-row projection (score/entity/factors derived from the tenant's own
/// rows), so the shared nPL contract admits it. The `risk` DATASET (entity
/// scores aggregated from findings) needs a lean-lake cell view bound to the
/// caller's own tenant risk state (NAN-3018, `cross_tenant_isolation`);
/// without one it is refused with a 400.
#[cfg(feature = "enterprise")]
#[test]
fn shared_npl_contract_admits_risk_projection_but_not_the_risk_dataset() {
    let shared = shared_auth_with_prevalence(false);
    for query in [
        "metadata.log_source=windows_sysmon | risk score=80 entity=device.hostname factor=\"x\"",
        "* | risk score=80 entity=device.hostname | risk score=90 factor=\"y\" | table time, risk_score",
    ] {
        assert!(
            require_shared_npl_contract(&shared, query, Some("logs")).is_ok(),
            "{query}"
        );
        assert!(require_shared_npl_contract(&shared, query, None).is_ok(), "{query}");
    }
    // NAN-3018: without a tenant-bound cell view the risk dataset (and any
    // other non-logs dataset) is a caller error naming what is unsupported,
    // never a retryable 503.
    for dataset in ["risk", "findings", "spans", "metrics", "RISK"] {
        match require_shared_npl_contract(&shared, "* | risk score=1", Some(dataset)) {
            Err(SearchError::BadRequest(message)) => assert!(
                message.contains(&format!("`{}`", dataset.to_ascii_lowercase())),
                "{dataset}: {message}"
            ),
            other => panic!("dataset={dataset} must be a 400: {other:?}"),
        }
    }
    assert!(require_shared_npl_contract(&shared, "* | risk score=1", Some("log")).is_ok());
    // A blocked dependency after `| risk` is still refused by name.
    match require_shared_npl_contract(
        &shared,
        "* | risk score=5 entity=user.name | inputlookup url=\"https://example.test/x.csv\"",
        Some("logs"),
    ) {
        Err(SearchError::ServiceUnavailable(message)) => {
            assert!(message.contains("`inputlookup-url` is not tenant-pinned"), "{message}")
        }
        other => panic!("an external inputlookup after risk must stay refused: {other:?}"),
    }
}

/// NAN-2922: tenant lookups, base-search IOC terms and the no-op `output` pass
/// the shared nPL contract on every surface. `| ai` and external fetches stay
/// refused with a message that says why.
#[cfg(feature = "enterprise")]
#[test]
fn shared_npl_contract_admits_tenant_pinned_lookups_and_explains_refusals() {
    let shared = shared_auth_with_prevalence(false);
    for query in [
        "* | lookup assets user.name OUTPUT owner",
        "* | inputlookup assets",
        "* | inputlookup assets key=user.name",
        "ioc in lookup(\"threats\")",
        "ioc in threatfox(\"apt29\") | head 10",
        "* | output tenant_export",
    ] {
        assert!(require_shared_npl_contract(&shared, query, Some("logs")).is_ok(), "{query}");
    }
    for (query, keyword, reason) in [
        ("* | ai prompt=\"classify\"", "`ai`", "billing"),
        (
            "* | inputlookup url=\"https://example.test/x.csv\"",
            "`inputlookup-url`",
            "upload the data as a lookup table",
        ),
        (
            "user.name=a | append [ioc in lookup(\"threats\")]",
            "`ioc-lookup`",
            "base search expression",
        ),
    ] {
        match require_shared_npl_contract(&shared, query, Some("logs")) {
            Err(SearchError::ServiceUnavailable(message)) => {
                assert!(message.contains(keyword), "{message}");
                assert!(message.contains(reason), "{message}");
            }
            other => panic!("{query} must stay refused: {other:?}"),
        }
    }
}

/// NAN-2959: detection findings (Live matches and alerts) are searched the
/// way the ClickHouse product searched them, as `source_type=findings` rows of
/// the caller's own pinned `logs` dataset. The shared contract admits those
/// queries; a separate `findings`/`signals`/`alerts` dataset selector does
/// not exist in the product and stays refused, and the refusal names the
/// supported form.
#[cfg(feature = "enterprise")]
#[test]
fn shared_npl_contract_admits_findings_and_alerts_in_the_logs_dataset() {
    let shared = shared_auth_with_prevalence(false);
    for query in [
        "source_type=findings",
        "source_type=findings is_alert=true | stats count() by finding_info.analytic.name",
        "source_type=findings severity_id>=4 | table time, finding_info.uid_alt, risk_score",
        "metadata.log_source=findings | timechart span=1h count()",
        // NAN-3224: the `risk` alias is findings in the same logs dataset.
        "metadata.log_source=risk | stats sum(risk_score) by resources.type, resources.name",
    ] {
        assert!(
            require_shared_npl_contract(&shared, query, Some("logs")).is_ok(),
            "{query}"
        );
        assert!(require_shared_npl_contract(&shared, query, None).is_ok(), "{query}");
    }
    for dataset in ["findings", "signals", "alerts"] {
        match require_shared_npl_contract(&shared, "source_type=findings", Some(dataset)) {
            Err(SearchError::BadRequest(message)) => {
                assert!(message.contains("source_type=findings"), "{message}")
            }
            other => panic!("dataset={dataset} must stay refused: {other:?}"),
        }
    }
}

/// NAN-3093: the field-stats / field-values companions execute only the base
/// search, so a product view after the pipe (`| cloud`) must not 503 them,
/// while the base search is still held to the contract and a non-logs
/// dataset is still refused.
#[cfg(feature = "enterprise")]
#[test]
fn field_companions_check_only_the_base_search_they_execute() {
    let shared = shared_auth_with_prevalence(false);
    for query in [
        "metadata.log_source=aws_cloudtrail | cloud",
        "| cloud principal=\"intern01\"",
        "* | ai prompt=\"classify\"",
        "user.name=a | append [ioc in lookup(\"threats\")]",
    ] {
        assert!(
            require_shared_npl_contract(&shared, query, Some("logs")).is_err(),
            "the full-text contract still refuses {query}"
        );
        assert!(
            require_shared_npl_base_search_contract(&shared, query, Some("logs")).is_ok(),
            "{query}"
        );
    }
    match require_shared_npl_base_search_contract(
        &shared,
        "metadata.log_source=aws_cloudtrail | cloud",
        Some("spans"),
    ) {
        Err(SearchError::BadRequest(_)) => {}
        other => panic!("a non-logs dataset must stay refused: {other:?}"),
    }
    assert!(require_shared_npl_base_search_contract(&shared, "a | (", Some("logs")).is_err());
    let search = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/handlers/search.rs"
    ))
    .unwrap();
    for handler in ["pub async fn field_stats_for_query(", "pub async fn field_values("] {
        let body = &search[search.find(handler).unwrap()..];
        let body = &body[..body.find("\n}\n").unwrap()];
        assert!(body.contains("require_shared_npl_base_search_contract("), "{handler}");
    }
}

#[test]
fn prevalence_companion_calls_the_shared_component_gate_before_data_access() {
    let search = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/handlers/search.rs"
    ))
    .expect("read search.rs");
    let marker = "pub async fn prevalence_artifacts(";
    let start = search.find(marker).expect("prevalence handler exists");
    let tail = &search[start + marker.len()..];
    let end = tail.find("pub async fn ").unwrap_or(tail.len());
    let handler = &tail[..end];
    let component = handler
        .find("require_shared_prevalence_component(&auth)")
        .expect("prevalence component gate exists");
    let runtime = handler
        .find("state.search_for_auth(&auth)")
        .expect("tenant search runtime lookup exists");
    assert!(
        component < runtime,
        "prevalence entitlement must be checked before tenant data access"
    );
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
    assert!(require_search_admin(&auth_with(&[
        permissions::SETTINGS_SYSTEM,
        permissions::SEARCH_EXECUTE
    ]))
    .is_ok());
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
        "get_search_job no longer applies the source-scope re-check — a \
         stored result would survive revocation of the caller's source access"
    );

    // The cross-user admin list must pass the viewer's scope into `list_all_checked`,
    // which is where the predicate lives.
    let admin = region("admin_list_search_jobs");
    assert!(
        admin.contains("list_all_checked(super::search::effective_scope(&auth).deny_set())")
            && admin.contains("map_err(map_job_store_error)?"),
        "admin_list_search_jobs must pass the admin's CURRENT effective scope to \
         list_all_checked and preserve outages — an unscoped call re-exposes every principal's query preview"
    );
}

#[test]
fn shared_data_release_paths_revalidate_live_authority() {
    let search = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/handlers/search.rs"
    ))
    .expect("read search.rs");
    let jobs = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/handlers/search_jobs.rs"
    ))
    .expect("read search_jobs.rs");
    let region = |source: &str, name: &str| -> String {
        let marker = format!("pub async fn {name}(");
        let start = source
            .find(&marker)
            .unwrap_or_else(|| panic!("handler {name} not found"));
        let rest = &source[start + marker.len()..];
        let end = rest.find("pub async fn ").unwrap_or(rest.len());
        rest[..end].to_string()
    };

    for name in [
        "search",
        "explain",
        "fetch_log",
        "prevalence_artifacts",
        "field_stats_for_query",
        "field_values",
        "search_histogram",
    ] {
        assert!(
            region(&search, name).contains("require_current_shared_authority"),
            "{name} can release data or a job handle without a live shared-authority check"
        );
    }
    for name in [
        "get_search_job",
        "get_search_job_result_page",
        "download_search_job_result",
        "list_search_jobs",
        "admin_list_search_jobs",
        "admin_get_stats",
    ] {
        assert!(
            region(&jobs, name).contains("require_current_shared_authority"),
            "{name} can release job data without a live shared-authority check"
        );
    }
    let download = region(&jobs, "download_search_job_result");
    assert!(download.matches("revalidate_shared_context").count() >= 3);
    assert!(download.contains("rows_since_revalidation >= 128"));
}

/// Cancellation performs awaited ownership reads before it reaches the
/// destructive engine/job-store call. Pin the late check ordering so a future
/// refactor cannot leave a revoke-to-cancel race while retaining only the
/// request-entry capability gate.
#[test]
fn shared_cancel_paths_revalidate_live_authority_at_destructive_boundary() {
    let search = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/handlers/search.rs"
    ))
    .expect("read search.rs");
    let jobs = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/handlers/search_jobs.rs"
    ))
    .expect("read search_jobs.rs");
    let region = |source: &str, name: &str| -> String {
        let marker = format!("pub async fn {name}(");
        let start = source
            .find(&marker)
            .unwrap_or_else(|| panic!("handler {name} not found"));
        let rest = &source[start + marker.len()..];
        let end = rest.find("pub async fn ").unwrap_or(rest.len());
        rest[..end].to_string()
    };
    let ordered = |handler: &str, ownership: &str, cancellation: &str| {
        let ownership = handler
            .find(ownership)
            .expect("ownership decision must remain before cancellation");
        let revalidation = handler
            .rfind("require_current_shared_authority")
            .expect("shared authority must be revalidated before cancellation");
        let cancellation = handler
            .find(cancellation)
            .expect("destructive cancellation call must remain present");
        assert!(
            ownership < revalidation && revalidation < cancellation,
            "shared authority must be revalidated after ownership and immediately before cancellation"
        );
    };

    ordered(
        &region(&search, "cancel_search"),
        "if owner != Some(principal)",
        ".cancel_query(&execution_id)",
    );
    ordered(
        &region(&jobs, "cancel_search_job"),
        "if !is_admin && job.user_id != Some(auth.claims.sub)",
        ".cancel_job(&job_id)",
    );
    ordered(
        &region(&jobs, "admin_cancel_search_job"),
        "search_for_auth(&auth)",
        ".cancel_job(&job_id)",
    );
}

/// A cache-age lookup is a Redis await. It must complete before the live
/// authority check; otherwise a membership revoke can land after revalidation
/// but before cached tenant data is released.
#[test]
fn cached_search_paths_revalidate_after_their_final_backend_await() {
    let search = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/handlers/search.rs"
    ))
    .expect("read search.rs");
    let region = |name: &str| -> String {
        let marker = format!("pub async fn {name}(");
        let start = search
            .find(&marker)
            .unwrap_or_else(|| panic!("handler {name} not found"));
        let rest = &search[start + marker.len()..];
        let end = rest.find("pub async fn ").unwrap_or(rest.len());
        rest[..end].to_string()
    };
    let assert_cached_order = |handler: &str, metric: &str| {
        let record_marker = format!("record_search_query(\"{metric}\"");
        let record = handler
            .find(&record_marker)
            .unwrap_or_else(|| panic!("cached metric {metric} not found"));
        let before_release = &handler[..record];
        let age = before_release
            .rfind("age_secs(")
            .unwrap_or_else(|| panic!("cached age lookup for {metric} not found"));
        let revalidation = before_release
            .rfind("require_current_shared_authority")
            .unwrap_or_else(|| panic!("cached authority revalidation for {metric} not found"));
        let final_await = before_release
            .rfind(".await")
            .unwrap_or_else(|| panic!("cached await for {metric} not found"));
        assert!(
            age < revalidation && revalidation < final_await,
            "{metric} must fetch cache age before its final authority revalidation"
        );
    };

    assert_cached_order(&region("search"), "piped_cached");
    assert_cached_order(
        &region("prevalence_artifacts"),
        "prevalence_artifacts_cached",
    );
    assert_cached_order(&region("field_stats_for_query"), "field_stats_cached");
    assert_cached_order(&region("field_values"), "field_values_cached");
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
    (
        "search_sql",
        "gated on search:sql (stricter raw-SQL capability)",
    ),
    // Identity resolution is an enrichment read, gated on enrichments:view.
    ("resolve_identity", "gated on enrichments:view"),
    // Saved-search surface: create needs search:save; mutations are owner-scoped
    // (owner_id equality); reads return only the caller's own / shared rows.
    ("create_saved_search", "gated on search:save"),
    // Saved-search surface gates on its own feature capabilities (NAN-2033),
    // additive to the repository's per-record ownership/visibility checks. These
    // are not `search:execute`, so they belong here with their real capability.
    (
        "update_saved_search",
        "gated on search:save (+ owner-only repo check)",
    ),
    (
        "delete_saved_search",
        "gated on search:save (+ owner-only repo check)",
    ),
    (
        "share_saved_search",
        "gated on search:share (+ owner-only repo check)",
    ),
    (
        "list_saved_searches",
        "gated on search:view (+ per-record visibility)",
    ),
    (
        "list_shared_searches",
        "gated on search:view (+ per-record visibility)",
    ),
    (
        "list_my_saved_searches",
        "gated on search:view (+ per-record visibility)",
    ),
    (
        "get_saved_search",
        "gated on search:view (+ per-record visibility)",
    ),
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
        //
        // NAN-2229: the marker must open a LINE, not merely appear somewhere in
        // one. A bare `match_indices` also matched the marker inside string
        // literals — `assets.rs`'s `let marker = "pub async fn
        // get_asset_true_time_range(";` and `search.rs`'s `const MARKER: &str =
        // "pub async fn ";`, both in unrelated tests. Each minted a phantom
        // region starting mid-file: the first duplicated a real handler's name
        // with a body containing no gate (reporting a correctly-gated handler as
        // ungated), the second produced an empty name (`search.rs::`). This
        // guard therefore failed closed against itself and sat red on main,
        // which is worse than useless — a check whose normal state is red gets
        // ignored, then deleted.
        //
        // Real handlers are free functions at module scope, so their definition
        // always begins a line. Leading whitespace is tolerated; a marker
        // preceded by anything else on its line (`= "`, `// `) is not a
        // definition.
        const MARKER: &str = "pub async fn ";
        let starts: Vec<usize> = src
            .match_indices(MARKER)
            .map(|(i, _)| i)
            .filter(|&i| {
                let line_start = src[..i].rfind('\n').map_or(0, |nl| nl + 1);
                src[line_start..i].chars().all(char::is_whitespace)
            })
            .collect();
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

    // NAN-2229: an empty name means the marker matched something that is not a
    // function definition — the exact signature of the string-literal matches
    // that used to poison this scan. Assert it directly, because the symptom
    // ("handler `search.rs::` is ungated") reads like a missing gate and sent
    // the last reader looking for an authorization bug that did not exist.
    assert!(
        !discovered.contains(""),
        "handler scan produced an empty handler name — the `pub async fn` marker \
         matched a non-definition (string literal or comment); fix the scan, do \
         not add an exemption"
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

/// NAN-3059: the Asset / Cloud product-view companions are open on shared
/// Search. Each must resolve the caller's own tenant-pinned cell view (never
/// the process singleton `state.search`) and revalidate the live shared
/// authority before every data or job-handle release, cached ones included.
#[test]
fn product_view_companions_use_the_tenant_view_and_revalidate_before_release() {
    let read = |file: &str| {
        std::fs::read_to_string(format!("{}/src/handlers/{file}", env!("CARGO_MANIFEST_DIR")))
            .expect("read handler file")
    };
    let region = |source: &str, name: &str| -> String {
        let marker = format!("pub async fn {name}(");
        let start = source
            .find(&marker)
            .unwrap_or_else(|| panic!("handler {name} not found"));
        let rest = &source[start + marker.len()..];
        let end = rest.find("\npub async fn ").unwrap_or(rest.len());
        let end = rest[..end].find("\n#[cfg(test)]").unwrap_or(end);
        rest[..end].to_string()
    };
    for (file, name) in [
        ("asset_dossier.rs", "get_asset_dossier"),
        ("cloud_overview.rs", "get_cloud_overview"),
        ("cloud_dossier.rs", "get_cloud_dossier"),
        ("assets.rs", "get_asset_events"),
        ("assets.rs", "get_cloud_events"),
        ("assets.rs", "get_cloud_user_timeline"),
        ("assets.rs", "get_cloud_entity_pivot"),
        ("assets.rs", "get_asset_true_time_range"),
        ("assets.rs", "get_asset_artifacts"),
        // NAN-3086: the retro companion (durable, proof-carrying on shared).
        ("retro.rs", "retro"),
        // NAN-3088: lean prevalence export / rare list (durable cell jobs).
        ("prevalence.rs", "lean_prevalence_export"),
        ("prevalence.rs", "lean_rare_artifacts"),
    ] {
        let body = region(&read(file), name);
        assert!(body.contains("super::product_view_search(&state, &auth)?"), "{name}");
        // NAN-3286: whitespace-insensitive, so `state\n.search\n.x` is caught.
        assert!(!compact(&body).contains("state.search."), "{name} reaches the process singleton");
        let releases = body.matches("Ok((").count();
        let checks = body.matches("require_current_shared_authority(&state, &auth).await?").count();
        assert!(releases > 0 && checks >= releases, "{name}: {checks} checks for {releases} releases");
    }
}

/// Source with every whitespace character removed, so a call split across
/// lines (`state\n    .search\n    .method(`) matches its one-line form.
fn compact(source: &str) -> String {
    source.chars().filter(|c| !c.is_whitespace()).collect()
}

/// The index just past the `}` closing the block whose `{` is at `open`.
fn block_end(source: &str, open: usize) -> usize {
    assert_eq!(&source[open..=open], "{");
    let mut depth = 0usize;
    for (offset, ch) in source[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return open + offset + 1;
                }
            }
            _ => {}
        }
    }
    panic!("unbalanced block at {open}");
}

/// Remove the dedicated-only fallback blocks taken when
/// `state.otel_lake_for(&auth)?` is `Ok(None)` — which it never is for an
/// enterprise-shared request (typed 503 instead). Both forms are handled:
/// `if let Some(c) = state.otel_lake_for(&auth)? { .. } else { FALLBACK }` and
/// `let Some(c) = state.otel_lake_for(&auth)? else { FALLBACK };`.
fn strip_dedicated_otel_fallbacks(compacted: &str) -> (String, usize) {
    let mut source = compacted.to_string();
    let mut stripped = 0;
    loop {
        if let Some(at) = source.find("state.otel_lake_for(&auth)?else{") {
            let open = at + "state.otel_lake_for(&auth)?else".len();
            let end = block_end(&source, open);
            source.replace_range(at..end, "OTEL_LAKE_FOR_LET_ELSE");
            stripped += 1;
            continue;
        }
        if let Some(at) = source.find("state.otel_lake_for(&auth)?{") {
            let open = at + "state.otel_lake_for(&auth)?".len();
            let then_end = block_end(&source, open);
            // Every `else if .. {}` / `else {}` arm runs only on `Ok(None)`.
            let mut else_end = then_end;
            loop {
                if source[else_end..].starts_with("else{") {
                    else_end = block_end(&source, else_end + "else".len());
                    break;
                }
                assert!(
                    source[else_end..].starts_with("elseif"),
                    "an `if let` OTLP client branch must carry an explicit dedicated else"
                );
                let arm_open = else_end
                    + source[else_end..].find('{').expect("else-if arm has a block");
                else_end = block_end(&source, arm_open);
            }
            let then_block = source[open..then_end].to_string();
            source.replace_range(at..else_end, &format!("OTEL_LAKE_FOR_IF{then_block}"));
            stripped += 1;
            continue;
        }
        return (source, stripped);
    }
}

/// NAN-3286: no OTLP handler may reach the process singleton `state.search`
/// on a path a shared request can take. The only admitted uses sit in the
/// dedicated ClickHouse fallback of `otel_lake_for` (unreachable for shared
/// requests); every other read — e.g. the security-signals Detection-Finding
/// read — must go through the caller's tenant view. The scan ignores
/// whitespace so a multi-line `state\n.search\n.x(` call is caught.
#[test]
fn otel_handlers_never_reach_the_process_singleton_on_a_shared_path() {
    let source = std::fs::read_to_string(format!(
        "{}/src/handlers/otel.rs",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("read otel.rs");
    let source = &source[..source.find("\n#[cfg(test)]").unwrap_or(source.len())];
    let mut handlers = 0;
    for chunk in source.split("\npub async fn ").skip(1) {
        handlers += 1;
        let name = chunk.split('(').next().unwrap_or_default().to_string();
        let (remaining, _) = strip_dedicated_otel_fallbacks(&compact(chunk));
        assert!(
            !remaining.contains("state.search."),
            "{name} reaches the process singleton outside the dedicated OTLP fallback"
        );
    }
    assert!(handlers >= 10, "expected the OTLP handler set, found {handlers}");
    // The scanner itself must catch the multi-line form it exists for.
    let (probe, stripped) = strip_dedicated_otel_fallbacks(&compact(
        "let Some(c) = state.otel_lake_for(&auth)? else { state\n .search\n .x() };\n\
         let r = state\n    .search\n    .search_with_admission(r);",
    ));
    assert_eq!(stripped, 1);
    assert!(probe.contains("state.search.search_with_admission"));
}
