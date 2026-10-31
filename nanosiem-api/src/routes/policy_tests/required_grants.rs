// SPDX-License-Identifier: AGPL-3.0-or-later
//! Independent caller contracts, including every grant of the operations that
//! previously registered only their last capability. The HTTP matrix also
//! consumes these assertions, before generating its partial-grant probes.
use super::*;

type Contract = (&'static str, &'static str, &'static [&'static str]);

const SHARED: &[Contract] = &[
    (
        "POST",
        "/api/dashboards/panel/query",
        &["dashboards:view", "search:execute"],
    ),
    (
        "POST",
        "/api/hunts/leads/{id}/promote",
        &["hunts:triage", "cases:create"],
    ),
    (
        "POST",
        "/api/rule-repositories/{id}/rules/import/{*path}",
        &["rule_repositories:import", "detections:create"],
    ),
    (
        "POST",
        "/api/rule-repositories/{id}/rules/import-batch",
        &["rule_repositories:import", "detections:create"],
    ),
    (
        "POST",
        "/api/rule-repositories/{id}/rules/remove-all-imported",
        &["rule_repositories:manage", "detections:delete"],
    ),
    (
        "GET",
        "/api/detection-rules/{id}/upstream-diff",
        &["rule_repositories:view", "detections:view"],
    ),
    (
        "POST",
        "/api/parser-repositories/{id}/fixup-match-values",
        &["parser_repositories:manage", "log_sources:edit"],
    ),
    (
        "POST",
        "/api/parser-repositories/{id}/parsers/import/{*path}",
        &["parser_repositories:import", "log_sources:create"],
    ),
    (
        "POST",
        "/api/parser-repositories/{id}/parsers/import-batch",
        &["parser_repositories:import", "log_sources:create"],
    ),
    (
        "POST",
        "/api/parser-repositories/{id}/parsers/remove-all-imported",
        &["parser_repositories:manage", "log_sources:delete"],
    ),
    (
        "GET",
        "/api/log-sources/{id}/upstream-diff",
        &["parser_repositories:view", "log_sources:view"],
    ),
    (
        "GET",
        "/api/playbooks/suggest-for-rule/{rule_id}",
        &["playbooks:view", "detections:view"],
    ),
    (
        "GET",
        "/api/playbooks/{id}/runs",
        &["playbooks:view", "cases:view"],
    ),
    (
        "POST",
        "/api/playbooks/{id}/runs",
        &["playbooks:run", "cases:edit"],
    ),
    (
        "POST",
        "/api/playbooks/{id}/run",
        &["playbooks:run", "cases:edit"],
    ),
    (
        "PATCH",
        "/api/playbook-runs/{id}",
        &["playbooks:run", "cases:edit"],
    ),
    (
        "GET",
        "/api/playbook-runs/{id}/resolved",
        &["playbooks:view", "cases:view"],
    ),
    (
        "GET",
        "/api/playbook-runs/{id}/steps",
        &["playbooks:view", "cases:view"],
    ),
    (
        "PATCH",
        "/api/playbook-runs/{run_id}/steps/{step_id}",
        &["playbooks:run", "cases:edit"],
    ),
    (
        "GET",
        "/api/cases/{case_id}/playbook-runs",
        &["playbooks:view", "cases:view"],
    ),
    (
        "POST",
        "/api/cases/{case_id}/compose-adaptive-playbook",
        &["playbooks:manage", "cases:view"],
    ),
    (
        "POST",
        "/api/cases/{id}/alerts",
        &["cases:edit", "alerts:view"],
    ),
    (
        "DELETE",
        "/api/cases/{id}/alerts/{alert_id}",
        &["cases:edit", "alerts:view"],
    ),
    (
        "POST",
        "/api/cases/{id}/notebook/merge",
        &["cases:edit", "notebooks:edit"],
    ),
    (
        "POST",
        "/api/notebooks/{id}/escalate",
        &["notebooks:edit", "cases:create"],
    ),
];

fn entry<'a>(inventory: &'a [Entry], method: &str, path: &str) -> &'a Entry {
    inventory
        .iter()
        .find(|row| row.method == method && row.path == path)
        .unwrap_or_else(|| panic!("missing production registration: {method} {path}"))
}

fn all_of(inventory: &[Entry], contracts: &[Contract]) {
    for &(method, path, required) in contracts {
        let row = entry(inventory, method, path);
        assert!(
            matches!(row.policy.capability(), CapabilityRequirement::AllOf(perms)
            if perms.as_ref() == required),
            "incomplete mandatory grants: {row:?}"
        );
        // Use independent required grants, never grants derived from the row.
        // Both a JWT and a delegated key must fail each partial conjunction.
        for key in [false, true] {
            for omitted in 0..required.len() {
                let partial = required
                    .iter()
                    .enumerate()
                    .filter(|(index, _)| *index != omitted)
                    .map(|(_, permission)| permission.to_string())
                    .collect();
                assert!(
                    !row.policy
                        .evaluate(Some(&principal(key, partial)))
                        .is_allow(),
                    "partial grants admitted: {row:?}"
                );
            }
            if row.policy.auth_mode() != AuthMode::InteractiveSession || !key {
                assert!(
                    row.policy
                        .evaluate(Some(&principal(
                            key,
                            required.iter().map(|p| p.to_string()).collect()
                        )))
                        .is_allow(),
                    "complete grants denied: {row:?}"
                );
            }
        }
    }
}

pub(super) fn check(inventory: &[Entry], shared: bool) {
    if !shared {
        let sources = entry(inventory, "GET", "/api/source-types");
        assert!(
            matches!(sources.policy.capability(), CapabilityRequirement::AnyOf(perms)
            if perms.as_ref() == nanosiem_api_lib::SOURCE_INVENTORY_CAPS)
        );
        all_of(
            inventory,
            &[("POST", "/api/sigma/convert", &["melod:detection"])],
        );
        if inventory
            .iter()
            .any(|r| r.path == "/api/marketplace/catalog/{slug}/preview")
        {
            all_of(
                inventory,
                &[(
                    "POST",
                    "/api/marketplace/catalog/{slug}/preview",
                    &["enrichments:configure"],
                )],
            );
        }
        if let Some(row) = inventory
            .iter()
            .find(|r| r.method == "POST" && r.path == "/api/notebooks/{id}/entries")
        {
            assert!(
                matches!(row.policy.capability(), CapabilityRequirement::AnyOf(perms)
                if perms.as_ref() == ["notebooks:edit", "cases:edit"])
            );
        }
        // These routes have request/resource-specific checks in their real
        // handlers. Inline parser samples need no raw-search grant, and a case
        // editor can add/chat without a separate notebooks:view grant.
        for (path, all, any) in [
            (
                "/api/dashboards/panel/query",
                &["dashboards:view"][..],
                &["search:execute", "search:sql"][..],
            ),
            (
                "/api/notebooks/{id}/chat",
                &["melod:notebook"][..],
                &["notebooks:edit", "cases:edit"][..],
            ),
            (
                "/api/notebooks/{id}/chat/stream",
                &["melod:notebook"][..],
                &["notebooks:edit", "cases:edit"][..],
            ),
            (
                "/api/melod/parser",
                &["melod:parser"][..],
                &["log_sources:view", "parsers:view"][..],
            ),
            (
                "/api/melod/parser/stream",
                &["melod:parser"][..],
                &["log_sources:view", "parsers:view"][..],
            ),
        ] {
            let Some(row) = inventory
                .iter()
                .find(|r| r.method == "POST" && r.path == path)
            else {
                continue;
            };
            assert!(
                matches!(row.policy.capability(), CapabilityRequirement::AllOfAnyOf { all: actual_all, any: actual_any }
                if *actual_all == all && *actual_any == any),
                "conditional capability became mandatory: {row:?}"
            );
        }
        return;
    }
    all_of(inventory, SHARED);
    for (method, path, floor) in [
        ("POST", "/api/notebooks/{id}/entries", "notebooks:view"),
        (
            "POST",
            "/api/notebooks/{id}/agent-entries",
            "notebooks:agent_record",
        ),
        (
            "DELETE",
            "/api/notebooks/{id}/entries/{entry_id}",
            "notebooks:view",
        ),
    ] {
        let row = entry(inventory, method, path);
        assert_eq!(row.policy.auth_mode(), AuthMode::InteractiveSession);
        assert!(
            matches!(row.policy.capability(), CapabilityRequirement::AllOfAnyOf { all, any }
            if *all == [floor] && *any == ["notebooks:edit", "cases:edit"])
        );
        for alternative in ["notebooks:edit", "cases:edit"] {
            assert!(
                row.policy
                    .evaluate(Some(&principal(
                        false,
                        vec![floor.into(), alternative.into()]
                    )))
                    .is_allow()
            );
            for (key, permissions) in [
                (false, vec![floor.into()]),
                (false, vec![alternative.into()]),
                (true, vec![floor.into(), alternative.into()]),
            ] {
                assert!(
                    !row.policy
                        .evaluate(Some(&principal(key, permissions)))
                        .is_allow()
                );
            }
        }
    }
    for action in ["accept", "bounce", "cancel"] {
        let path = format!("/api/cases/{{id}}/handoff/{{handoff_id}}/{action}");
        let row = entry(inventory, "POST", &path);
        assert_eq!(row.policy.auth_mode(), AuthMode::InteractiveSession);
        assert!(
            !row.policy
                .evaluate(Some(&principal(true, vec!["cases:assign".into()])))
                .is_allow()
        );
        assert!(
            row.policy
                .evaluate(Some(&principal(false, vec!["cases:assign".into()])))
                .is_allow()
        );
    }
}

#[cfg(feature = "enterprise")]
#[test]
fn shared_route_policy_required_grants() {
    // These are the actual production registration constructors and AppState
    // type. Inspecting their policy inventory requires no PostgreSQL fixture;
    // the full shared HTTP matrix still requires its exact-SHA fixture grant.
    use nanosiem_enterprise::handlers as shared;
    let inventory = shared::enterprise_shared_hunting::enterprise_shared_hunting_routes::<AppState>()
        .merge(shared::enterprise_shared_rule_repositories::enterprise_shared_rule_repositories_routes::<AppState>())
        .merge(shared::enterprise_shared_sources::enterprise_shared_sources_routes::<AppState>())
        .merge(shared::enterprise_shared_playbooks::enterprise_shared_playbooks_routes::<AppState>())
        .merge(shared::enterprise_shared_cases_extras::enterprise_shared_cases_extras_routes::<AppState>())
        .merge(shared::enterprise_shared_cases_notebooks::enterprise_shared_cases_notebooks_write_routes::<AppState>());
    let inventory = inventory.merge(
        shared::enterprise_shared_dashboard_panels::enterprise_shared_dashboard_panels_routes::<
            AppState,
        >(),
    );
    check(inventory.manifest(), true);
}
