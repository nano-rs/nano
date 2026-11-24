"""The RBAC persona matrix is generated from App.tsx / AppLayout.tsx and the
migrations (NAN-5686): prove the parser reads them, so a refactor that hides
the gates from it fails here, not silently in a smaller matrix."""

from __future__ import annotations

from nano_e2e import rbac_matrix as rm


def test_route_gates_are_read_from_app_tsx() -> None:
    gates = rm.route_gates()
    assert gates["/rules"].permission == "detections:view"
    assert gates["/rules/editor/new"].permission == "detections:create"
    # NAN-5850: the hunt settings pages moved; their old routes are redirects.
    assert gates["/settings/hunts"].permission == "hunts:view" and gates["/settings/hunts"].capability == "hunts"
    assert gates["/rules/ideas"].permission == "hunts:view" and gates["/rules/ideas"].capability == "hunts"
    assert gates["/hunts/runners"].redirect and gates["/hunts/rule-ideas"].redirect
    assert gates["/automation"].redirect  # a generated <Route key=...> block lends no gate upward
    assert "users:view" in gates["/settings/access-control"].any_permission
    assert gates["/settings/users"].redirect
    walk = {g.path for g in rm.walkable(gates)}
    assert len(walk) >= 60, len(walk)
    assert not any(":" in p for p in walk)
    assert "/ingestion/log-sources/new" not in walk  # computed permission


def test_rail_gates_and_builtin_roles() -> None:
    nav = {n.href: n for n in rm.nav_items()}
    assert nav["/rules"].permissions == ("detections:view",)
    assert nav["/getting-started"].permissions == ("settings:view",)
    # A const href resolves (AppLayout's RULE_IDEAS_PATH, NAN-5850).
    assert nav["/rules/ideas"].permissions == ("hunts:view",) and nav["/rules/ideas"].capability == "hunts"
    assert set(rm.builtin_roles()) >= {"Admin", "Editor", "ReadOnly"}


def test_allows_honours_wildcard_any_and_capability() -> None:
    g = rm.Gate(path="/x", permission="a:b", capability="cap")
    assert not g.allows({"a:b"}, {"cap": False})
    assert g.allows({"a:b"}, {"cap": True})
    assert g.allows({"*"}, {"cap": True})
    assert rm.Gate(path="/y", any_permission=("p", "q")).allows({"q"}, {})


def test_every_rail_is_parsed_with_its_gates() -> None:
    hrefs = {n.href: n for n in rm.nav_items()}
    assert hrefs["/ingestion/log-sources"].permissions  # ingestion-navigation.ts
    assert "/automation/approvals" in hrefs and hrefs["/automation/approvals"].permissions == ("soar:view",)
    settings = {s.href: s for s in rm.settings_items()}
    assert settings["/settings/audit"].permissions == ("audit:view",)
    assert settings["/settings/storage"].permissions == ("settings:retention",)
    assert "settings:system" in rm.all_gate_permissions()


def test_rbac_baseline_is_hand_maintained_and_complete() -> None:
    import json
    from pathlib import Path

    base = json.loads((Path(rm.ROOT) / "e2e" / "coverage" / "rbac-baseline.json").read_text())
    assert set(base["roles"]) >= set(rm.builtin_roles())
    gates = rm.route_gates()
    for role, entry in base["roles"].items():
        assert set(entry["routes"]) <= set(gates), (role, set(entry["routes"]) - set(gates))
        for sensitive in ("/settings/access-control", "/settings/audit", "/settings/source-scopes", "/settings/risk",
                          "/automation/approvals"):
            assert sensitive in entry["routes"], (role, sensitive)
