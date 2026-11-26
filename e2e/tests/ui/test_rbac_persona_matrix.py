"""RBAC persona matrix (NAN-5686): every built-in role and one custom role,
logged in through the UI as a throwaway user, walk every top-level page, both
rails and every primary action.

Two oracles, so the test is not only checking the code against itself:

1. **Generated** (`nano_e2e.rbac_matrix`): route gates from `App.tsx`, rail
   gates from `AppLayout.tsx` / `ingestion-navigation.ts` /
   `automation-nav.ts`, Settings rail gates from `sections.ts`, built-in roles
   from the migrations, grants from `GET /api/roles`. The browser and the API
   must behave exactly as these say.
2. **Hand-maintained** (`e2e/coverage/rbac-baseline.json`): for the built-in
   roles and the custom role, the decision on every sensitive page and API
   (settings, users, roles, API keys, audit, source scopes, SOAR approvals,
   risk config, cases, ...) and the permissions a role must never hold. The
   generated expectation must agree with it, so a code or migration change
   that widens (or narrows) access fails here until someone edits the
   baseline on purpose.

For each persona:

- effective permissions (`/api/auth/me`) == role grants ∪ the "Everyone"
  group's. Every expectation below is computed from that EXPECTED set, never
  from what the server says, and a wildcard `*` is legal only where the
  baseline says so. Any permission string (a grant, a gate, an action) that
  is not in `GET /api/permissions` fails the test: it cannot be classified
  (on open, a gate behind a capability that is off is skipped: an open build
  does not define its enterprise permission);
- every page the persona may open renders (no Access Denied, no error
  boundary, no /login bounce, content, no 5xx, no unexpected 403); every page
  it may not open shows `route-forbidden` (or the licensed-feature panel when
  the capability is off) AND fetched no data first: a 2xx from any API the
  app shell does not call on every page is a pre-gate leak;
- the main rail (every collapsible group expanded) and the Settings rail show
  no item the persona may not use, and no item whose page would refuse it;
- primary actions over the API (core and, on enterprise, cases, hunts,
  playbooks, notebooks, risk, SOAR approvals, IOC lists, AI providers, source
  scopes; reads and mutations): allowed ones succeed, refused ones answer a
  clean 403 JSON error; gated UI controls are hidden when refused.

Per-persona results land in `rbac/<persona>.json`.
"""

from __future__ import annotations

import json
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import pytest
from nano_e2e import rbac_matrix as rm
from nano_e2e import ui as uilib
from nano_e2e.client import Journal, Nano, expect, jwt_claims, time_range
from nano_e2e.edition import UNLICENSED
from nano_e2e.rbac import role_browser, role_user
from nano_e2e.stack import Stack
from nano_e2e.waits import eventually

EVERYONE_GROUP = "00000000-0000-0000-0000-000000000001"
BUILTIN = rm.builtin_roles()
BASELINE = json.loads((Path(__file__).resolve().parents[2] / "coverage" / "rbac-baseline.json").read_text())
CUSTOM = "TriageAnalyst"
# The custom role: an alert-triage analyst who can read detections and
# lookups and acknowledge alerts, but authors nothing.
CUSTOM_PERMISSIONS = (
    "search:view",
    "search:execute",
    "alerts:view",
    "alerts:acknowledge",
    "detections:view",
    "lookup:view",
    "dashboards:view",
)
PERSONAS = [*BUILTIN, CUSTOM]

ROUTE_ERROR = {"testid": "route-error"}
DENIED = {"testid": "route-forbidden"}
STACK_TRACE = re.compile(r"(\n\s+at \S+ \(|stack backtrace|panicked at|Traceback \(most recent)")
# Pages the matrix does not walk: flows that need state (`/upload` takes a file).
EXCLUDE = ("/upload",)
# Known non-failures on any page (same list as test_page_smoke.py).
KNOWN = ((404, "/api/search/explanation/lookup"), (404, "/api/siem-health/reports/latest"),
         (409, "/api/soar/packs/upstream-updates"))
# 403s on pages a role may open, pinned to their bugs; any other 403 fails.
# NAN-5709 and NAN-5713 were fixed in #10112, NAN-5724 in its own PR; none remain.
KNOWN_403: dict[tuple[str, str], str] = {}
_ID_SEGMENT = re.compile(r"/(?:[a-z]+_[0-9a-hjkmnp-tv-z]{26}|[0-9a-f-]{36}|\d+)(?=/|$)")


def _api_path(url: str) -> str:
    """`/api/...` path with ids folded, no query: a stable endpoint name."""
    p = re.sub(r"[?#].*$", "", url.split("/api/", 1)[-1])
    return _ID_SEGMENT.sub("/:id", "/" + p).lstrip("/")


# --------------------------------------------------------------- primary actions
@dataclass
class Action:
    """A primary action over the API: the permission the product's handler
    checks, and how to do it as the persona."""

    id: str
    perm: str
    run: Callable[[Nano, dict[str, Any]], httpx.Response]
    cleanup: Callable[[Nano, httpx.Response], None] | None = None
    enterprise: bool = False
    ok: tuple[int, ...] = ()  # extra non-2xx answers that still mean "allowed"
    also: tuple[str, ...] = ()  # further permissions the handler ALSO requires (all of them)

    @property
    def perms(self) -> tuple[str, ...]:
        return (self.perm, *self.also)

    def allowed(self, held: set[str]) -> bool:
        return all(rm.holds(held, p) for p in self.perms)


def _rule_body(tag: str) -> dict[str, Any]:
    return {
        "name": f"rbac_matrix_{tag}",
        "description": "nano-e2e RBAC matrix (NAN-5686)",
        "query": f'"rbac-matrix-{tag}"',
        "severity": "low",
        "mode": "staging",
        "detection_mode": "scheduled",
        "schedule_cron": "*/30 * * * *",
        "folder": "Automated",
    }


def _delete_id(path: str) -> Callable[[Nano, httpx.Response], None]:
    def go(admin: Nano, resp: httpx.Response) -> None:
        if resp.status_code < 300 and resp.content:
            obj = resp.json()
            oid = obj.get("id") or (obj.get("key") or {}).get("id") or (obj.get("user") or {}).get("id")
            if oid:
                expect(admin.api.delete(path.format(id=oid)), 200, 204, 404)

    return go


def _lookup_cleanup(admin: Nano, resp: httpx.Response) -> None:
    if resp.status_code < 300:
        name = (resp.json() or {}).get("name") or (resp.json().get("table") or {}).get("name")
        if name:
            expect(admin.api.delete(f"/api/lookup-tables/{name}"), 200, 204, 404)


def _get(path: str, **params: Any) -> Callable[[Nano, dict[str, Any]], httpx.Response]:
    return lambda c, ctx: c.api.get(path, params=params or None)


ACTIONS: list[Action] = [
    # Core reads and writes.
    Action("search.execute", "search:execute",
           lambda c, ctx: c.search_http.post("/api/search", json={
               "query": "*", "limit": 1, "skip_histogram": True, "skip_field_stats": True, "use_cache": False,
               "time_range": time_range(15)})),
    Action("rules.create", "detections:create",
           lambda c, ctx: c.api.post("/api/rules", json=_rule_body(ctx["tag"])), _delete_id("/api/rules/{id}")),
    Action("rules.promote", "detections:promote",
           lambda c, ctx: c.api.post(f"/api/rules/{ctx['victim_rule']}/promote", json={"expected_mode": "staging"})),
    Action("rules.delete", "detections:delete", lambda c, ctx: c.api.delete(f"/api/rules/{ctx['victim_rule']}")),
    Action("alerts.view", "alerts:view", _get("/api/alerts", limit=1)),
    Action("dashboards.create", "dashboards:create",
           lambda c, ctx: c.api.post("/api/dashboards", json={
               "name": f"rbac-matrix-{ctx['tag']}", "layout": {"columns": 12, "rowHeight": 80, "items": []},
               "panels": [], "visibility": "private"}),
           _delete_id("/api/dashboards/{id}")),
    Action("lookup.create", "lookup:create",
           lambda c, ctx: c.api.post("/api/lookup-tables",
                                     files={"file": ("m.csv", b"k,v\na,1\n", "text/csv")},
                                     data={"config": json.dumps({"name": f"rbac_{ctx['tag']}", "format": "csv",
                                                                 "primary_key": "k", "mode": "append"})}),
           _lookup_cleanup),
    Action("log_sources.create", "log_sources:create",
           lambda c, ctx: c.api.post("/api/log-sources", json={
               "name": f"rbac_{ctx['tag']}", "description": "nano-e2e RBAC matrix", "source_type": "routed",
               "parser_vrl": "", "match_values": [f"rbac_{ctx['tag']}"], "lifecycle_status": "draft"}),
           _delete_id("/api/log-sources/{id}")),
    Action("log_sources.delete", "log_sources:delete",
           lambda c, ctx: c.api.delete(f"/api/log-sources/{ctx['victim_source']}")),
    Action("users.view", "users:view", _get("/api/users")),
    Action("users.create", "users:create",
           lambda c, ctx: c.api.post("/api/users", json={
               "email": f"rbac-victim-{ctx['tag']}@e2e.invalid", "name": f"rbac-victim-{ctx['tag']}",
               "password": "E2e-" + secrets.token_hex(12) + "!", "group_ids": []}),
           _delete_id("/api/users/{id}")),
    Action("groups.create", "groups:create",
           lambda c, ctx: c.api.post("/api/groups", json={
               "name": f"rbac-victim-{ctx['tag']}", "description": "nano-e2e", "role_ids": []}),
           _delete_id("/api/groups/{id}")),
    Action("roles.create", "roles:create",
           lambda c, ctx: c.api.post("/api/roles", json={
               "name": f"rbac-victim-{ctx['tag']}", "description": "nano-e2e", "permissions": ["search:view"]}),
           _delete_id("/api/roles/{id}")),
    Action("apikeys.create", "apikeys:create",
           lambda c, ctx: c.api.post("/api/api-keys", json={
               "name": f"rbac-matrix-{ctx['tag']}", "permissions": ["search:view"]}),
           _delete_id("/api/api-keys/{id}")),
    Action("audit.view", "audit:view", _get("/api/audit", limit=1)),
    Action("settings.retention.view", "settings:retention", _get("/api/settings/retention")),
    Action("settings.retention.update", "settings:retention",
           lambda c, ctx: c.api.put("/api/settings/storage/clickhouse/retention",
                                    json={"retention_days": ctx["retention_days"]})),
    Action("source_scopes.view", "source_scopes:view", _get("/api/source-scopes/restricted")),
    # Enterprise reads.
    Action("cases.list", "cases:view", _get("/api/cases", limit=1), enterprise=True),
    Action("hunts.list", "hunts:view", _get("/api/hunts"), enterprise=True),
    Action("hunts.leads", "hunts:view", _get("/api/hunts/leads"), enterprise=True),
    Action("playbooks.list", "playbooks:view", _get("/api/playbooks"), enterprise=True),
    Action("notebooks.list", "notebooks:view", _get("/api/notebooks"), enterprise=True),
    Action("risk.entities", "risk:view", _get("/api/risk/entities", limit=1), enterprise=True),
    Action("risk.settings", "risk:configure", _get("/api/settings/risk"), enterprise=True),
    # SOAR is off on a fresh stack: an allowed caller learns that (404/409),
    # a refused one gets the 403 first.
    Action("soar.approvals", "soar:view", _get("/api/soar/approvals"), enterprise=True, ok=(404, 409)),
    Action("ioc_lists.list", "enrichments:view", _get("/api/ioc-lists"), enterprise=True),
    Action("ai.providers", "settings:ai_providers", _get("/api/settings/ai-providers"), enterprise=True),
    # Agent Lane (NAN-5880). Status needs agentlane:manage; the switch, networks,
    # certificate and the checks need settings:system too. Every write here is a
    # no-op: the switch is set to what it already is, the network save carries a
    # stale revision (409) and so does the empty certificate upload, so an
    # allowed persona never changes the stack.
    Action("agentlane.status", "agentlane:manage", _get("/api/settings/agentlane"), enterprise=True),
    Action("agentlane.switch", "agentlane:manage",
           lambda c, ctx: c.api.put("/api/settings/agentlane",
                                    json={"enabled": bool(ctx["agentlane"].get("enabled", False))}),
           enterprise=True, also=("settings:system",), ok=(409, 422)),
    Action("agentlane.network", "agentlane:manage",
           lambda c, ctx: c.api.put("/api/settings/agentlane/network", json={
               "allow_cidrs": ctx["agentlane"].get("network", {}).get("allow_cidrs", []),
               "expected_revision": -1}),
           enterprise=True, also=("settings:system",), ok=(409, 422)),
    Action("agentlane.certificate", "agentlane:manage",
           lambda c, ctx: c.api.put("/api/settings/agentlane/certificate",
                                    json={"mode": "upload", "cert_pem": "", "key_pem": "", "expected_revision": -1}),
           enterprise=True, also=("settings:system",), ok=(409,)),
    Action("agentlane.certificate_download", "agentlane:manage",
           _get("/api/settings/agentlane/certificate/download"),
           enterprise=True, also=("settings:system",), ok=(404, 409)),
    Action("agentlane.check_address", "agentlane:manage",
           lambda c, ctx: c.api.post("/api/settings/agentlane/check-address", json={"ip": "192.0.2.1"}),
           enterprise=True, also=("settings:system",)),
    Action("agentlane.connection_test", "agentlane:manage",
           lambda c, ctx: c.api.post("/api/settings/agentlane/connection-test", json={}),
           enterprise=True, also=("settings:system",), ok=(409, 422)),
    Action("agentlane.connection_test_result", "agentlane:manage",
           _get("/api/settings/agentlane/connection-test/00000000-0000-0000-0000-000000000000"),
           enterprise=True, also=("settings:system",), ok=(404,)),
]

# UI controls behind the same gates: (page, control finder, permission).
UI_CONTROLS = [
    ("/dashboards", {"role": "button", "name": "New Dashboard", "exact": True}, "dashboards:create"),
    ("/settings/access-control?tab=users", {"role": "button", "name": "Invite user", "exact": True}, "users:create"),
    ("/settings/access-control?tab=roles", {"css": 'button[title="New role"]'}, "roles:create"),
    ("/settings/access-control?tab=api-keys", {"css": 'button[title="New API key"]'}, "apikeys:create"),
    ("/settings/access-control?tab=groups", {"css": 'button[title="New group"]'}, "groups:create"),
]


# --------------------------------------------------------------- helpers
@dataclass
class Persona:
    name: str
    role_ids: list[str]
    granted: set[str]
    effective: set[str] = field(default_factory=set)


def _roles(nano: Nano) -> dict[str, dict[str, Any]]:
    body = expect(nano.api.get("/api/roles"), 200)
    return {r["name"]: r for r in body["roles"]}


def _everyone_permissions(nano: Nano, roles: dict[str, dict[str, Any]]) -> set[str]:
    group = expect(nano.api.get(f"/api/groups/{EVERYONE_GROUP}"), 200)
    ids = {str(r.get("id", r)) if isinstance(r, dict) else str(r) for r in group.get("roles", group.get("role_ids", []))}
    perms: set[str] = set()
    for role in roles.values():
        if str(role["id"]) in ids or role["name"] in ids:
            perms |= set(role["permissions"])
    return perms


def _catalog(nano: Nano) -> set[str]:
    body = expect(nano.api.get("/api/permissions"), 200)
    items = body.get("permissions", body) if isinstance(body, dict) else body
    return {str(p["id"] if isinstance(p, dict) else p) for p in items}


def _clean_403(resp: httpx.Response) -> str | None:
    """None when a refusal is clean: 403, a JSON error body, no internals."""
    if resp.status_code != 403:
        return f"expected 403, got {resp.status_code}: {resp.text[:200]}"
    try:
        body = resp.json()
    except ValueError:
        return f"403 without a JSON body: {resp.text[:200]}"
    text = json.dumps(body)
    if STACK_TRACE.search(text) or "sqlx" in text or "SELECT " in text:
        return f"403 leaks internals: {text[:300]}"
    return None


def _settle(page: uilib.UiPage) -> str:
    try:
        page.wait_text(uilib.rx(r"^Loading\b.*…?$"), exact=False, timeout_ms=20_000, gone=True)
    except uilib.UiError:
        pass
    return eventually(
        lambda: page.main_text().strip(),
        timeout=20,
        interval=0.3,
        desc="the page to render content",
        ok=lambda t: len(t) >= 20 or page.count(DENIED) > 0 or page.count(ROUTE_ERROR) > 0
        or page.count(UNLICENSED) > 0,
    )


def _shell_endpoints(page: uilib.UiPage) -> set[str]:
    """APIs the app shell calls on any page (auth, capabilities, status bar):
    what a denied page may legitimately have fetched."""
    shell: set[str] = set()
    # Both shells: the Settings layout and the main app layout (rail badges,
    # status bar, pivt), twice each so slow pollers are seen.
    for path in ("/settings/user", "/", "/settings/user", "/", "/getting-started"):
        _quiet(page)
        since = page.now_ms()
        page.goto(path)
        _settle(page)
        _quiet(page)
        shell |= {_api_path(r["url"]) for r in page.api_responses_since(since)}
    return shell


def _quiet(page: uilib.UiPage) -> None:
    """Wait until no API response has arrived for 1.5 s, so a response the
    previous page asked for is not counted against the next one."""
    eventually(lambda: page.api_responses_since(page.now_ms() - 1500), timeout=15, interval=0.5,
               desc="network quiet", ok=lambda rs: not rs)


def _visit(page: uilib.UiPage, gate: rm.Gate, allowed: bool, capabilities: dict[str, bool],
           shell: set[str]) -> dict[str, Any]:
    try:
        _quiet(page)
    except AssertionError:
        pass  # a page that polls; its late responses are attributed by path below
    since = page.now_ms()
    page.goto(gate.path)
    problems: list[str] = []
    known: list[str] = []
    try:
        main = _settle(page)
    except AssertionError as exc:
        main = ""
        problems.append(f"blank page: {exc}"[:300])
    url = page.url
    denied = page.count(DENIED) > 0
    unlicensed = page.count(UNLICENSED) > 0
    if page.count(ROUTE_ERROR):
        problems.append("route error boundary: " + page.texts(ROUTE_ERROR)[0][:200])
    if STACK_TRACE.search(main):
        problems.append("stack trace on the page")
    if re.search(r"/login(\?|$)", url):
        problems.append(f"bounced to {url}")
    responses = [r for r in page.api_responses_since(since)
                 if not any(r["status"] == code and frag in r["url"] for code, frag in KNOWN)]
    five = [f"{r['status']} {r['url']}" for r in responses if r["status"] >= 500]
    if five:
        problems.append(f"5xx: {five[:4]}")
    if allowed:
        if denied:
            problems.append(f"Access Denied, but the role holds {gate.needs}")
        elif unlicensed:
            problems.append("licensed-feature panel on a licensed stack")
        elif len(main) < 20:
            problems.append(f"main content is empty ({main[:60]!r})")
        for api in sorted({_api_path(r["url"]) for r in responses if r["status"] == 403}):
            bug = KNOWN_403.get((gate.path, api))
            (known if bug else problems).append(
                f"allowed page called {api}, which answered 403" + (f" ({bug})" if bug else ""))
    else:
        cap_missing = bool(gate.capability) and not capabilities.get(gate.capability, False)
        if cap_missing:
            if not (denied or unlicensed):
                problems.append(f"capability {gate.capability} is off but the page neither refused nor showed the "
                                "licensed-feature panel")
        elif not denied:
            problems.append(f"opened without {gate.needs} (expected route-forbidden)")
        # Nothing behind the gate may have been fetched on the way.
        fetched = sorted({_api_path(r["url"]) for r in responses if 200 <= r["status"] < 300} - shell)
        if fetched:
            problems.append(f"denied page fetched data before the gate (2xx): {fetched[:6]}")
    return {"path": gate.path, "needs": gate.needs, "allowed": allowed, "denied_shown": denied,
            "url": url, "problems": problems, "known": known}


def _shown(page: uilib.UiPage, items: list[rm.NavItem], container: str) -> set[str]:
    return {i.href for i in items
            if page.count({"css": f'[data-testid="{container}"] a[href="{i.href}"]', "visible": False})}


def _main_rail_shown(page: uilib.UiPage, items: list[rm.NavItem]) -> set[str]:
    """Rail links across every collapsible group. The groups are an accordion
    (one open at a time) and render their links only while open, so open each
    group in turn and collect what it shows."""
    toggles = {"css": '[data-testid="app-rail"] nav button:has(svg.lucide-chevron-down)'}
    shown = _shown(page, items, "app-rail")
    # The open group's links are already counted; clicking it closes it and
    # clicking a closed one opens it, so clicking every toggle once visits all.
    for i in range(page.count(toggles)):
        page.click({**toggles, "nth": i})
        shown |= _shown(page, items, "app-rail")
    return shown


def _rail_problems(shown: set[str], items: list[rm.NavItem], container: str, perms: set[str],
                   capabilities: dict[str, bool], gates: dict[str, rm.Gate], edition: str | None = None) -> list[str]:
    problems = []
    for item in items:
        if item.href not in shown:
            continue
        if not item.in_edition(edition):
            problems.append(f"{container} shows the enterprise-only {item.name} ({item.href}) on a {edition} build")
            continue
        if not rm.nav_visible(item, perms, capabilities, edition):
            problems.append(f"{container} shows {item.name} ({item.href}) without {item.permissions}")
        gate = gates.get(item.href.split("?")[0])
        if gate and not gate.redirect and gate.permission != "<dynamic>" and not gate.allows(perms, capabilities):
            problems.append(f"{container} shows {item.href}, but its page refuses the persona ({gate.needs})")
    return problems


@pytest.fixture(scope="module")
def matrix_admin(stack: Stack) -> Any:
    def bearer() -> dict[str, str]:
        login = Nano(stack.api_url, stack.search_url, {}, Journal(None))
        try:
            jwt = login.login(stack.admin_email, stack.admin_password)
        finally:
            login.close()
        # A shortened access TTL must fail here, not hide behind re-logins.
        claims = jwt_claims(jwt) or {}
        life = claims.get("exp", 0) - claims.get("iat", 0)
        assert life >= 600, f"the admin access token lives {life}s"
        return {"Authorization": f"Bearer {jwt}"}

    client = Nano(stack.api_url, stack.search_url, bearer(),
                  Journal(stack.artifact_dir / "rbac-matrix-admin.jsonl"))
    # The module walks every persona (about 5 min each) and outlives the 15 min
    # access token; an expired one ended the last persona's cleanup in 401s
    # (NAN-5827). Log in again on a 401 for an expired token only (Http.reauth).
    client.api.reauth = bearer
    client.search_http.reauth = bearer
    yield client
    client.close()


@pytest.fixture(scope="module")
def custom_role(matrix_admin: Nano) -> Any:
    role = expect(matrix_admin.api.post("/api/roles", json={
        "name": f"{CUSTOM}-{secrets.token_hex(3)}", "description": "nano-e2e custom role (NAN-5686)",
        "permissions": list(CUSTOM_PERMISSIONS)}), 200, 201)
    yield role
    expect(matrix_admin.api.delete(f"/api/roles/{role['id']}"), 200, 204, 404)


def test_baseline_names_every_persona_and_only_known_paths() -> None:
    """The hand-maintained baseline covers every built-in role, and every
    route / action it names still exists (a rename must update it)."""
    roles = BASELINE["roles"]
    assert set(roles) == set(PERSONAS), f"baseline roles {sorted(roles)} != personas {sorted(PERSONAS)}"
    gates = rm.route_gates()
    ids = {a.id for a in ACTIONS}
    for name, entry in roles.items():
        unknown_routes = sorted(set(entry["routes"]) - set(gates))
        unknown_actions = sorted(set(entry["actions"]) - ids)
        assert not unknown_routes and not unknown_actions, (name, unknown_routes, unknown_actions)
        assert set(entry["routes"].values()) <= {"allow", "deny"}
        assert set(entry["actions"].values()) <= {"allow", "deny"}


@pytest.mark.parametrize("persona_name", PERSONAS)
def test_rbac_persona_matrix(
    persona_name: str, stack: Stack, nano: Nano, matrix_admin: Nano, custom_role: dict[str, Any],
    ui: uilib.Driver, artifact_dir: Path, timeline,
) -> None:
    roles = _roles(matrix_admin)
    system = {name for name, r in roles.items() if r.get("is_system")}
    assert set(BUILTIN) <= system, f"migrations seed {sorted(BUILTIN)}, /api/roles has system roles {sorted(system)}"
    if persona_name == CUSTOM:
        persona = Persona(CUSTOM, [str(custom_role["id"])], set(CUSTOM_PERMISSIONS))
    else:
        role = roles[persona_name]
        persona = Persona(persona_name, [str(role["id"])], set(role["permissions"]))
    base = BASELINE["roles"][persona_name]
    everyone = _everyone_permissions(matrix_admin, roles)
    catalog = _catalog(matrix_admin)
    capabilities = expect(nano.api.get("/api/capabilities"), 200).get("capabilities", {})
    gates_by_path = rm.route_gates()
    gates = rm.walkable(gates_by_path, exclude=EXCLUDE)
    enterprise = stack.edition == "enterprise"
    actions = [a for a in ACTIONS if enterprise or not a.enterprise]
    out = artifact_dir / "rbac"
    out.mkdir(parents=True, exist_ok=True)
    problems: list[str] = []

    # 0. The EXPECTED permission set drives everything; classify every string.
    expected = persona.granted | everyone
    if "*" in expected and not base.get("wildcard", False):
        problems.append("the role is granted the wildcard '*', which the baseline does not allow")
    # Open only: an open build does not define the permissions of gates behind
    # an off capability. Enterprise defines every permission, licensed or not.
    # `edition` drops enterpriseOnly Settings entries (Agent Lane) on open and
    # keeps them on enterprise, where their permission must be defined.
    gate_perms = rm.all_gate_permissions(None if enterprise else capabilities, edition=stack.edition)
    classify = expected | gate_perms | {p for a in actions for p in a.perms}
    unknown = sorted(classify - catalog - {"*"})
    if unknown:
        problems.append(f"permission strings not in /api/permissions (cannot be classified): {unknown}")
    held_forbidden = sorted(p for p in base["never_holds"] if p in expected or "*" in expected)
    if held_forbidden:
        problems.append(f"the role holds permissions the baseline forbids it: {held_forbidden}")

    # 1. The generated expectations agree with the hand-maintained baseline.
    for path, want in base["routes"].items():
        cap = gates_by_path[path].capability
        if cap and not capabilities.get(cap, False):
            continue  # unlicensed on this stack: licensing refuses it, not RBAC
        got = "allow" if gates_by_path[path].allows(expected, capabilities) else "deny"
        if got != want:
            problems.append(f"baseline: {path} is '{want}' for {persona_name}, the code now says '{got}' "
                            f"(gate {gates_by_path[path].needs})")
    action_of = {a.id: a for a in actions}
    for aid, want in base["actions"].items():
        if aid not in action_of:
            continue  # an enterprise action on an open stack
        got = "allow" if action_of[aid].allowed(expected) else "deny"
        if got != want:
            problems.append(f"baseline: API {aid} is '{want}' for {persona_name}, the code now says '{got}'")
    perms = expected

    tag = f"{persona_name.lower()}_{secrets.token_hex(3)}"
    victim = expect(matrix_admin.api.post("/api/rules", json=_rule_body(f"victim_{tag}")), 200, 201)
    victim_source = expect(matrix_admin.api.post("/api/log-sources", json={
        "name": f"rbac_victim_{tag}", "description": "nano-e2e RBAC matrix", "source_type": "routed",
        "parser_vrl": "", "match_values": [f"rbac_victim_{tag}"], "lifecycle_status": "draft"}), 200, 201)
    overview = expect(matrix_admin.api.get("/api/settings/storage/overview"), 200)
    record: dict[str, Any] = {"persona": persona_name}
    try:
        with role_user(stack, f"rbac-{persona_name}", persona.role_ids,
                       Journal(artifact_dir / "rbac-user.jsonl")) as user:
            ui.register_secret(user.password)
            page = uilib.UiPage.open(ui, artifact_dir / "ui", name=f"rbac:{persona_name}")
            failed = True
            try:
                uilib.login(page, user.email, user.password)
                me = page.session_fetch("GET", "/api/auth/me")
                assert me["status"] == 200, me
                persona.effective = set(me["json"]["permissions"])
                if "*" in expected:
                    if "*" not in persona.effective:
                        problems.append(f"expected the wildcard '*', got {sorted(persona.effective)}")
                elif persona.effective != expected:
                    problems.append(
                        f"effective permissions differ from role ∪ Everyone: "
                        f"extra={sorted(persona.effective - expected)} missing={sorted(expected - persona.effective)}"
                    )
                record["permissions"] = sorted(expected)
                timeline.step("persona", persona=persona_name, permissions=len(expected))

                # 2. Every top-level page.
                shell = _shell_endpoints(page)
                record["shell_endpoints"] = sorted(shell)
                pages = []
                for gate in gates:
                    allowed = gate.allows(perms, capabilities)
                    try:
                        rec = _visit(page, gate, allowed, capabilities, shell)
                    except uilib.UiError as exc:
                        rec = {"path": gate.path, "needs": gate.needs, "allowed": allowed,
                               "problems": [f"driver: {exc}"[:300]], "known": []}
                    pages.append(rec)
                    problems += [f"{gate.path}: {p}" for p in rec["problems"]]
                    if rec["problems"]:
                        page.screenshot(f"rbac-{persona_name}-{re.sub(r'[^a-z0-9]+', '-', gate.path.lower()).strip('-')}.png",
                                        full_page=False)
                record["pages"] = pages
                timeline.step("pages walked", total=len(pages), allowed=sum(p["allowed"] for p in pages),
                              bad=[p["path"] for p in pages if p["problems"]],
                              known=[k for p in pages for k in p["known"]])

                # 3. Both rails, every group expanded.
                page.goto("/")
                _settle(page)
                eventually(lambda: page.count({"testid": "app-rail"}), timeout=15, interval=0.3, desc="the rail")
                shown = _main_rail_shown(page, rm.nav_items())
                rail = _rail_problems(shown, rm.nav_items(), "app-rail", perms, capabilities, gates_by_path)
                page.goto("/settings/user")
                _settle(page)
                eventually(lambda: page.count({"testid": "settings-rail"}), timeout=15, interval=0.3,
                           desc="the Settings rail")
                sshown = _shown(page, rm.settings_items(), "settings-rail")
                srail = _rail_problems(sshown, rm.settings_items(), "settings-rail", perms, capabilities,
                                       gates_by_path, stack.edition)
                problems += rail + srail
                record["rail"] = {"main": sorted(shown), "settings": sorted(sshown), "problems": rail + srail}

                # 4. UI controls behind permissions.
                controls = []
                for path, control, perm in UI_CONTROLS:
                    gate = gates_by_path.get(path.split("?")[0])
                    if gate and not gate.allows(perms, capabilities):
                        continue
                    page.goto(path)
                    _settle(page)
                    want = rm.holds(perms, perm)
                    if want:
                        try:
                            page.wait_for(control, timeout_ms=15_000)
                            shown_c = True
                        except uilib.UiError:
                            shown_c = False
                    else:
                        shown_c = page.count(control) > 0
                    controls.append({"path": path, "perm": perm, "want": want, "shown": shown_c})
                    if shown_c != want:
                        problems.append(f"{path}: control {control} {'shown' if shown_c else 'hidden'} "
                                        f"but the persona {'holds' if want else 'lacks'} {perm}")
                record["controls"] = controls
                failed = False
            finally:
                page.finish(failed or bool(problems))

            # 5. Primary actions over the API, as the persona (JWT).
            jwt = Nano(stack.api_url, stack.search_url, {}, Journal(None)).login(user.email, user.password)
            client = Nano(stack.api_url, stack.search_url, {"Authorization": f"Bearer {jwt}"},
                          Journal(artifact_dir / "rbac-persona-api.jsonl"))
            results = []
            try:
                ctx = {"tag": tag, "victim_rule": victim["id"], "victim_source": victim_source["id"],
                       "retention_days": overview["clickhouse"]["ttl_days"],
                       # The Agent Lane actions write back what is already there (NAN-5880).
                       "agentlane": (expect(matrix_admin.api.get("/api/settings/agentlane"), 200)
                                     if enterprise else {})}
                for act in actions:
                    want = act.allowed(perms)
                    resp = act.run(client, ctx)
                    ok = resp.status_code < 300 or resp.status_code in act.ok
                    note = None
                    if want and not ok:
                        held = " + ".join(act.perms)
                        note = (f"{act.id}: refused ({resp.status_code}) but the persona holds {held}: "
                                f"{resp.text[:200]}")
                    elif not want:
                        bad = _clean_403(resp)
                        if bad:
                            note = f"{act.id} without {' + '.join(act.perms)}: {bad}"
                    if act.cleanup:
                        act.cleanup(matrix_admin, resp)
                    results.append({"id": act.id, "perm": " + ".join(act.perms), "want": want,
                                    "status": resp.status_code})
                    if note:
                        problems.append(note)
            finally:
                client.close()
            record["actions"] = results
    finally:
        expect(matrix_admin.api.delete(f"/api/rules/{victim['id']}"), 200, 204, 404)
        expect(matrix_admin.api.delete(f"/api/log-sources/{victim_source['id']}"), 200, 204, 404)
        record["problems"] = problems
        (out / f"{persona_name}.json").write_text(json.dumps(record, indent=2))
    timeline.step("matrix", persona=persona_name, problems=len(problems))
    assert not problems, f"RBAC matrix for {persona_name}:\n" + "\n".join(f"- {p}" for p in problems)


def test_allowed_pages_call_apis_the_role_cannot_use(stack: Stack, ui: uilib.Driver, artifact_dir: Path, timeline) -> None:
    """NAN-5713: as the built-in ReadOnly role, the pages it may open must
    not call APIs it is refused. Self-contained (no state from the matrix).

    Enterprise: the real pages mount (no license panel, Access Denied or
    error boundary) and call no API that answers 403. Open (NAN-5747): both
    routes are capability-off, so the license panel renders, and it calls no
    API that answers 403 or 404 and fetches nothing beyond the app shell."""
    gates = rm.route_gates()
    open_build = stack.edition == "open"
    with role_browser(stack, ui, artifact_dir, "rbac-readonly-403", [BUILTIN["ReadOnly"]]) as (page, client, _):
        me = expect(client.api.get("/api/auth/me"), 200)
        perms = set(me["permissions"])
        caps = expect(client.api.get("/api/capabilities"), 200).get("capabilities", {})
        shell = _shell_endpoints(page) if open_build else set()
        found = []
        for path in ("/inbox", "/risk"):
            g = gates[path]
            if open_build:
                assert rm.holds(perms, g.permission, g.any_permission), (
                    f"ReadOnly may no longer open {path}: update this test")
                assert g.capability and not caps.get(g.capability, False), (
                    f"open build: {path} expected capability-off, capabilities={caps}")
            else:
                assert g.allows(perms, caps), f"ReadOnly may no longer open {path}: update this test"
            since = page.now_ms()
            page.goto(path)
            _settle(page)
            if open_build:
                assert page.count(UNLICENSED) > 0, f"open build: {path} does not show the license panel"
            else:
                blocked = page.count(UNLICENSED) + page.count(DENIED) + page.count(ROUTE_ERROR)
                assert blocked == 0, f"{path}: the real page did not mount: {page.main_text()[:200]}"
            responses = [r for r in page.api_responses_since(since)
                         if not any(r["status"] == code and frag in r["url"] for code, frag in KNOWN)]
            refused = (403, 404) if open_build else (403,)
            found += sorted({f"{path}→{r['status']} {_api_path(r['url'])}"
                             for r in responses if r["status"] in refused})
            if open_build:
                fetched = {_api_path(r["url"]) for r in responses if 200 <= r["status"] < 300}
                found += sorted(f"{path}→2xx {api}" for api in fetched - shell)
        timeline.step("refused or unexpected API calls on allowed pages", found=found)
        page.screenshot("rbac-readonly-inbox-403s.png", full_page=False)
        assert not found, "refused or unexpected API calls on allowed pages: " + ", ".join(found)


def test_rule_repositories_page_calls_no_refused_api(stack: Stack, ui: uilib.Driver, artifact_dir: Path, timeline) -> None:
    """NAN-5724: as ReadOnly, /rules/repositories loads its list (NAN-5709
    fixed) and calls no API that refuses the role."""
    with role_browser(stack, ui, artifact_dir, "rbac-readonly-repos", [BUILTIN["ReadOnly"]]) as (page, client, _):
        since = page.now_ms()
        page.goto("/rules/repositories")
        _settle(page)
        responses = page.api_responses_since(since)
        assert any(_api_path(r["url"]) == "rule-repositories" and r["status"] == 200 for r in responses), responses
        found = sorted({_api_path(r["url"]) for r in responses if r["status"] == 403})
        timeline.step("403s on /rules/repositories", found=found)
        assert not found, f"/rules/repositories called refused APIs: {found}"
