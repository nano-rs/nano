"""The RBAC persona matrix, generated from the code (NAN-5686).

The expectations are not hand-written. They come from the same definitions
the product enforces:

- route gates: every `<Route path=...>` in `nanosiem-web/src/App.tsx` whose
  element is a `<PermissionRoute permission=... | anyPermission=[...]
  capability=...>` (and the `[path, Page]` tuple lists mapped through one);
- rail gates: every `{ name, href, permissions, capability }` item in
  `components/layout/AppLayout.tsx`, and every Settings entry in
  `components/layout/settings/sections.ts` (which also carries
  `enterpriseOnly`: shown only in the enterprise build, whatever the license);
- role grants: `GET /api/roles` (built-in roles carry `is_system`), read at
  run time, so a migration that changes a built-in role changes the matrix.

A role "can open" a route when it holds the route's permission (or any of its
`anyPermission`, or `*`) and the stack has the route's capability. Routes with
path parameters are left out (the matrix walks top-level pages).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
APP = ROOT / "nanosiem-web" / "src" / "App.tsx"
LAYOUT = ROOT / "nanosiem-web" / "src" / "components" / "layout" / "AppLayout.tsx"

_ROUTE = re.compile(r'<Route\b[^>]*?\bpath="([^"]+)"')
_PERM = re.compile(r'<PermissionRoute\b([^>]*?)element=\{', re.S)
_ATTR_PERM = re.compile(r'\bpermission="([^"]+)"')
_ATTR_ANY = re.compile(r"\banyPermission=\{\[([^\]]*)\]\}")
_ATTR_CAP = re.compile(r'\bcapability="([^"]+)"')
_TUPLES = re.compile(r"\{\(\[(.*?)\]\s*as const\)\.map\((.*?)\)\)\}", re.S)
_TUPLE_PATH = re.compile(r"\[\s*'(/[^']*)',\s*[A-Z]\w*\s*\]")
# href: a quoted path, or a const declared in the same file (RULE_IDEAS_PATH, NAN-5850).
_NAV = re.compile(r"\{\s*name:\s*'([^']+)',\s*href:\s*('/[^']*'|[A-Z][A-Z0-9_]*)([^}]*)\}")
_NAV_PERMS = re.compile(r"permissions:\s*(\[[^\]]*\]|'[^']+'|[A-Z_]+)")


@dataclass(frozen=True)
class Gate:
    path: str
    permission: str | None = None
    any_permission: tuple[str, ...] = ()
    capability: str | None = None
    redirect: bool = False

    def allows(self, perms: set[str], capabilities: dict[str, bool]) -> bool:
        if self.capability and not capabilities.get(self.capability, False):
            return False
        return holds(perms, self.permission, self.any_permission)

    @property
    def needs(self) -> str:
        if self.permission:
            return self.permission
        if self.any_permission:
            return "any(" + ", ".join(self.any_permission) + ")"
        return "(signed in)"


@dataclass(frozen=True)
class NavItem:
    name: str
    href: str
    permissions: tuple[str, ...]
    capability: str | None
    # `enterpriseOnly: true` (sections.ts): the build, not the license, hides
    # it. An open build neither shows it nor defines its permission.
    enterprise_only: bool = False

    def in_edition(self, edition: str | None) -> bool:
        """False only for an enterpriseOnly entry on a known non-enterprise
        build; `None` (edition unknown) keeps every entry."""
        return not self.enterprise_only or edition in (None, "enterprise")


def holds(perms: set[str], permission: str | None, any_permission: tuple[str, ...] = ()) -> bool:
    if "*" in perms:
        return True
    if permission:
        return permission in perms
    if any_permission:
        return any(p in perms for p in any_permission)
    return True


def _quoted(s: str) -> tuple[str, ...]:
    return tuple(re.findall(r"'([^']+)'", s))


def _gate_from(path: str, chunk: str) -> Gate:
    m = _PERM.search(chunk)
    if not m:
        # A route whose element is a redirect (inline or a *Redirect component).
        redirect = bool(re.search(r"<(?:Navigate|\w*Redirect)\b", chunk))
        return Gate(path=path, redirect=redirect)
    redirect = False
    if re.search(r"\bpermission=\{", m.group(1)):
        # Computed at render time (e.g. sourceOnboardingPermission): no static gate.
        return Gate(path=path, permission="<dynamic>")
    attrs = m.group(1)
    perm = _ATTR_PERM.search(attrs)
    anyp = _ATTR_ANY.search(attrs)
    cap = _ATTR_CAP.search(attrs)
    return Gate(
        path=path,
        permission=perm.group(1) if perm else None,
        any_permission=_quoted(anyp.group(1)) if anyp else (),
        capability=cap.group(1) if cap else None,
        redirect=redirect,
    )


def route_gates(src: str | None = None) -> dict[str, Gate]:
    """{path: Gate} for every App.tsx route (catch-alls excluded)."""
    src = src if src is not None else APP.read_text(encoding="utf-8")
    gates: dict[str, Gate] = {}
    starts = [(m.start(), m.end(), m.group(1)) for m in _ROUTE.finditer(src)]
    for i, (_start, end, path) in enumerate(starts):
        if path in ("*", "/*"):
            continue
        nxt = starts[i + 1][0] if i + 1 < len(starts) else len(src)
        # Stop at the next <Route of any shape too: a generated `<Route key={path}`
        # block must not lend its gate to the redirect route above it (NAN-5850).
        any_next = src.find("<Route", end)
        if 0 <= any_next < nxt:
            nxt = any_next
        gates.setdefault(path, _gate_from(path, src[end:nxt]))
    for m in _TUPLES.finditer(src):
        body = m.group(2)
        perm = _PERM.search(body)
        attrs = perm.group(1) if perm else ""
        p = _ATTR_PERM.search(attrs)
        a = _ATTR_ANY.search(attrs)
        c = _ATTR_CAP.search(attrs)
        for path in _TUPLE_PATH.findall(m.group(1)):
            gates[path] = Gate(
                path=path,
                permission=p.group(1) if p else None,
                any_permission=_quoted(a.group(1)) if a else (),
                capability=c.group(1) if c else None,
            )
    return gates


def walkable(gates: dict[str, Gate], *, exclude: tuple[str, ...] = ()) -> list[Gate]:
    """Top-level pages: no path parameter, not a redirect, not a bare-auth
    flow page, not listed in `exclude`."""
    flow = {"/login", "/setup", "/mfa-setup", "/denied", "/demo", "/getting-started"}
    return [
        g
        for p, g in sorted(gates.items())
        if ":" not in p and not g.redirect and g.permission != "<dynamic>" and p not in flow and p not in exclude and not p.startswith("/auth/")
    ]


INGESTION_NAV = ROOT / "nanosiem-web" / "src" / "components" / "layout" / "ingestion-navigation.ts"
AUTOMATION_NAV = ROOT / "nanosiem-web" / "src" / "enterprise" / "pages" / "Automation" / "automation-nav.ts"
SETTINGS_SECTIONS = ROOT / "nanosiem-web" / "src" / "components" / "layout" / "settings" / "sections.ts"


def nav_items(src: str | None = None) -> list[NavItem]:
    """Every rail item with its permission and capability gate: AppLayout's
    own lists, the Ingestion section (ingestion-navigation.ts) and the
    Automation section (automation-nav.ts)."""
    if src is None:
        items = _nav_items(LAYOUT.read_text(encoding="utf-8"))
        items += _nav_items(INGESTION_NAV.read_text(encoding="utf-8"))
        items += automation_nav_items()
        return items
    return _nav_items(src)


def automation_nav_items() -> list[NavItem]:
    """Automation's rail entries carry no permission of their own: the section
    exists only when the SOAR gate (settings readable with `soar:view`) is on,
    and every /automation route requires `soar:view` + the `soar` capability."""
    if not AUTOMATION_NAV.is_file():
        return []
    out = []
    for name, href in re.findall(r"\{\s*name:\s*'([^']+)',\s*href:\s*'(/[^']*)'", AUTOMATION_NAV.read_text(encoding="utf-8")):
        if not href.startswith("/automation/"):
            raise AssertionError(f"automation-nav.ts item {name} -> {href} is outside /automation: classify its gate")
        out.append(NavItem(name, href, ("soar:view",), "soar"))
    return out


def settings_items(src: str | None = None) -> list[NavItem]:
    """Settings rail sections and their children (sections.ts) with their
    `permissions` (ANY of) and `capability`; an entry with no permissions is
    visible to anyone who can open Settings."""
    src = src if src is not None else SETTINGS_SECTIONS.read_text(encoding="utf-8")
    out = []
    for m in re.finditer(r"href:\s*'(/[^']*)'", src):
        # The entry's own fields: from this href to the next href / id.
        tail = src[m.end():]
        stop = re.search(r"\bhref:|\bid:\s*'", tail)
        body = tail[: stop.start()] if stop else tail
        if src[max(0, m.start() - 4): m.start()].strip().startswith("//"):
            continue
        line_start = src.rfind("\n", 0, m.start()) + 1
        if src[line_start:m.start()].lstrip().startswith("//"):
            continue
        pm = _NAV_PERMS.search(body)
        cap = re.search(r"capability:\s*'([^']+)'", body)
        ent = re.search(r"\benterpriseOnly:\s*(true|false)\b", body)
        out.append(NavItem(m.group(1), m.group(1), _quoted(pm.group(1)) if pm else (), cap.group(1) if cap else None,
                           enterprise_only=bool(ent and ent.group(1) == "true")))
    return out


def all_gate_permissions(capabilities: dict[str, bool] | None = None, *, edition: str | None = None) -> set[str]:
    """Every permission string a route, rail item or settings entry names.

    With `capabilities`, gates behind a capability that is off are left out:
    licensing refuses those before RBAC, and an open build does not define
    their enterprise permissions (`hunts:view`, `soar:view`, ...; NAN-5747),
    so they cannot be classified against its `/api/permissions`. With
    `edition="open"`, `enterpriseOnly` Settings entries are left out for the
    same reason (Agent Lane's `agentlane:manage`); on enterprise they are
    kept, so their permission must be in the catalog."""

    def live(capability: str | None) -> bool:
        return capabilities is None or not capability or capabilities.get(capability, False)

    perms: set[str] = set()
    for g in route_gates().values():
        if not live(g.capability):
            continue
        if g.permission and g.permission != "<dynamic>":
            perms.add(g.permission)
        perms.update(g.any_permission)
    for item in nav_items() + settings_items():
        if live(item.capability) and item.in_edition(edition):
            perms.update(item.permissions)
    return perms


def _nav_items(src: str) -> list[NavItem]:
    consts = dict(re.findall(r"const ([A-Z_]+)\s*=\s*('[^']+'|\[[^\]]*\])", src))
    # Imported constants (INSTANCE_SETUP_PERMISSION lives in lib/onboarding-access.ts).
    for name, mod in re.findall(r"import \{ ([A-Z_]+)[^}]*\} from '@/lib/([\w-]+)'", src):
        lib = ROOT / "nanosiem-web" / "src" / "lib" / f"{mod}.ts"
        if lib.is_file():
            m = re.search(rf"export const {name}\s*=\s*('[^']+'|\[[^\]]*\])", lib.read_text(encoding="utf-8"))
            if m:
                consts[name] = m.group(1)
    out = []
    for name, href, rest in _NAV.findall(src):
        href = href if href.startswith("'") else consts.get(href, "")
        if not href.startswith("'/"):
            continue  # a const that is not a path literal: nothing to audit
        href = href.strip("'")
        pm = _NAV_PERMS.search(rest)
        raw = pm.group(1) if pm else ""
        if raw and raw[0].isupper():
            raw = consts.get(raw, "")
        cap = re.search(r"capability:\s*'([^']+)'", rest)
        out.append(NavItem(name, href, _quoted(raw), cap.group(1) if cap else None))
    return out


def nav_visible(item: NavItem, perms: set[str], capabilities: dict[str, bool], edition: str | None = None) -> bool:
    if item.capability and not capabilities.get(item.capability, False):
        return False
    if not item.in_edition(edition):
        return False
    return not item.permissions or holds(perms, None, item.permissions)


MIGRATIONS = ROOT / "migrations" / "postgres"
_SYSTEM_ROLE = re.compile(r"\(\s*'([0-9a-f-]{36})',\s*'([^']+)',\s*'[^']*',\s*TRUE\s*\)", re.I)


def builtin_roles() -> dict[str, str]:
    """{name: id} of every built-in (is_system) role the migrations seed."""
    out: dict[str, str] = {}
    for sql in sorted(MIGRATIONS.glob("*.sql")):
        text = sql.read_text(encoding="utf-8", errors="replace")
        for block in re.findall(r"INSERT INTO roles\s*\([^)]*is_system\)\s*VALUES(.*?);", text, re.S | re.I):
            for rid, name in _SYSTEM_ROLE.findall(block):
                out.setdefault(name, rid)
    return out
