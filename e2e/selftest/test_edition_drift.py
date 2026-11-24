"""NAN-5747: the open-edition lane must not hard-code enterprise expectations.

- the panel copy the edition scenarios assert still exists in the web source
  (the same check the release preflight runs);
- persona/role permission sets are narrowed to the build's catalog on open,
  and never quietly narrowed on enterprise;
- the RBAC matrix does not demand that an open build define the permissions
  of gates behind a capability that is off.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import httpx
import pytest

from nano_e2e import edition
from nano_e2e import rbac_matrix as rm
from nano_e2e.rbac import edition_permissions

OPEN_CATALOG = ["search:view", "search:execute", "lookup:create", "cases:view"]


class _Api:
    def __init__(self, catalog: list[str]) -> None:
        self.catalog = catalog

    def get(self, path: str) -> httpx.Response:
        assert path == "/api/permissions"
        body = {"permissions": [{"id": p} for p in self.catalog]}
        request = httpx.Request("GET", "http://x" + path)
        return httpx.Response(200, content=json.dumps(body).encode(), request=request)


def test_edition_markers_exist_in_the_web_source() -> None:
    assert edition.missing_markers() == []


def test_edition_marker_check_fails_on_drift(tmp_path: Path) -> None:
    missing = edition.missing_markers(tmp_path)
    assert len(missing) == len(edition.MARKERS)
    assert "LicensedFeatureUnavailable.tsx" in missing[0]


def test_edition_marker_check_covers_the_full_unlicensed_copy(tmp_path: Path) -> None:
    """The whole sentence the tests assert, not a tail of it: a change to
    "Open/core features," must fail the guard (JSX line wraps are ignored)."""
    rel = "components/LicensedFeatureUnavailable.tsx"
    src = (edition.WEB_SRC / rel).read_text(encoding="utf-8")
    assert "Open/core features," in src
    for other in {f for _, f in edition.MARKERS} - {rel}:
        target = tmp_path / other
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text((edition.WEB_SRC / other).read_text(encoding="utf-8"), encoding="utf-8")
    (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / rel).write_text(src, encoding="utf-8")
    assert edition.missing_markers(tmp_path) == []
    (tmp_path / rel).write_text(src.replace("Open/core features,", "Core features,"), encoding="utf-8")
    missing = edition.missing_markers(tmp_path)
    assert len(missing) == 1 and "Open/core features" in missing[0], missing


def test_edition_marker_cli_is_stdlib_only(root: Path) -> None:
    r = subprocess.run([sys.executable, "-I", str(root / "e2e" / "nano_e2e" / "edition.py")],
                       capture_output=True, text=True, timeout=60, check=False)
    assert r.returncode == 0, r.stderr
    assert r.stdout.startswith("ok ")


def test_open_narrows_to_the_catalog() -> None:
    wanted = ["hunts:view", "search:execute", "lookup:create"]
    assert edition_permissions(_Api(OPEN_CATALOG), wanted, "open") == ["search:execute", "lookup:create"]


def test_enterprise_never_drops_a_permission() -> None:
    with pytest.raises(AssertionError, match="hunts:view"):
        edition_permissions(_Api(OPEN_CATALOG), ["hunts:view", "search:view"], "enterprise")
    assert edition_permissions(_Api(OPEN_CATALOG), ["search:view"], "enterprise") == ["search:view"]


def test_gate_permissions_skip_capabilities_that_are_off() -> None:
    every = rm.all_gate_permissions()
    assert {"hunts:view", "soar:view", "settings:system"} <= every
    off = rm.all_gate_permissions({"hunts": False, "soar": False})
    assert "hunts:view" not in off and "soar:view" not in off
    assert "settings:system" in off
    on = rm.all_gate_permissions({"hunts": True, "soar": True})
    assert {"hunts:view", "soar:view"} <= on
