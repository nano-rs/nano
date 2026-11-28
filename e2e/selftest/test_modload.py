"""NAN-5947: modules loaded by path are registered in sys.modules first.

`support.py` (SOAR lab fixtures) uses `from __future__ import annotations`
with `@dataclass`. Loaded with `module_from_spec` + `exec_module` and no
`sys.modules` entry, it fails on Python 3.12 (the e2e VM default) and works
on newer Pythons, so it only broke on the VM. These checks pin the shared
loader's behavior, run it under every 3.11 / 3.12 interpreter on PATH, and
refuse a hand-rolled loader anywhere under e2e/.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from nano_e2e.modload import load_module

E2E = Path(__file__).resolve().parents[1]
DATACLASS_MODULE = textwrap.dedent(
    """
    from __future__ import annotations

    from dataclasses import dataclass, field


    @dataclass
    class Pack:
        name: str
        tags: list[str] = field(default_factory=list)


    PACK = Pack("okta")
    """
)


def _write(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "mod.py"
    path.write_text(body, encoding="utf-8")
    return path


def test_dataclass_module_loads_and_is_registered(tmp_path: Path) -> None:
    name = "nano_e2e_selftest_modload_ok"
    try:
        module = load_module(name, _write(tmp_path, DATACLASS_MODULE))
        assert module.PACK.name == "okta"
        assert sys.modules[name] is module
        assert load_module(name, tmp_path / "mod.py") is module
    finally:
        sys.modules.pop(name, None)


def test_same_name_from_another_file_is_refused(tmp_path: Path) -> None:
    name = "nano_e2e_selftest_modload_clash"
    try:
        load_module(name, _write(tmp_path, DATACLASS_MODULE))
        other = tmp_path / "other.py"
        other.write_text("X = 1\n", encoding="utf-8")
        with pytest.raises(ImportError, match="already loaded"):
            load_module(name, other)
    finally:
        sys.modules.pop(name, None)


def test_failed_import_leaves_nothing_registered(tmp_path: Path) -> None:
    name = "nano_e2e_selftest_modload_bad"
    with pytest.raises(RuntimeError, match="boom"):
        load_module(name, _write(tmp_path, "raise RuntimeError('boom')\n"))
    assert name not in sys.modules


def test_soar_support_loads() -> None:
    support = E2E / "tests" / "enterprise" / "soar" / "support.py"
    if not support.is_file():
        pytest.skip("enterprise e2e tree not present (open-core mirror)")
    name = "nano_e2e_soar_support"
    already = name in sys.modules
    try:
        module = load_module(name, support)
        assert callable(module.catalog_bundle)
    finally:
        if not already:
            sys.modules.pop(name, None)


def _old_interpreters() -> list[str]:
    found = []
    for candidate in ("python3.11", "python3.12"):
        path = shutil.which(candidate)
        if path:
            found.append(path)
    return found


@pytest.mark.parametrize("interpreter", _old_interpreters() or [None])
def test_loader_works_on_python_311_and_312(interpreter: str | None, tmp_path: Path) -> None:
    """The VM runs 3.12; run the loader there even when this venv is newer."""
    if interpreter is None:
        pytest.skip("no python3.11 or python3.12 on PATH (the venv's own version is covered above)")
    module = _write(tmp_path, DATACLASS_MODULE)
    script = textwrap.dedent(
        """
        import sys
        sys.path.insert(0, sys.argv[1])
        from nano_e2e.modload import load_module
        print(load_module("nano_e2e_selftest_modload_sub", sys.argv[2]).PACK.name)
        """
    )
    result = subprocess.run(
        [interpreter, "-I", "-c", script, str(E2E), str(module)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "okta"


def test_no_hand_rolled_module_loaders_under_e2e() -> None:
    """Every load-by-path goes through nano_e2e.modload.load_module."""
    allowed = {E2E / "nano_e2e" / "modload.py", Path(__file__).resolve()}
    offenders = []
    for path in E2E.rglob("*.py"):
        if ".venv" in path.parts or "__pycache__" in path.parts or path.resolve() in allowed:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if "module_from_spec" in text or "exec_module" in text:
            offenders.append(str(path.relative_to(E2E)))
    assert not offenders, f"load modules by path with nano_e2e.modload.load_module: {offenders}"
