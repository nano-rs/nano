"""NAN-5462: every test module under e2e/tests needs a unique basename.

The tree has no `__init__.py` packages and pytest runs in its default
`prepend` import mode, so two `test_x.py` files in different directories
both import as module `test_x`. Collecting both in one session (`run all`,
or `ui` together with `enterprise`) fails with "import file mismatch" and the
run executes zero scenarios."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

TESTS = Path(__file__).resolve().parents[1] / "tests"


def test_test_module_basenames_are_unique() -> None:
    seen: dict[str, list[str]] = defaultdict(list)
    for path in TESTS.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        if path.name.startswith("test_") or path.name.endswith("_test.py"):
            seen[path.name].append(str(path.relative_to(TESTS)))
    dupes = {name: paths for name, paths in seen.items() if len(paths) > 1}
    assert not dupes, f"duplicate e2e test module basenames: {dupes}"
