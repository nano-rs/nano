"""Load a Python file as a module by path (NAN-5947).

Use this instead of calling `importlib.util.module_from_spec` and
`exec_module` by hand. The module must be in `sys.modules` while its body
runs: `@dataclass` in a file with `from __future__ import annotations` looks
its own module up there, and on Python 3.12 (the e2e VM default) an
unregistered module fails with "'NoneType' object has no attribute
'__dict__'". Newer Pythons happen not to fail, so it passed on the Mac.
`selftest/test_modload.py` checks this and that nothing under e2e/ loads a
module any other way.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType


def load_module(name: str, path: Path) -> ModuleType:
    """Import `path` as module `name`, registered in `sys.modules`.

    Loading the same name twice returns the module already loaded, so test
    files that share a support module share its state, as a normal import
    would. A file that fails to import leaves nothing behind in
    `sys.modules`.
    """
    existing = sys.modules.get(name)
    if existing is not None:
        loaded_from = getattr(existing, "__file__", None)
        if loaded_from is None or Path(loaded_from).resolve() != Path(path).resolve():
            raise ImportError(f"module {name!r} is already loaded from {loaded_from!r}, not {path}")
        return existing
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path} as module {name!r}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module
