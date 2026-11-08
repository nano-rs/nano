"""Every crate that embeds SQLx migrations must track its source directory.

Adding a file to a directory is not represented in rustc's dep-info. Once a
crate has any explicit ``cargo:rerun-if-changed`` directive, Cargo will reuse a
stale ``sqlx::migrate!`` expansion unless the owning build script watches the
directory itself.
"""

from __future__ import annotations

import os
import re
from pathlib import Path


MIGRATE = re.compile(r'sqlx::migrate!\(\s*"(?P<path>\.\./migrations/[^"/]+)"\s*\)')


def owning_crate(source: Path, root: Path) -> Path:
    current = source.parent
    while current != root:
        if (current / "Cargo.toml").is_file():
            return current
        current = current.parent
    raise AssertionError(f"no owning Cargo crate for {source.relative_to(root)}")


def test_every_embedded_migration_directory_is_tracked(root: Path) -> None:
    expected: dict[Path, set[str]] = {}
    for directory, names, files in os.walk(root):
        names[:] = [
            name
            for name in names
            if name not in {".git", "node_modules", "target", "vendor"}
        ]
        for filename in files:
            if not filename.endswith(".rs"):
                continue
            source = Path(directory) / filename
            for match in MIGRATE.finditer(source.read_text()):
                expected.setdefault(owning_crate(source, root), set()).add(match.group("path"))

    assert expected, "repository scan found no sqlx::migrate! users"
    for crate, migration_dirs in expected.items():
        build_script = crate / "build.rs"
        assert build_script.is_file(), (
            f"{crate.relative_to(root)} embeds migrations but has no build.rs directory watch"
        )
        contents = build_script.read_text()
        for migration_dir in migration_dirs:
            directive = f"cargo:rerun-if-changed={migration_dir}"
            assert directive in contents, (
                f"{crate.relative_to(root)}/build.rs does not track {migration_dir}; "
                "an added migration would be omitted by an incremental build"
            )
