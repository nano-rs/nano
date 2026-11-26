"""The e2e web bundle cache key and the Sentry release are real on a source
tree with no `.git` (NAN-5884).

v2.0.35 RC3: the RC tree was unpacked from an archive, the git-only key hashed
empty input (`e3b0c442...`), and the UI lanes reused the RC2 bundle against the
RC3 backend. Here the key must come from the web sources themselves, change
when they change, ignore node_modules, and never be the empty-input hash; the
Sentry release must never be "unknown"."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts/e2e.sh"
EMPTY = hashlib.sha256(b"").hexdigest()[:16]


def _bash(script: str, env: dict[str, str] | None = None) -> str:
    base = {k: v for k, v in os.environ.items() if k not in ("E2E_SENTRY_RELEASE", "_E2E_SENTRY_TREE_RELEASE")}
    done = subprocess.run(
        ["bash", "-c", f'set -euo pipefail; source "{RUNNER}"; {script}'],
        capture_output=True, text=True, env={**base, **(env or {})}, timeout=60,
    )
    assert done.returncode == 0, done.stderr
    return done.stdout.strip()


def _tree(root: Path) -> Path:
    web = root / "nanosiem-web"
    (web / "src").mkdir(parents=True)
    (web / "node_modules/pkg").mkdir(parents=True)
    (web / "package.json").write_text('{"name": "nanosiem-web"}\n')
    (web / "src/main.tsx").write_text("export const a = 1;\n")
    (web / "node_modules/pkg/index.js").write_text("module.exports = 1;\n")
    return web


def test_a_tree_without_git_is_keyed_by_its_web_sources(tmp_path: Path) -> None:
    web = _tree(tmp_path)
    source, key = _bash(f'web_source_key "{tmp_path}"').split()
    assert source == "tree"
    assert len(key) == 16 and key != EMPTY
    assert _bash(f'web_source_key "{tmp_path}"') == f"tree {key}", "stable for the same tree"

    (web / "node_modules/pkg/index.js").write_text("module.exports = 2;\n")
    assert _bash(f'web_source_key "{tmp_path}"') == f"tree {key}", "dependencies are not sources"

    (web / "src/main.tsx").write_text("export const a = 2;\n")
    changed = _bash(f'web_source_key "{tmp_path}"').split()[1]
    assert changed != key, "a changed source file must miss the cache"

    (web / "src/new.ts").write_text("export {};\n")
    assert _bash(f'web_source_key "{tmp_path}"').split()[1] not in (key, changed), "a new file too"


def test_a_tree_with_no_web_sources_has_no_key(tmp_path: Path) -> None:
    assert _bash(f'web_source_key "{tmp_path}" || echo none') == "none"
    assert _bash('printf %s "$EMPTY_INPUT_KEY"') == EMPTY


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
def test_a_git_checkout_keeps_the_git_key(tmp_path: Path) -> None:
    _tree(tmp_path)
    git = ["git", "-C", str(tmp_path), "-c", "user.email=e2e@example.invalid", "-c", "user.name=e2e"]
    subprocess.run([*git, "init", "-q"], check=True)
    (tmp_path / ".gitignore").write_text("node_modules/\n")
    subprocess.run([*git, "add", "-A"], check=True)
    subprocess.run([*git, "commit", "-qm", "init"], check=True)
    source, key = _bash(f'web_source_key "{tmp_path}"').split()
    assert source == "git" and key != EMPTY
    (tmp_path / "nanosiem-web/src/main.tsx").write_text("export const a = 3;\n")
    assert _bash(f'web_source_key "{tmp_path}"').split()[1] != key, "uncommitted changes count"


@pytest.mark.skipif(not (ROOT / "scripts/lib/e2e-sentry.sh").is_file(), reason="stripped from the open-core mirror")
def test_the_sentry_release_is_never_unknown(tmp_path: Path) -> None:
    assert _bash("sentry_release", {"E2E_SENTRY_RELEASE": "v2.0.36-rc1"}) == "v2.0.36-rc1"
    # A tree with no checkout: a hash of its sources.
    (tmp_path / "Cargo.lock").write_text("# lock\n")
    first = _bash(f'ROOT="{tmp_path}"; sentry_release')
    assert first.startswith("tree-") and len(first) == len("tree-") + 16, first
    (tmp_path / "Cargo.lock").write_text("# lock 2\n")
    assert _bash(f'ROOT="{tmp_path}"; sentry_release') != first
    empty = tmp_path / "empty"
    empty.mkdir()
    assert _bash(f'ROOT="{empty}"; sentry_release') == "tree-nosource"


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
def test_an_archive_inside_another_checkout_is_keyed_by_its_own_tree(tmp_path: Path) -> None:
    """Review P2-1: git walks up to an ancestor .git; an unpacked tree inside
    some other repository must still be keyed (and released) by its own
    sources, never by the ancestor's commit."""
    outer = tmp_path / "outer"
    _tree(outer)
    git = ["git", "-C", str(outer), "-c", "user.email=e2e@example.invalid", "-c", "user.name=e2e"]
    subprocess.run([*git, "init", "-q"], check=True)
    subprocess.run([*git, "add", "-A"], check=True)
    subprocess.run([*git, "commit", "-qm", "init"], check=True)
    inner = outer / "unpacked"
    _tree(inner)
    assert _bash(f'web_source_key "{inner}"').split()[0] == "tree"
    assert _bash(f'ROOT="{inner}"; sentry_release').startswith("tree-")
    assert _bash(f'web_source_key "{outer}"').split()[0] == "git"


def test_a_tree_whose_web_sources_are_not_regular_files_has_no_key(tmp_path: Path) -> None:
    """Review P1: no regular file to hash is "no key" on GNU and BSD xargs
    alike, never a hash of empty input."""
    web = tmp_path / "nanosiem-web"
    (web / "src").mkdir(parents=True)
    (tmp_path / "real.json").write_text("{}\n")
    (web / "package.json").symlink_to(tmp_path / "real.json")
    assert _bash(f'web_source_key "{tmp_path}" || echo none') == "none"
