"""NAN-5829: the docker-app e2e stack runs the live tap relay nano-api points at.

The base template gives nano-api NANO_VECTOR_TAP_URL=http://vector:8687, and
the generated secrets give it a tap token, so the API reports live tap as
enabled. Without the vector-tap relay every tap answered 503 "Live tap relays
are unreachable" (test_pipeline_live_tap failed on v2.0.34 and v2.0.35 RC1).
No Docker needed: these read the compose files and the runner.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "docker-compose.opensource.yml"
OVERLAY = ROOT / "dev/e2e/compose.e2e.yml"
RUNNER = ROOT / "scripts/e2e.sh"


class _ComposeLoader(yaml.SafeLoader):
    """Safe loader that accepts compose's `!override` / `!reset` tags."""


def _tagged(loader: yaml.SafeLoader, _suffix: str, node: yaml.Node) -> Any:
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_scalar(node)


_ComposeLoader.add_multi_constructor("!", _tagged)


def _services(path: Path) -> dict[str, Any]:
    return yaml.load(path.read_text(), Loader=_ComposeLoader)["services"]  # noqa: S506 - SafeLoader subclass


def _docker_app_up() -> list[str]:
    """Services the runner starts with the docker app (after the migrator)."""
    m = re.search(r"dc up -d (vector [^>]*nano-api) >>", RUNNER.read_text())
    assert m, "the docker-app `dc up -d vector ... nano-api` line moved; update this test"
    return m.group(1).split()


def test_base_api_points_at_the_vector_tap_relay() -> None:
    base = _services(BASE)
    assert base["nano-api"]["environment"]["NANO_VECTOR_TAP_URL"] == "http://vector:8687"
    assert base["vector-tap"]["network_mode"] == "service:vector-netns"


def test_docker_app_starts_the_vector_tap_relay() -> None:
    assert "vector-tap" in _docker_app_up()


def test_overlay_isolates_the_vector_tap_relay() -> None:
    tap = _services(OVERLAY)["vector-tap"]
    # Per-run name and labels (the base's fixed nano-vector-tap would collide
    # across runs and escape `scripts/e2e.sh gc`), the app's image, and only
    # with the docker app (native mode never sets the tap URL).
    assert tap["container_name"] == "${E2E_PROJECT}-vector-tap"
    assert "nano.e2e.project" in tap["labels"]
    assert tap["profiles"] == ["docker-app"]
    assert tap["image"] == _services(OVERLAY)["nano-api"]["image"]


def test_every_started_base_service_has_a_per_run_container_name() -> None:
    base, overlay = _services(BASE), _services(OVERLAY)
    for svc in _docker_app_up():
        if "container_name" in base.get(svc, {}):
            name = overlay.get(svc, {}).get("container_name", "")
            assert name.startswith("${E2E_PROJECT}-"), (svc, name)
