"""The realistic seed writes only to a throwaway stack this checkout's
`scripts/e2e.sh` created (NAN-5764). No flag turns the guard off.

Refused, before a single request: `--target existing` (field or env), the
UDM profile (env or the run's marker), a compose project that is not
`nanoe2e-<run id>`, a run dir outside `target/e2e/`, a missing marker or one
written by another checkout, Dan's dev ports (3000 / 5173), any `*.nano.rs`
host, a non-loopback host, and a stack whose containers lack the harness's
labels for this checkout. The CLI exits 2 on all of them, and the runner
rejects `--seed` with `--target existing`, an unknown profile, or
`zero_clicks`.
"""

from __future__ import annotations

import dataclasses
import subprocess
from pathlib import Path

import pytest
from fake_nano_api import FakeNano
from nano_e2e import realistic_seed as seed
from nano_e2e.stack import Stack
from test_realistic_seed_apply import RUN_ID, _labels, fake, stack  # noqa: F401 - fixtures


def _refused(target: Stack, match: str, labels=_labels) -> None:
    with pytest.raises(seed.UnsafeTarget, match=match):
        seed.check_target(target, labels=labels)


def test_the_harness_stack_passes(stack: Stack) -> None:  # noqa: F811
    assert seed.check_target(stack, labels=_labels).started > 0


@pytest.mark.parametrize(
    ("change", "match"),
    [
        ({"target": "existing"}, "target existing"),
        ({"project": "nanoch-dev"}, "compose project"),
        ({"project": "nanoe2e-someone-else"}, "compose project"),
        ({"api_url": "http://localhost:3000"}, "ephemeral e2e port"),
        ({"search_url": "http://127.0.0.1:3002"}, "ephemeral e2e port"),
        ({"api_url": "http://localhost:5173"}, "ephemeral e2e port"),
        ({"api_url": "https://path.nano.rs:443"}, "nano.rs host"),
        ({"hec_url": "https://ingest.path.nano.rs:52000"}, "nano.rs host"),
        ({"api_url": "http://10.0.0.5:52000"}, "not loopback"),
        ({"api_url": "http://203.0.113.9:52000"}, "not loopback"),
    ],
)
def test_a_foreign_stack_is_refused(stack: Stack, change: dict, match: str) -> None:  # noqa: F811
    _refused(dataclasses.replace(stack, **change), match)


def test_env_target_existing_and_udm_are_refused(stack: Stack, monkeypatch) -> None:  # noqa: F811
    monkeypatch.setenv("E2E_TARGET", "existing")
    _refused(stack, "target existing")
    monkeypatch.delenv("E2E_TARGET")
    monkeypatch.setenv("NANO_SCHEMA_PROFILE", "udm")
    _refused(stack, "OCSF only")


def test_the_run_dir_marker_is_required(stack: Stack, tmp_path: Path) -> None:  # noqa: F811
    marker = stack.run_dir / "compose.env"
    text = marker.read_text()
    marker.write_text(text.replace("NANO_SCHEMA_PROFILE=ocsf", "NANO_SCHEMA_PROFILE=udm"))
    _refused(stack, "brought up 'udm'")
    marker.write_text(text.replace(f"E2E_OWNER={seed.ROOT}", "E2E_OWNER=/Users/dan/Documents/git/nanosiem"))
    _refused(stack, "another checkout")
    marker.unlink()
    _refused(stack, "no harness marker")
    elsewhere = tmp_path / "elsewhere" / RUN_ID
    elsewhere.mkdir(parents=True)
    _refused(dataclasses.replace(stack, run_dir=elsewhere), "run dir")


def test_containers_must_carry_this_checkouts_labels(stack: Stack) -> None:  # noqa: F811
    _refused(stack, "lacks the harness label", labels=lambda c: {})
    _refused(
        stack,
        "another checkout",
        labels=lambda c: {
            "nano.e2e.project": f"nanoe2e-{RUN_ID}",
            "nano.e2e.owner": "/nonexistent/other-checkout",
        },
    )


def test_apply_refuses_before_any_request(stack: Stack, fake: FakeNano) -> None:  # noqa: F811
    with pytest.raises(seed.UnsafeTarget):
        seed.apply(dataclasses.replace(stack, api_url="http://localhost:3000"), labels=_labels)
    with pytest.raises(seed.UnsafeTarget):
        seed.apply(stack, labels=lambda c: {})
    assert not fake.calls, f"requests went out before the guard: {dict(fake.calls)}"


def test_the_cli_exits_2_on_a_foreign_stack(tmp_path: Path, monkeypatch, fake: FakeNano) -> None:  # noqa: F811
    env = tmp_path / "stack.env"
    run_dir = tmp_path / "dan-local"
    (run_dir / "artifacts").mkdir(parents=True)
    env.write_text(
        "\n".join(
            [
                "E2E_RUN_ID=dan-local",
                "E2E_PROJECT=nanoch",
                "NANOSIEM_API_URL=http://localhost:3000",
                "NANOSIEM_SEARCH_URL=http://localhost:3002",
                "NANOSIEM_JOBS_URL=http://localhost:3003",
                "NANOSIEM_EDGE_URL=http://localhost:5173",
                "NANOSIEM_HEC_URL=http://localhost:8088",
                "NANOSIEM_VECTOR_HTTP_URL=http://localhost:8080",
                "NANOSIEM_VECTOR_METRICS_URL=http://localhost:9598",
                "NANOSIEM_API_KEY=nano_ak_dans_real_key_0123456789",
                "NANO_ADMIN_EMAIL=admin@nano.local",
                "NANO_ADMIN_PASSWORD=not-a-real-password-0123",
                f"E2E_RUN_DIR={run_dir}",
                f"E2E_ARTIFACT_DIR={run_dir / 'artifacts'}",
                "E2E_RUNNER=/dev/null",
                f"E2E_VECTOR_DYNAMIC_DIR={run_dir}",
                "CLICKHOUSE_URL=http://localhost:8123",
            ]
        )
        + "\n"
    )
    for line in env.read_text().splitlines():  # stackenv.load exports these: restore them afterwards
        key, _, value = line.partition("=")
        monkeypatch.setenv(key, value)
    assert seed.main(["--stack-env", str(env)]) == 2
    assert not fake.calls


RUNNER = Path(__file__).resolve().parents[2] / "scripts" / "e2e.sh"


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["run", "ui", "--seed", "tiny"], "unknown --seed"),
        (["run", "ui", "--seed", "realistic", "--target", "existing"], "never with --target existing"),
        (["run", "zero_clicks", "--seed", "realistic"], "cannot run with zero_clicks"),
    ],
)
def test_the_runner_rejects_unsafe_seed_flags(args: list[str], message: str) -> None:
    out = subprocess.run(
        ["bash", str(RUNNER), *args], capture_output=True, text=True, timeout=60, check=False
    )  # noqa: S603,S607
    assert out.returncode != 0 and message in out.stderr, out.stderr[-500:]
