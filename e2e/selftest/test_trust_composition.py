"""NAN-5771: a bare `up` builds the release trust config, and every path that
starts or reuses the app proves the trust it runs with.

The non-shippable test-key composition (`--cfg nano_content_acceptance` +
NANO_NON_RELEASE_BUILD=1) must be an explicit opt-in. A bare
`scripts/e2e.sh up` once built it silently (no suite reads as "every suite",
which includes soar), and a manual fresh-install check then trusted test keys
(the NAN-5768 false alarm). These tests source the real runner with real
arguments; the build tests drive `native_build` with a fake cargo that emits
fake binaries answering `--print-content-trust` like the real ones.
"""

from __future__ import annotations

import http.server
import json
import os
import subprocess
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts/e2e.sh"
PROD = "production"
TEST = "production+acceptance"
NATIVE_ENT = ["--app", "native", "--edition", "enterprise"]

pytestmark = pytest.mark.skipif(
    not (ROOT / "nanosiem-enterprise").is_dir() or not (ROOT / "e2e/tests/enterprise/soar").is_dir(),
    reason="needs the enterprise tree (the open-core mirror has no test-trust composition)",
)

# Build env a developer shell may carry; every test starts without it.
_BUILD_ENV = ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS", "NANO_NON_RELEASE_BUILD")


def _env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in _BUILD_ENV and not k.startswith("CARGO_TARGET_")}
    env["E2E_EDITION"] = ""
    env.update(extra or {})
    return env


def _source(args: list[str], script: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    quoted = " ".join(f"'{a}'" for a in args)
    return subprocess.run(
        ["bash", "-c", f'set -euo pipefail; source "{RUNNER}" {quoted}; {script}'],
        env=_env(env),
        capture_output=True,
        text=True,
        timeout=90,
        check=False,
    )


def _trust(args: list[str]) -> str:
    r = _source(args, "expected_trust")
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


# ------------------------------------------------------------ composition


@pytest.mark.parametrize(
    "args",
    [
        ["up", *NATIVE_ENT],
        ["up", "--app", "native"],
        ["up", *NATIVE_ENT, "--profile", "ai-stub"],
        ["up", *NATIVE_ENT, "--profile", "recon-fast"],
        # legacy `all` names lanes, not suites: no test trust.
        ["legacy", "all", *NATIVE_ENT],
        # A run whose suites do not include soar / content_acceptance.
        ["run", "zero_clicks", *NATIVE_ENT],
        ["run", "ui", "personas", *NATIVE_ENT],
        ["run", "base", *NATIVE_ENT],
        # Docker / image modes always build release-like images.
        ["run", "content_acceptance", "--app", "docker", "--edition", "enterprise"],
    ],
)
def test_defaults_build_production_trust(args: list[str]) -> None:
    assert _trust(args) == PROD


@pytest.mark.parametrize(
    "args",
    [
        ["up", *NATIVE_ENT, "--acceptance-trust"],
        ["up", *NATIVE_ENT, "--profile", "soar-lab"],
        ["run", "soar", *NATIVE_ENT],
        ["run", "all", *NATIVE_ENT],
        ["run", *NATIVE_ENT],
        ["run", "content_acceptance", *NATIVE_ENT],
    ],
)
def test_explicit_opt_ins_build_test_trust(args: list[str]) -> None:
    assert _trust(args) == TEST


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        (["up", "--acceptance-trust", "--app", "docker", "--edition", "enterprise"], "needs --app native"),
        (["up", "--acceptance-trust", "--app", "image:v1", "--edition", "enterprise"], "needs --app native"),
        (["up", "--acceptance-trust", "--app", "native", "--edition", "open"], "needs --edition enterprise"),
        (["up", "--profile", "soar-lab", "--app", "docker", "--edition", "enterprise"], "needs --app native"),
        (["up", "--profile", "soar-lab", "--app", "native", "--edition", "open"], "needs --edition enterprise"),
        (["run", "content_acceptance", "--app", "docker", "--edition", "enterprise"], "needs --app native"),
        (["run", "content_acceptance", "--app", "native", "--edition", "open"], "needs --edition enterprise"),
        (["up", "--acceptance-trust", *NATIVE_ENT, "--release"], "debug-only"),
        (["up", "--profile", "soar-lab", *NATIVE_ENT, "--release"], "debug-only"),
    ],
)
def test_unhonourable_test_trust_request_is_refused(args: list[str], expected: str) -> None:
    r = _source(args, "check_trust_request")
    assert r.returncode != 0
    assert expected in r.stderr


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        (["run", "base", "--acceptance-trust", "--app", "docker", "--edition", "enterprise"], "needs --app native"),
        (["run", "base", "--acceptance-trust", "--app", "native", "--edition", "open"], "needs --edition enterprise"),
        (["run", "base", "--acceptance-trust", *NATIVE_ENT, "--release"], "debug-only"),
    ],
)
def test_cmd_run_refuses_unhonourable_test_trust(args: list[str], expected: str) -> None:
    """cmd_run checks the request itself (it may reuse a stack, never calling up)."""
    r = subprocess.run(
        ["bash", str(RUNNER), *args], env=_env(), capture_output=True, text=True, timeout=60, check=False
    )
    assert r.returncode != 0
    assert expected in r.stderr


@pytest.mark.parametrize(
    "extra",
    [["--acceptance-trust"], ["--profile", "soar-lab"], ["content_acceptance"]],
)
def test_existing_target_refuses_test_trust(extra: list[str], tmp_path: Path) -> None:
    """--target existing neither builds nor checks the stack: a test-trust
    request is refused before anything (even the credentials file) is read."""
    r = subprocess.run(
        ["bash", str(RUNNER), "run", "ui", *extra, "--target", "existing"],
        env=_env({"E2E_TARGET_CREDS_FILE": str(tmp_path / "absent")}),
        capture_output=True, text=True, timeout=60, check=False,
    )
    assert r.returncode != 0
    assert "never --target existing" in r.stderr


def test_banner_labels_test_builds_loudly() -> None:
    prod = _source(["up"], f"trust_banner {PROD}")
    test = _source(["up"], f"trust_banner {TEST}")
    assert prod.returncode == 0 and test.returncode == 0
    assert "TEST" not in prod.stderr and "trust: production" in prod.stderr
    assert "TEST BUILD" in test.stderr and "nano_content_acceptance" in test.stderr


# ------------------------------------------------------------ fake run dir


def _write_bin(path: Path, label: str | None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = f'echo "{label}"' if label is not None else "exit 3"
    path.write_text(f'#!/usr/bin/env bash\n[[ "${{1:-}}" == --print-content-trust ]] || exit 9\n{body}\n')
    path.chmod(0o755)


def _run_dir(tmp_path: Path, trust: str | None, **extra: str) -> Path:
    run_dir = tmp_path / "run"
    for d in ("artifacts", "pids"):
        (run_dir / d).mkdir(parents=True, exist_ok=True)
    lines = ["E2E_PROFILE_DIR=debug", f"E2E_APP_MODE={extra.pop('mode', 'native')}"]
    if trust is not None:
        lines.append(f"E2E_TRUST={trust}")
    lines += [f"{k}={v}" for k, v in extra.items()]
    (run_dir / "run.env").write_text("\n".join(lines) + "\n")
    return run_dir


# ------------------------------------------------------------ build env


def _fake_cargo(tmp_path: Path) -> Path:
    """A cargo that records its env and emits api/jobs binaries whose trust
    follows the cfg it was invoked with, as the real build would."""
    cargo = tmp_path / "bin" / "cargo"
    cargo.parent.mkdir()
    target = tmp_path / "target"
    cargo.write_text(
        "#!/usr/bin/env bash\n"
        'printf "RUSTFLAGS=%s\\nNANO_NON_RELEASE_BUILD=%s\\nARGS=%s\\n" '
        '"${RUSTFLAGS:-}" "${NANO_NON_RELEASE_BUILD:-}" "$*"\n'
        "label=production\n"
        'case "${RUSTFLAGS:-}" in *nano_content_acceptance*) label=production+acceptance ;; esac\n'
        f'mkdir -p "{target}/debug"\n'
        "for b in nanosiem-api nanosiem-jobs; do\n"
        f'  printf "#!/usr/bin/env bash\\necho %s\\n" "$label" > "{target}/debug/$b"; chmod +x "{target}/debug/$b"\n'
        "done\n"
    )
    cargo.chmod(0o755)
    return cargo


def _fake_build(
    tmp_path: Path, args: list[str], inherited: dict[str, str] | None = None
) -> tuple[subprocess.CompletedProcess[str], str]:
    cargo = _fake_cargo(tmp_path)
    r_args = [a for a in args]
    want = TEST if "--acceptance-trust" in r_args else PROD
    run_dir = _run_dir(tmp_path, want, E2E_PROFILES="")
    r = _source(
        args,
        f'RUN_DIR="{run_dir}"; RUN_ID=t; native_build',
        env={"E2E_CARGO": str(cargo), "CARGO_TARGET_DIR": str(tmp_path / "target"), **(inherited or {})},
    )
    log = run_dir / "artifacts/build.log"
    return r, log.read_text() if log.exists() else ""


def test_bare_up_build_has_no_test_cfg(tmp_path: Path) -> None:
    r, log = _fake_build(tmp_path, ["up", *NATIVE_ENT])
    assert r.returncode == 0, r.stderr
    assert "nano_content_acceptance" not in log
    assert "NANO_NON_RELEASE_BUILD=\n" in log
    assert "--features enterprise" in log


def test_acceptance_trust_build_has_test_cfg(tmp_path: Path) -> None:
    r, log = _fake_build(tmp_path, ["up", *NATIVE_ENT, "--acceptance-trust"])
    assert r.returncode == 0, r.stderr
    assert "--cfg nano_content_acceptance" in log
    assert "NANO_NON_RELEASE_BUILD=1" in log


@pytest.mark.parametrize("var", ["RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS",
                                 "CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS"])
def test_bare_up_refuses_inherited_test_cfg(tmp_path: Path, var: str) -> None:
    r, log = _fake_build(tmp_path, ["up", *NATIVE_ENT], {var: "--cfg nano_content_acceptance"})
    assert r.returncode != 0
    assert f"{var} carries nano_content_acceptance" in r.stderr
    assert log == ""  # refused before cargo ran


def test_bare_up_strips_inherited_non_release_marker(tmp_path: Path) -> None:
    r, log = _fake_build(tmp_path, ["up", *NATIVE_ENT], {"NANO_NON_RELEASE_BUILD": "1"})
    assert r.returncode == 0, r.stderr
    assert "NANO_NON_RELEASE_BUILD=\n" in log


@pytest.mark.parametrize("value", ["-Copt-level=1", ""])
def test_test_build_refuses_encoded_rustflags(tmp_path: Path, value: str) -> None:
    """Cargo prefers CARGO_ENCODED_RUSTFLAGS over RUSTFLAGS (it tests presence,
    so even an empty value) and would drop the cfg."""
    r, log = _fake_build(tmp_path, ["up", *NATIVE_ENT, "--acceptance-trust"], {"CARGO_ENCODED_RUSTFLAGS": value})
    assert r.returncode != 0
    assert "CARGO_ENCODED_RUSTFLAGS is set" in r.stderr
    assert log == ""  # refused before cargo ran


def test_production_build_accepts_empty_encoded_rustflags(tmp_path: Path) -> None:
    r, _ = _fake_build(tmp_path, ["up", *NATIVE_ENT], {"CARGO_ENCODED_RUSTFLAGS": ""})
    assert r.returncode == 0, r.stderr


def test_build_asserts_the_binaries_trust(tmp_path: Path) -> None:
    """A build whose binaries report the other trust (e.g. injected by
    .cargo/config) fails after cargo, whatever the flags looked like."""
    cargo = tmp_path / "bin" / "cargo"
    cargo.parent.mkdir()
    target = tmp_path / "target"
    cargo.write_text(
        f'#!/usr/bin/env bash\nmkdir -p "{target}/debug"\n'
        f'for b in nanosiem-api nanosiem-jobs; do printf "#!/usr/bin/env bash\\necho production+acceptance\\n" '
        f'> "{target}/debug/$b"; chmod +x "{target}/debug/$b"; done\n'
    )
    cargo.chmod(0o755)
    run_dir = _run_dir(tmp_path, PROD, E2E_PROFILES="")
    r = _source(["up", *NATIVE_ENT], f'RUN_DIR="{run_dir}"; RUN_ID=t; native_build',
                env={"E2E_CARGO": str(cargo), "CARGO_TARGET_DIR": str(target)})
    assert r.returncode != 0
    assert "nanosiem-api trust mismatch" in r.stderr


# ------------------------------------------------------------ binary trust


@pytest.mark.parametrize(
    ("recorded", "api", "jobs", "error"),
    [
        (PROD, PROD, PROD, None),
        (TEST, TEST, TEST, None),
        (PROD, PROD, TEST, "nanosiem-jobs trust mismatch"),
        (TEST, TEST, PROD, "nanosiem-jobs trust mismatch"),
        (PROD, TEST, PROD, "nanosiem-api trust mismatch"),
        (PROD, PROD, None, "nanosiem-jobs did not report its trust"),
        (None, PROD, PROD, "records no E2E_TRUST"),
    ],
)
def test_verify_binary_trust(tmp_path: Path, recorded: str | None, api: str | None, jobs: str | None,
                             error: str | None) -> None:
    target = tmp_path / "target"
    _write_bin(target / "debug/nanosiem-api", api)
    _write_bin(target / "debug/nanosiem-jobs", jobs)
    run_dir = _run_dir(tmp_path, recorded)
    r = _source(["up"], f'RUN_DIR="{run_dir}"; RUN_ID=t; verify_binary_trust api; verify_binary_trust jobs',
                env={"CARGO_TARGET_DIR": str(target)})
    if error is None:
        assert r.returncode == 0, r.stderr
    else:
        assert r.returncode != 0
        assert error in r.stderr


@pytest.mark.parametrize("svc", ["api", "jobs"])
def test_native_start_refuses_a_stale_binary(tmp_path: Path, svc: str) -> None:
    """Every start (up, run reuse, svc restart) goes through native_start."""
    target = tmp_path / "target"
    _write_bin(target / f"debug/nanosiem-{svc}", TEST)
    run_dir = _run_dir(tmp_path, PROD)
    r = _source(["up"], f'RUN_DIR="{run_dir}"; RUN_ID=t; native_start {svc}', env={"CARGO_TARGET_DIR": str(target)})
    assert r.returncode != 0
    assert f"nanosiem-{svc} trust mismatch" in r.stderr
    assert not (run_dir / f"pids/{svc}.pid").exists()


# ------------------------------------------------------------ reuse


@pytest.mark.parametrize(
    ("args", "recorded", "profiles", "error"),
    [
        (["run", "base", *NATIVE_ENT], PROD, "", None),
        (["run", "base", *NATIVE_ENT], TEST, "soar-lab", None),
        (["run", "base", *NATIVE_ENT, "--acceptance-trust"], PROD, "", "test trust was requested"),
        (["run", "ui", *NATIVE_ENT, "--profile", "soar-lab"], PROD, "", "test trust was requested"),
        (["run", "ui", *NATIVE_ENT, "--profile", "soar-lab"], TEST, "", "no soar-lab profile"),
        (["run", "soar", *NATIVE_ENT], PROD, "soar-lab ai-stub", "test trust was requested"),
        (["run", "base", *NATIVE_ENT], None, "", "records no E2E_TRUST"),
    ],
)
def test_check_reuse_trust(tmp_path: Path, args: list[str], recorded: str | None, profiles: str,
                           error: str | None) -> None:
    run_dir = _run_dir(tmp_path, recorded, E2E_PROFILES=profiles)
    r = _source(args, f'RUN_DIR="{run_dir}"; RUN_ID=t; check_reuse_trust')
    if error is None:
        assert r.returncode == 0, r.stderr
    else:
        assert r.returncode != 0
        assert error in r.stderr


@pytest.mark.parametrize(
    ("recorded", "api_file", "jobs_file", "error"),
    [
        (PROD, PROD, PROD, None),
        (TEST, TEST, TEST, None),
        (PROD, PROD, None, "running nanosiem-jobs of run t was not started for trust 'production'"),
        (PROD, TEST, PROD, "running nanosiem-api of run t was not started for trust 'production'"),
        (TEST, TEST, PROD, "running nanosiem-jobs of run t was not started for trust 'production+acceptance'"),
    ],
)
def test_check_reuse_trust_running_processes(tmp_path: Path, recorded: str, api_file: str | None,
                                             jobs_file: str | None, error: str | None) -> None:
    """The running api/jobs must have been started (and checked) for the run's
    trust: pids/<svc>.trust is what native_start recorded for them."""
    run_dir = _run_dir(tmp_path, recorded, E2E_PROFILES="soar-lab" if recorded == TEST else "")
    for svc, value in (("api", api_file), ("jobs", jobs_file)):
        if value is not None:
            (run_dir / f"pids/{svc}.trust").write_text(value + "\n")
    # Both services "running": pid identity is covered by test_runner_safety.
    r = _source(["run", "base", *NATIVE_ENT],
                f'RUN_DIR="{run_dir}"; RUN_ID=t; pid_alive() {{ return 0; }}; check_reuse_trust')
    if error is None:
        assert r.returncode == 0, r.stderr
    else:
        assert r.returncode != 0
        assert error in r.stderr


def test_check_reuse_trust_skips_stopped_processes(tmp_path: Path) -> None:
    run_dir = _run_dir(tmp_path, PROD)  # no trust files: nothing is running
    r = _source(["run", "base", *NATIVE_ENT], f'RUN_DIR="{run_dir}"; RUN_ID=t; pid_alive() {{ return 1; }}; check_reuse_trust')
    assert r.returncode == 0, r.stderr


def test_reuse_path_runs_the_checks() -> None:
    runner = RUNNER.read_text()
    reuse = runner[runner.index("        resolve_run\n        if content_acceptance_selected"):]
    reuse = reuse[: reuse.index("    venv_ensure\n")]
    assert "check_reuse_trust" in reuse and "verify_stack_trust" in reuse
    assert 'if [[ "$svc" == api ]]; then verify_stack_trust; fi' in runner


# ------------------------------------------------------------ API trust


class _Api:
    def __init__(self) -> None:
        self.status = 200
        self.body: object = {"trust": PROD, "channels": []}
        api = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                if self.path != "/api/content/channels" or self.headers.get("X-API-Key") != "k":
                    self.send_response(401)
                    self.end_headers()
                    return
                data = api.body if isinstance(api.body, bytes) else json.dumps(api.body).encode()
                self.send_response(api.status)
                self.send_header("content-type", "application/json")
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *a: object) -> None:
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()


@pytest.fixture
def api() -> Iterator[_Api]:
    a = _Api()
    yield a
    a.server.shutdown()


# (recorded, app mode, HTTP status, body, error substring or None, warns)
API_CASES = [
    (PROD, "native", 200, {"trust": PROD}, None),
    (TEST, "native", 200, {"trust": TEST}, None),
    (PROD, "native", 200, {"trust": TEST}, "mismatch"),
    (TEST, "native", 200, {"trust": PROD}, "mismatch"),
    (PROD, "native", 500, {"error": "boom"}, "HTTP 500"),
    (PROD, "docker", 500, {"error": "boom"}, "HTTP 500"),
    (PROD, "native", 401, {}, "HTTP 401"),
    (PROD, "native", 404, {}, "HTTP 404"),
    (PROD, "native", 200, {"channels": []}, "no trust field"),
    (PROD, "native", 200, b"not json", "not JSON"),
    (PROD, "native", 200, [], "not a JSON object"),
    (PROD, "native", 200, None, "not a JSON object"),
    # A published image: only 404 (the image predates the endpoint) is tolerated.
    (PROD, "image", 404, {}, None),
    (PROD, "image", 500, {"error": "boom"}, "HTTP 500"),
    (PROD, "image", 403, {}, "HTTP 403"),
    (PROD, "image", 200, b"not json", "not JSON"),
    (PROD, "image", 200, {"trust": TEST}, "mismatch"),
]


@pytest.mark.parametrize(("recorded", "mode", "status", "body", "error"), API_CASES)
def test_verify_stack_trust_fails_closed(tmp_path: Path, api: _Api, recorded: str, mode: str, status: int,
                                         body: object, error: str | None) -> None:
    api.status, api.body = status, body
    run_dir = _run_dir(tmp_path, recorded, mode=mode, E2E_API_PORT=str(api.port))
    (run_dir / "admin.env").write_text("NANOSIEM_API_KEY=k\n")
    r = _source(["up"], f'RUN_DIR="{run_dir}"; RUN_ID=t; verify_stack_trust', env={"E2E_TRUST_PROBE_ATTEMPTS": "1"})
    if error is None:
        assert r.returncode == 0, r.stderr
        if status == 404:
            assert "predates" in r.stderr  # a visible warning, never silent
        else:
            assert "trust verified via API" in r.stderr
    else:
        assert r.returncode != 0
        assert error in r.stderr


def test_verify_stack_trust_network_error_fails_closed(tmp_path: Path, api: _Api) -> None:
    port = api.port
    api.server.shutdown()
    api.server.server_close()
    for mode in ("native", "image"):
        run_dir = _run_dir(tmp_path / mode, PROD, mode=mode, E2E_API_PORT=str(port))
        (run_dir / "admin.env").write_text("NANOSIEM_API_KEY=k\n")
        r = _source(["up"], f'RUN_DIR="{run_dir}"; RUN_ID=t; verify_stack_trust', env={"E2E_TRUST_PROBE_ATTEMPTS": "1"})
        assert r.returncode != 0, mode
        assert "trust not verified" in r.stderr, mode


def test_verify_stack_trust_without_admin_key_defers(tmp_path: Path) -> None:
    run_dir = _run_dir(tmp_path, PROD)
    r = _source(["up"], f'RUN_DIR="{run_dir}"; RUN_ID=t; verify_stack_trust')
    assert r.returncode == 0, r.stderr
    assert "deferred to first-run setup" in r.stderr


@pytest.mark.parametrize(("recorded", "mode", "status", "body", "error"),
                         [*API_CASES, ("", "native", 200, {"trust": PROD}, "no E2E_TRUST")])
def test_firstrun_checks_trust_after_minting_the_key(monkeypatch: pytest.MonkeyPatch, api: _Api, recorded: str,
                                                     mode: str, status: int, body: object, error: str | None) -> None:
    """firstrun runs the SAME decision as the runner (nano_e2e.trust)."""
    from nano_e2e import firstrun

    api.status, api.body = status, body
    monkeypatch.setenv("E2E_TRUST", recorded)
    monkeypatch.setenv("E2E_APP_MODE", mode)
    monkeypatch.setenv("E2E_TRUST_PROBE_ATTEMPTS", "1")
    url = f"http://127.0.0.1:{api.port}"
    if error is None:
        if status == 404:
            with pytest.warns(UserWarning, match="predates"):
                assert firstrun.check_stack_trust(url, "k") == ""
        else:
            assert firstrun.check_stack_trust(url, "k") == recorded
    else:
        with pytest.raises(firstrun.TrustMismatch, match=error):
            firstrun.check_stack_trust(url, "k")


def test_auth_failure_is_not_retried(api: _Api) -> None:
    from nano_e2e import trust

    api.status = 401
    with pytest.raises(trust.TrustMismatch, match="HTTP 401"):
        trust.check(f"http://127.0.0.1:{api.port}", "k", PROD, "native", attempts=5, delay=30)


def test_runner_and_firstrun_share_one_decision() -> None:
    runner = RUNNER.read_text()
    src = (ROOT / "e2e/nano_e2e/firstrun.py").read_text()
    assert "python3 -m nano_e2e.trust" in runner
    assert "trust.check(" in src
    assert "httpx.get" not in src[src.index("def check_stack_trust"):src.index("def ensure_admin")]


def test_firstrun_calls_the_check() -> None:
    src = (ROOT / "e2e/nano_e2e/firstrun.py").read_text()
    body = src[src.index("def ensure_admin"):]
    assert "check_stack_trust(api, key)" in body


def test_trust_recorded_in_run_and_stack_metadata() -> None:
    runner = RUNNER.read_text()
    assert 'put E2E_TRUST "$(expected_trust)"' in runner
    assert 'put E2E_TRUST "$(env_get "$r" E2E_TRUST)"' in runner


def test_binaries_answer_print_content_trust() -> None:
    contract = (ROOT / "nanosiem-core/src/content_bundle/contract.rs").read_text()
    assert 'PRINT_TRUST_ARGUMENT: &str = "--print-content-trust"' in contract
    for main in ("nanosiem-api/src/main.rs", "nanosiem-api/src/bin/jobs.rs"):
        assert "contract::PRINT_TRUST_ARGUMENT" in (ROOT / main).read_text(), main
