"""Artifact secret guard (NAN-4937 review P1): rendered Vector source configs
are redacted structurally, every known secret is scrubbed from every artifact,
and anything left fails the run (exit 3). Also: the runner never copies the
rendered tree verbatim any more."""

from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path

from nano_e2e import artifact_guard as g

RUNNER = Path(__file__).resolve().parents[2] / "scripts" / "e2e.sh"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
AZ_SECRET = "Az~8Q~not-a-real-client-secret-0123456789"
SAS = "q1w2e3r4t5y6u7i8o9p0ASDFGHJKLzxcvbnm1234567="

RENDERED = f"""
[sources.e2e_sqs]
type = "aws_sqs"
queue_url = "https://sqs.us-east-1.amazonaws.com/123456789012/nano-e2e-q"
region = "us-east-1"

[sources.e2e_sqs.auth]
access_key_id = "AKIAIOSFODNN7EXAMPLE"
secret_access_key = "{AWS_SECRET}"

[sources.e2e_hub]
type = "azure_event_hubs"
connection_string = "Endpoint=sb://ns.servicebus.windows.net/;SharedAccessKeyName=nano;SharedAccessKey={SAS}"
client_secret = "{AZ_SECRET}"

[transforms.e2e_route]
type = "remap"
inputs = ["e2e_sqs"]
source = '.source_type = "e2e"'
"""


def test_rendered_toml_is_redacted_structurally(tmp_path: Path) -> None:
    src, dst = tmp_path / "sources", tmp_path / "out"
    (src / "configs").mkdir(parents=True)
    (src / "configs" / "e2e.toml").write_text(RENDERED)
    assert g.redact_rendered(src, dst) == 1
    out = (dst / "configs" / "e2e.toml").read_text()
    for secret in (AWS_SECRET, AZ_SECRET, SAS, "AKIAIOSFODNN7EXAMPLE"):
        assert secret not in out, secret
    # Routing stays readable for debugging.
    assert 'queue_url = "https://sqs.us-east-1.amazonaws.com/123456789012/nano-e2e-q"' in out
    assert 'inputs = ["e2e_sqs"]' in out and 'connection_string = "<redacted>"' in out
    # A connection string under a non-sensitive key still loses its key part.
    assert "SharedAccessKey=<redacted>" in g.redact_toml_text(f'endpoint = "Endpoint=sb://x/;SharedAccessKey={SAS}"\n')


def test_registry_scrub_and_fail_on_leftover(tmp_path: Path) -> None:
    run = tmp_path / "run"
    (run / "artifacts" / "scenarios").mkdir(parents=True)
    os.chmod(run, 0o700)
    token = "nit_" + "a1b2c3d4" * 4
    sa_json = json.dumps({"type": "service_account", "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQ\n-----END"})
    g.remember(token, sa_json, AWS_SECRET, run_dir=run)
    reg = run / g.REGISTRY
    assert stat.S_IMODE(reg.stat().st_mode) == 0o600
    a = run / "artifacts"
    (a / "scenarios" / "api.jsonl").write_text(json.dumps({"token": token, "key": AWS_SECRET}))
    (a / "scenarios" / "cfg.toml").write_text('private_key = "-----BEGIN PRIVATE KEY-----\\nMIIEvQ\\n-----END"\n')
    (a / "compose.log").write_text(f"POSTGRES_PASSWORD=pg-{'x' * 20}\n")
    env = run / "compose.env"
    env.write_text(f"POSTGRES_PASSWORD=pg-{'x' * 20}\nE2E_PROJECT=nanoe2e-x\n")
    secrets = g.load(reg, [env])
    assert g.scrub(a, secrets) == []
    blob = b"".join(f.read_bytes() for f in a.rglob("*") if f.is_file())
    for s in (token, AWS_SECRET, "pg-" + "x" * 20, "MIIEvQ"):
        assert s.encode() not in blob, s
    # A secret inside a binary artifact cannot be scrubbed: the guard reports it.
    (a / "trace.bin").write_bytes(b"\x00\xff" + token.encode() + b"\x00")
    assert g.scrub(a, secrets) == ["trace.bin"]
    r = subprocess.run(
        ["python3", "-m", "nano_e2e.artifact_guard", "scrub", str(a), "--run-dir", str(run), "--env-file", str(env)],
        cwd=RUNNER.parents[1] / "e2e",
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == 3 and "trace.bin" in r.stderr


def test_runner_never_copies_rendered_config_verbatim() -> None:
    body = RUNNER.read_text().split("collect_artifacts() {", 1)[1].split("\n}\n", 1)[0]
    assert 'cp -R "$RUN_DIR/vector-dynamic/sources"' not in body
    assert "guard redact-rendered" in body and "scrub_artifacts" in body
    run_body = RUNNER.read_text().split("cmd_run() {", 1)[1]
    assert "crc == 3" in run_body, "a leftover secret must fail the run"
