"""NAN-5832: the OTLP sender collector runs as the harness user, who owns
the 0600 config it mounts. It ran as `--user 0:0 --cap-drop ALL`, and root
without CAP_DAC_OVERRIDE cannot read a 0600 file another uid owns on a native
Linux bind mount: the collector exited with "permission denied" on the e2e VM."""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from nano_e2e import otlp


def test_collector_runs_as_the_owner_of_its_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    seen: dict[str, Any] = {}

    def fake_run(argv: list[str], **_kw: Any) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        if argv[:2] == ["docker", "run"]:
            st = sender.config.stat()
            seen["mode"], seen["uid"], seen["gid"] = stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid
            return subprocess.CompletedProcess(argv, 1, "", "stop here")
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(otlp.subprocess, "run", fake_run)
    stack = SimpleNamespace(project="nanoe2e-selftest", ingest_url="http://127.0.0.1:1234")
    sender = otlp.CollectorSender(stack, "tok", tmp_path / "sender", "label")  # type: ignore[arg-type]
    with pytest.raises(RuntimeError, match="Collector did not start"):
        sender.__enter__()

    run = next(c for c in calls if c[:2] == ["docker", "run"])
    user = run[run.index("--user") + 1]
    assert user == f"{os.getuid()}:{os.getgid()}", user
    assert user == f"{seen['uid']}:{seen['gid']}", "the collector user must own the config it reads"
    assert seen["mode"] == 0o600, oct(seen["mode"])  # it holds the ingest token
    assert "ALL" in run and "--read-only" in run  # the hardening stays
