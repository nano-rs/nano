"""The UI driver reaps its entire Puppeteer Chrome tree on interruption."""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
from pathlib import Path

import pytest


def _browser_pids() -> set[int]:
    output = subprocess.check_output(["ps", "-axo", "pid=,command="], text=True)
    return {
        int(line.split(None, 1)[0])
        for line in output.splitlines()
        if "puppeteer_dev_chrome_profile-" in line
    }


def _has_chrome() -> bool:
    candidates = [
        os.environ.get("CHROME_PATH", ""),
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        "/usr/bin/google-chrome",
        "/usr/bin/chromium",
    ]
    return bool(shutil.which("node")) and any(path and Path(path).is_file() for path in candidates)


def test_sigterm_reaps_puppeteer_process_group(tmp_path: Path) -> None:
    from nano_e2e import ui

    if not _has_chrome() or not (ui.WEB / "node_modules" / "puppeteer-core").is_dir():
        pytest.skip("needs node, puppeteer-core, and a local Chrome")

    before = _browser_pids()
    driver = ui.Driver("http://127.0.0.1:1", tmp_path / "driver.log")
    try:
        ui.UiPage.open(driver, tmp_path / "ui", "interrupt cleanup")
        assert _browser_pids() - before, "Puppeteer did not start a Chrome process"
        driver._proc.send_signal(signal.SIGTERM)  # noqa: SLF001 - exercise the driver signal boundary
        driver._proc.wait(timeout=15)  # noqa: SLF001
    finally:
        driver.close()

    deadline = time.monotonic() + 10
    while _browser_pids() - before and time.monotonic() < deadline:
        time.sleep(0.1)
    assert not (_browser_pids() - before), "SIGTERM left Puppeteer Chrome descendants behind"
