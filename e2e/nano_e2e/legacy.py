"""Run the legacy lanes in dev/e2e/legacy-lanes.toml (scripts/e2e.sh legacy).

Lanes run sequentially. Each lane's output goes to
$E2E_LEGACY_ARTIFACTS/<lane>.log; a summary (pass / FAIL / skip + reason) is
printed at the end. Exit status is non-zero if any selected lane failed.
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import signal
import socket
import subprocess
import sys
import time
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Lane:
    name: str
    kind: str
    stack: bool = False
    cmd: list[str] = field(default_factory=list)
    package: str = ""
    test: str = ""
    threads: int = 0
    needs: list[str] = field(default_factory=list)
    requires_env: list[str] = field(default_factory=list)
    free_ports: list[str] = field(default_factory=list)
    platforms: list[str] = field(default_factory=lambda: ["darwin", "linux"])
    enterprise: bool = False
    timeout_min: int = 30
    issue: str = ""


def load(manifest: Path) -> list[Lane]:
    data = tomllib.loads(manifest.read_text())
    lanes = [Lane(**entry) for entry in data.get("lane", [])]
    names = [lane.name for lane in lanes]
    dupes = {n for n in names if names.count(n) > 1}
    if dupes:
        raise SystemExit(f"duplicate lane names in {manifest}: {sorted(dupes)}")
    return lanes


def select(lanes: list[Lane], wanted: list[str]) -> list[Lane]:
    if wanted == ["all"]:
        return lanes
    by_name = {lane.name: lane for lane in lanes}
    unknown = [w for w in wanted if w not in by_name]
    if unknown:
        raise SystemExit(f"unknown lane(s): {', '.join(unknown)} (scripts/e2e.sh legacy list)")
    return [by_name[w] for w in wanted]


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def skip_reason(lane: Lane, root: Path) -> str:
    plat = platform.system().lower()
    if plat not in lane.platforms:
        return f"platform {plat} not in {lane.platforms}"
    if lane.enterprise and not (root / "nanosiem-enterprise").is_dir():
        return "needs nanosiem-enterprise (open-core tree)"
    if lane.kind == "script" and not (root / lane.cmd[0]).exists():
        return f"{lane.cmd[0]} not in this tree"
    if lane.kind == "cargo" and not (root / lane.package).is_dir():
        return f"package {lane.package} not in this tree"
    if "docker" in lane.needs and not shutil.which("docker"):
        return "docker not found"
    missing = [e for e in lane.requires_env if not os.environ.get(e)]
    if missing:
        return f"requires {', '.join(missing)}"
    if lane.stack and not os.environ.get("E2E_RUN_ID"):
        return "needs the e2e stack env (run through scripts/e2e.sh legacy)"
    return ""


def command(lane: Lane, root: Path | None = None) -> list[str]:
    if lane.kind == "script":
        script = (root or Path.cwd()) / lane.cmd[0]
        # Several checked-in scripts lack the exec bit; run them through bash
        # (they all declare bash/sh shebangs) instead of failing with EACCES.
        if not os.access(script, os.X_OK):
            return ["bash", *lane.cmd]
        return list(lane.cmd)
    cargo = os.environ.get("E2E_CARGO") or "cargo"
    cmd = [cargo, "test", "-p", lane.package, "--test", lane.test, "--", "--ignored", "--nocapture"]
    if lane.threads:
        cmd.append(f"--test-threads={lane.threads}")
    return cmd


def run_lane_process(argv: list[str], *, cwd: Path, env: dict[str, str], log: Path, timeout: float) -> str:
    """Run one lane in its OWN session (process group). On timeout the whole
    group gets TERM (so the lane's cleanup traps run and its containers go),
    then KILL after a grace period; descendants never outlive the lane."""
    with log.open("w") as out:
        proc = subprocess.Popen(  # noqa: S603 - manifest-defined argv
            argv, cwd=cwd, env=env, stdout=out, stderr=subprocess.STDOUT, start_new_session=True
        )
        try:
            rc = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            _kill_group(proc, signal.SIGTERM)
            try:
                proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                pass
            _kill_group(proc, signal.SIGKILL)
            proc.wait()
            return f"FAIL (timeout {timeout / 60:.0f}m)"
    return "pass" if rc == 0 else f"FAIL (exit {rc})"


def _kill_group(proc: subprocess.Popen, sig: int) -> None:
    try:
        os.killpg(proc.pid, sig)  # pgid == pid (start_new_session)
    except (ProcessLookupError, PermissionError):
        pass


def run(lanes: list[Lane], root: Path, artifacts: Path, *, explicit: bool, allow_skips: bool) -> int:
    """Run lanes sequentially. Exit non-zero when a lane failed, when an
    EXPLICITLY named lane was skipped, or when nothing ran at all (unless
    allow_skips): a selection that executes nothing is not a green run."""
    artifacts.mkdir(parents=True, exist_ok=True)
    results: list[tuple[str, str, str]] = []
    for lane in lanes:
        reason = skip_reason(lane, root)
        if reason:
            results.append((lane.name, "skip", reason))
            print(f"-- {lane.name}: SKIP ({reason})", flush=True)
            continue
        env = dict(os.environ)
        env.setdefault("CARGO", os.environ.get("E2E_CARGO") or "cargo")
        env["E2E_ARTIFACT_DIR"] = str(artifacts / lane.name)
        for var in lane.free_ports:
            env[var] = str(free_port())
        log = artifacts / f"{lane.name}.log"
        argv = command(lane, root)
        print(f"-- {lane.name}: running ({' '.join(argv)}); log {log}", flush=True)
        started = time.monotonic()
        status = run_lane_process(argv, cwd=root, env=env, log=log, timeout=lane.timeout_min * 60)
        secs = time.monotonic() - started
        results.append((lane.name, status, f"{secs:.0f}s"))
        print(f"-- {lane.name}: {status} in {secs:.0f}s", flush=True)
        if status != "pass":
            print("".join(log.read_text(errors="replace").splitlines(keepends=True)[-40:]), flush=True)
    print("\nlegacy lanes:")
    for name, status, note in results:
        print(f"  {name:32} {status:22} {note}")
    return verdict(results, explicit=explicit, allow_skips=allow_skips)


def verdict(results: list[tuple[str, str, str]], *, explicit: bool, allow_skips: bool) -> int:
    if any(s.startswith("FAIL") for _, s, _ in results):
        return 1
    if allow_skips:
        return 0
    skipped = [n for n, s, _ in results if s == "skip"]
    ran = [n for n, s, _ in results if s == "pass"]
    if explicit and skipped:
        print(
            f"legacy: explicitly selected lane(s) did not run: {', '.join(skipped)} (--allow-skips to permit)"
        )
        return 1
    if not ran:
        print("legacy: no lane executed (--allow-skips to permit)")
        return 1
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True, type=Path)
    ap.add_argument("--root", type=Path, default=Path.cwd())
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--needs-stack", action="store_true", help="exit 0 iff a selected lane needs the stack")
    ap.add_argument("--allow-skips", action="store_true", help="skipped / zero lanes do not fail the run")
    ap.add_argument("lanes", nargs="*")
    args = ap.parse_args()
    lanes = load(args.manifest)
    if args.list:
        for lane in lanes:
            what = " ".join(lane.cmd) if lane.kind == "script" else f"{lane.package} --test {lane.test}"
            flags = ",".join(f for f, on in (("stack", lane.stack), ("enterprise", lane.enterprise)) if on)
            print(f"  {lane.name:32} {what:58} {flags}")
        return 0
    chosen = select(lanes, args.lanes or ["all"])
    if args.needs_stack:
        return 0 if any(lane.stack for lane in chosen) else 1
    artifacts = Path(os.environ.get("E2E_LEGACY_ARTIFACTS") or (args.root / "target/e2e/legacy"))
    explicit = bool(args.lanes) and args.lanes != ["all"]
    return run(chosen, args.root, artifacts, explicit=explicit, allow_skips=args.allow_skips)


if __name__ == "__main__":
    sys.exit(main())
