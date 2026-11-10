#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Collect a REDACTED nano support bundle on one host (standard library only).

  ssh USER@HOST 'python3 -I - --install-dir ~/nano' < support-bundle.py
  scp USER@HOST:~/nano-support-<host>-<ts>.tar.gz ./nano-deploy-work/

Collected: host facts (OS, CPU, memory, disk, Docker/Compose versions), release
markers, .env and .nano-role.env KEY NAMES with secret values removed,
`docker compose ps`, container states and health, and the last --tail lines of
each nano container's logs.

Redaction, applied to everything before it is written:
  * every value from .env / .nano-role.env whose key looks secret (PASSWORD,
    TOKEN, SECRET, KEY, CREDENTIAL, PRIVATE) is replaced by [REDACTED:<KEY>];
  * bearer / basic auth headers, JWTs, password=/token=/secret= pairs, PEM blocks.
Review the archive before sending it: `tar -xzf ... -O | less`. It is mode 0600.
"""
from __future__ import annotations

import argparse
import io
import os
import re
import socket
import subprocess
import sys
import tarfile
import time

SECRET_KEY = re.compile(r"(PASSWORD|TOKEN|SECRET|KEY|CREDENTIAL|PRIVATE|PASS)", re.I)
PATTERNS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "[REDACTED:PEM]"),
    (re.compile(r"(?i)(authorization\"?\s*[:=]\s*\"?)[A-Za-z]+\s+[^\s\",]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{12,}"), r"\1 [REDACTED]"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), "[REDACTED:JWT]"),
    (re.compile(r"(?i)\b(password|passwd|token|secret|api[_-]?key)(\"?\s*[:=]\s*\"?)[^\s\"',;&]+"), r"\1\2[REDACTED]"),
    (re.compile(r"(?i)(://[^:/\s]+:)[^@/\s]+@"), r"\1[REDACTED]@"),
]


def read_env(path: str) -> dict:
    out: dict = {}
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.rstrip("\n")
                if line.strip() and not line.lstrip().startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    v = v.strip()
                    if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
                        v = v[1:-1]
                    out[k.strip()] = v
    except FileNotFoundError:
        pass
    return out


def run(cmd: list[str], timeout: int = 60) -> str:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (p.stdout or "") + (("\n[stderr]\n" + p.stderr) if p.stderr.strip() else "")
    except (OSError, subprocess.TimeoutExpired) as err:
        return f"[failed: {err}]"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--install-dir", default="~/nano")
    ap.add_argument("--tail", type=int, default=400)
    ap.add_argument("--out-dir", default="~")
    a = ap.parse_args()
    d = os.path.expanduser(a.install_dir)
    env = read_env(os.path.join(d, ".env"))
    role = read_env(os.path.join(d, ".nano-role.env"))
    secrets = {}
    for src in (env, role, read_env(os.path.expanduser("~/.nano-admin-credentials"))):
        for k, v in src.items():
            if SECRET_KEY.search(k) and len(v) >= 6 and not v.startswith("/"):
                secrets[v] = k
    ordered = sorted(secrets.items(), key=lambda kv: -len(kv[0]))

    def redact(text: str) -> str:
        for value, key in ordered:
            text = text.replace(value, f"[REDACTED:{key}]")
        for rx, rep in PATTERNS:
            text = rx.sub(rep, text)
        return text

    files: dict[str, str] = {}
    files["host.txt"] = "\n".join([
        f"host: {socket.gethostname()}  collected: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}",
        run(["uname", "-a"]), run(["cat", "/etc/os-release"]), run(["nproc"]), run(["free", "-m"]),
        run(["df", "-h"]), run(["timedatectl"]), run(["docker", "version"]), run(["docker", "compose", "version"]),
        run(["docker", "info"]),
    ])
    markers = []
    for name in (".nano-edition", ".nano-bundle"):
        p = os.path.join(d, name)
        if os.path.isfile(p):
            markers.append(f"{name}: {open(p, encoding='utf-8').read().strip()[:200]}")
    for lock in ("images.enterprise.customer.lock", "images.enterprise.lock", "images.lock"):
        p = os.path.join(d, lock)
        if os.path.isfile(p):
            markers.append(f"{lock}:\n" + open(p, encoding="utf-8").read())
    files["release.txt"] = "\n".join(markers)

    def describe(e: dict) -> str:
        return "\n".join(f"{k}=" + ("[REDACTED]" if SECRET_KEY.search(k) else v) for k, v in sorted(e.items()))
    files["env-keys.txt"] = describe(env)
    if role:
        files["role-env.txt"] = describe(role)

    compose = ["docker", "compose"]
    if role:
        compose += ["--env-file", os.path.join(d, ".env"), "--env-file", os.path.join(d, ".nano-role.env"),
                    "-f", os.path.join(d, "deploy/compose/docker-compose.enterprise.yml")]
    else:
        compose += ["-f", os.path.join(d, "docker-compose.opensource.yml")]
    files["compose-ps.txt"] = run(compose + ["ps", "-a"])
    files["docker-ps.txt"] = run(["docker", "ps", "-a", "--format",
                                  "{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.RunningFor}}"])
    names = [n for n in run(["docker", "ps", "-a", "--format", "{{.Names}}"]).split() if n.startswith("nano")]
    for n in names:
        files[f"logs/{n}.log"] = run(["docker", "logs", "--timestamps", "--tail", str(a.tail), n], timeout=90)
        files[f"inspect/{n}.state.txt"] = run(["docker", "inspect", "--format",
                                               "{{json .State}} restarts={{.RestartCount}}", n])

    ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    out = os.path.join(os.path.expanduser(a.out_dir), f"nano-support-{socket.gethostname()}-{ts}.tar.gz")
    old = os.umask(0o077)
    try:
        with tarfile.open(out, "w:gz") as tar:
            for name, text in files.items():
                data = redact(text).encode()
                info = tarfile.TarInfo(f"nano-support/{name}")
                info.size, info.mtime, info.mode = len(data), int(time.time()), 0o600
                tar.addfile(info, io.BytesIO(data))
    finally:
        os.umask(old)
    print(f"wrote {out} ({len(files)} files, {len(ordered)} secret values redacted); review before sharing")
    return 0


if __name__ == "__main__":
    sys.exit(main())
