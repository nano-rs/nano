"""Artifact secret guard (NAN-4937 review P1).

Artifacts are uploaded when a run fails, so cleanup succeeding can never be
the security boundary. Two layers:

- `redact_rendered(src, dst)`: rendered Vector source configs are copied
  through a structured TOML redactor: every value under a sensitive key
  (secret, password, token, key, connection string, credentials, ...) and every
  `SharedAccessKey=` / `AccountKey=` part of a string is replaced, keeping the
  file's layout so a reader can still debug routing.
- `scrub(artifacts_dir, secrets)`: every known secret value (the stack's own,
  the cloud test credentials loaded for the run, tokens the scenarios issued)
  is replaced in every file; then every file, text or binary, is re-scanned
  and the guard FAILS (exit 3) if any value remains.

Known values come from env files the runner passes and from a 0600 registry in
the run dir (`.secrets.jsonl`), which pytest appends to at session start (the
credentials `with_creds` loaded) and whenever a scenario learns a secret. It
lives outside `artifacts/` and is removed by `down`.

Stdlib only: the runner calls it with the system python3.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tomllib
from collections.abc import Iterable, Iterator
from pathlib import Path

REGISTRY = ".secrets.jsonl"
MIN_LEN = 8
REDACTED = "<redacted>"
SENSITIVE_KEY = re.compile(
    r"(secret|passw|token|api_?key|access_?key|private_?key|account_?key|sas|connection_?string|credential|auth)",
    re.I,
)
SECRET_ENV = re.compile(r"(SECRET|PASSWORD|_KEY|TOKEN|SA_JSON|ADC|CONNECTION_STRING|DATABASE_URL)")
INLINE = re.compile(r"((?:SharedAccessKey|AccountKey|SharedAccessSignature|sig)=)([^;&\"'\s]+)", re.I)


# ---------------------------------------------------------------- registry
def registry_path(run_dir: str | os.PathLike[str] | None = None) -> Path | None:
    d = run_dir or os.environ.get("E2E_RUN_DIR")
    return Path(d) / REGISTRY if d else None


def remember(*values: str, run_dir: str | os.PathLike[str] | None = None) -> None:
    """Record secret values the artifact guard must scrub (0600, append)."""
    path = registry_path(run_dir)
    vals = [v for v in values if isinstance(v, str) and len(v) >= MIN_LEN]
    if not path or not vals or not path.parent.is_dir():
        return
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a") as f:
        for v in vals:
            f.write(json.dumps(v) + "\n")


def env_secrets(environ: dict[str, str] | None = None) -> list[str]:
    env = os.environ if environ is None else environ
    return [v for k, v in env.items() if SECRET_ENV.search(k) and len(v) >= MIN_LEN]


def _leaves(value: str) -> Iterator[str]:
    """A secret and the forms it can take inside other text: JSON/TOML-escaped,
    and, for a JSON document (a service-account key), its sensitive leaves."""
    yield value
    yield json.dumps(value)[1:-1]
    try:
        doc = json.loads(value)
    except (ValueError, TypeError):
        return
    stack = [doc]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            for k, v in cur.items():
                if isinstance(v, str) and SENSITIVE_KEY.search(str(k)) and len(v) >= MIN_LEN:
                    yield v
                    yield json.dumps(v)[1:-1]
                elif isinstance(v, (dict, list)):
                    stack.append(v)
        elif isinstance(cur, list):
            stack.extend(cur)


def expand(values: Iterable[str]) -> list[str]:
    out = {leaf for v in values for leaf in _leaves(v) if len(leaf) >= MIN_LEN}
    return sorted(out, key=len, reverse=True)


def file_secrets(paths: Iterable[Path]) -> list[str]:
    """Secret FILES (the C05 license, NAN-5331): read at scrub time from where
    the operator keeps them, so their contents are never copied into the run
    dir's registry. A missing/unreadable/binary file contributes nothing."""
    vals: list[str] = []
    for p in paths:
        try:
            text = p.read_bytes().decode()
        except (OSError, UnicodeDecodeError):
            continue
        vals.extend(v for v in (text, text.strip()) if len(v) >= MIN_LEN)
    return vals


def load(
    registry: Path | None, env_files: Iterable[Path] = (), secret_files: Iterable[Path] = ()
) -> list[str]:
    vals: list[str] = file_secrets(secret_files)
    if registry and registry.is_file():
        for line in registry.read_text().splitlines():
            if line.strip():
                vals.append(json.loads(line))
    for ef in env_files:
        if ef.is_file():
            for line in ef.read_text().splitlines():
                k, sep, v = line.partition("=")
                if sep and SECRET_ENV.search(k) and len(v) >= MIN_LEN:
                    vals.append(v)
    return expand(vals)


# ---------------------------------------------------------------- redactor
def _sensitive_values(doc: object, under_sensitive: bool = False) -> Iterator[str]:
    if isinstance(doc, dict):
        for k, v in doc.items():
            yield from _sensitive_values(v, under_sensitive or bool(SENSITIVE_KEY.search(str(k))))
    elif isinstance(doc, list):
        for v in doc:
            yield from _sensitive_values(v, under_sensitive)
    elif isinstance(doc, str) and under_sensitive and len(doc) >= MIN_LEN:
        yield doc


def redact_toml_text(text: str) -> str:
    """Replace every value under a sensitive key and every inline
    `SharedAccessKey=`-style part; layout preserved. Unparseable input is
    redacted line by line (`key = "..."` on a sensitive key)."""
    try:
        doc = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        doc = None
    out = text
    if doc is not None:
        for v in sorted(set(_sensitive_values(doc)), key=len, reverse=True):
            for form in (v, json.dumps(v)[1:-1]):
                out = out.replace(form, REDACTED)
    else:
        out = re.sub(
            r'(?m)^(\s*[\w.\-"]+\s*=\s*)("(?:[^"\\]|\\.)*"|\'[^\']*\')',
            lambda m: m.group(1) + '"' + REDACTED + '"' if SENSITIVE_KEY.search(m.group(1)) else m.group(0),
            out,
        )
    return INLINE.sub(lambda m: m.group(1) + REDACTED, out)


def redact_rendered(src: Path, dst: Path) -> int:
    """Copy a rendered-config tree through the redactor; returns files written."""
    n = 0
    for f in sorted(p for p in src.rglob("*") if p.is_file()):
        target = dst / f.relative_to(src)
        target.parent.mkdir(parents=True, exist_ok=True)
        data = f.read_bytes()
        try:
            text = data.decode()
        except UnicodeDecodeError:
            continue  # never copy a binary we cannot inspect
        target.write_text(redact_toml_text(text))
        n += 1
    return n


# ---------------------------------------------------------------- scrub + verify
def scrub(root: Path, secrets: list[str]) -> list[str]:
    """Replace known secrets in every text file under `root`; return the files
    that STILL contain one (text or binary). Empty list = clean."""
    if not secrets:
        return []
    enc = [(s, s.encode()) for s in secrets]
    left: list[str] = []
    for f in sorted(p for p in root.rglob("*") if p.is_file()):
        data = f.read_bytes()
        if not any(b in data for _, b in enc):
            continue
        try:
            text = data.decode()
        except UnicodeDecodeError:
            left.append(str(f.relative_to(root)))
            continue
        for s, _ in enc:
            text = text.replace(s, REDACTED)
        f.write_text(text)
        if any(b in f.read_bytes() for _, b in enc):
            left.append(str(f.relative_to(root)))
    return left


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="nano_e2e.artifact_guard")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("redact-rendered")
    r.add_argument("src", type=Path)
    r.add_argument("dst", type=Path)
    s = sub.add_parser("scrub")
    s.add_argument("artifacts", type=Path)
    s.add_argument("--run-dir", type=Path, required=True)
    s.add_argument("--env-file", type=Path, action="append", default=[])
    s.add_argument("--secret-file", type=Path, action="append", default=[])
    a = ap.parse_args(argv)
    if a.cmd == "redact-rendered":
        print(f"redacted {redact_rendered(a.src, a.dst)} rendered config file(s)")
        return 0
    secrets = load(a.run_dir / REGISTRY, a.env_file, a.secret_file)
    left = scrub(a.artifacts, secrets)
    if left:
        print("E2E-SECURITY: secret value(s) remain in artifacts after scrubbing:", file=sys.stderr)
        for f in left:
            print(f"  {f}", file=sys.stderr)
        return 3
    print(f"artifact guard: {len(secrets)} known secret form(s), artifacts clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
