#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Convert an open nano install to enterprise (Self-run), in place (NAN-5558).

    scripts/nano convert --to enterprise --package nano-compose-enterprise-X.Y.Z.tar.gz
        --backup-key-file KEY.pem --backup-output DIR
        (--license-env-file FILE | --license-file LICENSE.json)
        [--dry-run] [--resume] [--probe-ingest] [--install-dir DIR]
    scripts/nano convert --rollback --backup-key-file KEY.pem [--backup BUNDLE_DIR]

The only supported edition change. install.sh and `scripts/nano upgrade` keep
refusing every other one. Same release, same Compose project, same data
volumes: the enterprise compose package is extracted over the open install
and its install.sh runs with NANO_CONVERT_EDITION=enterprise and the license.

State machine, recorded in <install>/.nano-convert.json (mode 0600, a copy in
the run directory under --backup-output):

    started -> backed-up -> tree-switched -> env-switched -> started-enterprise -> verified
    rollback: rollback-started -> rollback-tree-restored -> rollback-postgres-restored
              -> rollback-reinstalled -> rolled-back

Secrets (the license token, database passwords) never reach argv, the
journal or the output.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import fcntl
import hashlib
import json
import os
import pathlib
import re
import secrets
import shutil
import ssl
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Iterable, Sequence

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
DEFAULT_INSTALL_DIR = SCRIPT_DIR.parent

# The first release whose installer honours NANO_CONVERT_EDITION. Convert also
# checks the package's own install.sh for it (older packages cannot convert).
MIN_CONVERT_VERSION = (2, 0, 32)
OPEN_IMAGE_PREFIX = "ghcr.io/nano-rs/nano"
CUSTOMER_LOCK = "images.enterprise.customer.lock"
JOURNAL_NAME = ".nano-convert.json"
LOCK_NAME = ".nano-convert.lock"
PREVIOUS_JOURNAL_NAME = ".nano-convert.previous.json"
OPEN_GIT_NAME = ".nano-open-git"
JOURNAL_FORMAT = "nano-convert-v1"
FORWARD_STATES = ("started", "backed-up", "tree-switched", "env-switched", "started-enterprise", "verified")
ROLLBACK_STATES = (
    "rollback-started", "rollback-tree-restored", "rollback-postgres-restored",
    "rollback-reinstalled", "rolled-back",
)
TERMINAL_STATES = ("verified", "rolled-back")
# PostgreSQL tables whose rows must survive the conversion. None may shrink.
# They may grow: the open stack keeps serving while the backup runs, and the
# enterprise overlay seeds default rows (roles, detection rules). `cases`
# exists only once the overlay ran, so an open install has nothing to compare.
COUNT_TABLES = (
    "users", "roles", "api_keys", "ingest_tokens", "log_sources",
    "detection_rules", "cases", "dashboards",
)
EVENT_TABLES = ("logs", "ocsf_logs")
ENTERPRISE_MIGRATION_FLOOR = 9000000
LICENSE_KEYS = ("LICENSE_URL", "LICENSE_TOKEN", "NANO_DEPLOYMENT_ID")
LICENSE_DEFAULT_URL = "https://api.nano.rs/api/license/status"
LICENSE_PAGE_HINT = "app.nano.rs > Deployments > your Self-run deployment > License"
LICENSE_URL_RE = re.compile(r"^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$")
LICENSE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{32,255}$")
DEPLOYMENT_ID_RE = re.compile(r"^deploy_[0-9a-hjkmnp-tv-z]{26}$")
OFFLINE_LICENSE_MAX_BYTES = 262144
SEMVER_RE = re.compile(r"^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
BINDING_RE = re.compile(r"install|bound|binding|another", re.IGNORECASE)
# Never extracted over an install, never taken from a package.
HOST_STATE_FILES = frozenset({".env", ".nano-role.env", JOURNAL_NAME, LOCK_NAME, PREVIOUS_JOURNAL_NAME,
                              ".nano-host-identity"})
CONTROL_TREE_EXCLUDES = frozenset({"backups", JOURNAL_NAME, LOCK_NAME, PREVIOUS_JOURNAL_NAME, OPEN_GIT_NAME})
CH_QUERY_SCRIPT = r'''
IFS= read -r password
[ -n "$password" ] || { echo "ClickHouse admin credential is empty" >&2; exit 1; }
escaped=$(printf "%s" "$password" | sed -e "s/&/\&amp;/g" -e "s/</\&lt;/g" -e "s/>/\&gt;/g")
umask 077
config=$(mktemp /tmp/nano-convert-clickhouse.XXXXXX.xml)
trap 'rm -f -- "$config"' EXIT HUP INT TERM
printf "<clickhouse><password>%s</password></clickhouse>\n" "$escaped" > "$config"
clickhouse-client --config-file "$config" --host localhost --port 9000 \
    --user nanosiem_admin --format=TSVRaw --multiquery
'''


class ConvertError(Exception):
    """A refusal or failure, with a message safe to print."""


@dataclasses.dataclass
class Check:
    name: str
    passed: bool
    detail: str
    warning: bool = False


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def semver(value: str) -> tuple[int, int, int]:
    match = SEMVER_RE.fullmatch((value or "").strip())
    if not match:
        raise ConvertError(f"invalid release version {value!r}; expected X.Y.Z")
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def version_text(parts: Sequence[int]) -> str:
    return ".".join(str(part) for part in parts)


def print_checks(checks: Sequence[Check], title: str = "Preflight") -> None:
    rows = [("PASS" if c.passed and not c.warning else "WARN" if c.passed else "FAIL", c.name, c.detail) for c in checks]
    width = max([len("CHECK")] + [len(r[1]) for r in rows])
    print(f"{'RESULT':<6}  {'CHECK':<{width}}  DETAIL")
    for result, name, detail in rows:
        print(f"{result:<6}  {name:<{width}}  {detail}")
    failed = sum(not c.passed for c in checks)
    print(f"{title}: {len(checks) - failed}/{len(checks)} PASS; {failed} FAIL")


# --------------------------------------------------------------------------
# Small file helpers
# --------------------------------------------------------------------------

def parse_env_text(text: str) -> dict[str, str]:
    """install.sh env_value semantics: KEY=value, last assignment wins, quotes
    and CR dropped."""
    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.lstrip().startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            continue
        values[key] = value.replace("\r", "").replace('"', "").replace("'", "")
    return values


def read_env(path: pathlib.Path) -> dict[str, str]:
    try:
        return parse_env_text(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, UnicodeDecodeError) as error:
        raise ConvertError(f"cannot read {path}: {error.__class__.__name__}") from error


def atomic_write(path: pathlib.Path, data: bytes, mode: int = 0o600) -> None:
    """Write beside the target, fsync, then rename over it: a reader sees the
    old file or the new one, never a partial one. Resolves a symlinked .env so
    it stays a link."""
    target = path.resolve() if path.is_symlink() else path
    descriptor, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=str(target.parent))
    try:
        with os.fdopen(descriptor, "wb") as handle:
            os.fchmod(handle.fileno(), mode)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    except BaseException:
        with _suppress(OSError):
            os.unlink(temporary)
        raise


class _suppress:
    def __init__(self, *errors: type[BaseException]):
        self.errors = errors

    def __enter__(self) -> None:
        return None

    def __exit__(self, kind: Any, value: Any, traceback: Any) -> bool:
        return kind is not None and issubclass(kind, self.errors)


def require_private_file(path: pathlib.Path, label: str) -> None:
    """A regular, non-symlink file owned by this user with mode 0600."""
    try:
        info = path.lstat()
    except OSError as error:
        raise ConvertError(f"{label} not found: {path}") from error
    if not stat.S_ISREG(info.st_mode):
        raise ConvertError(f"{label} must be a regular file, not a symlink or directory: {path}")
    if info.st_uid != os.geteuid():
        raise ConvertError(f"{label} must be owned by the user running convert (uid {os.geteuid()}): {path}")
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise ConvertError(
            f"{label} must have mode 0600 (it has {stat.S_IMODE(info.st_mode):04o}); "
            f"run chmod 600 {path}"
        )


@dataclasses.dataclass
class License:
    mode: str  # online | offline
    url: str = ""
    token: str = dataclasses.field(default="", repr=False)
    deployment_id: str = ""
    file: str = ""

    def environment(self) -> dict[str, str]:
        if self.mode == "online":
            return {"LICENSE_URL": self.url, "LICENSE_TOKEN": self.token, "NANO_DEPLOYMENT_ID": self.deployment_id}
        return {"NANO_LICENSE_MODE": "offline", "NANO_LICENSE_FILE": self.file}

    def describe(self) -> str:
        if self.mode == "online":
            return f"online check-in for {self.deployment_id} (token not shown)"
        return f"offline license file {self.file}"


def load_license_env_file(path: pathlib.Path) -> License:
    """LICENSE_URL / LICENSE_TOKEN / NANO_DEPLOYMENT_ID lines from a 0600 file
    owned by this user. Errors name keys, never values."""
    require_private_file(path, "--license-env-file")
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise ConvertError(f"cannot read --license-env-file {path}") from error
    values: dict[str, str] = {}
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip().replace("\r", "")
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        key, sep, value = line.partition("=")
        key = key.strip()
        if not sep or key not in LICENSE_KEYS:
            raise ConvertError(
                f"--license-env-file line {number} is not one of {', '.join(LICENSE_KEYS)} "
                "(KEY=value; the value is not shown)"
            )
        if key in values:
            raise ConvertError(f"--license-env-file sets {key} twice")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key] = value
    for key in ("LICENSE_TOKEN", "NANO_DEPLOYMENT_ID"):
        if not values.get(key):
            raise ConvertError(f"--license-env-file has no {key}; copy it from {LICENSE_PAGE_HINT}")
    url = values.get("LICENSE_URL") or LICENSE_DEFAULT_URL
    if not LICENSE_URL_RE.fullmatch(url):
        raise ConvertError(f"LICENSE_URL in --license-env-file is not an https:// URL such as {LICENSE_DEFAULT_URL}")
    if not LICENSE_TOKEN_RE.fullmatch(values["LICENSE_TOKEN"]):
        raise ConvertError(
            "LICENSE_TOKEN in --license-env-file is not an enrollment token "
            f"(expected 32+ letters, digits, '-' or '_'; value not shown). Copy it from {LICENSE_PAGE_HINT}"
        )
    if not DEPLOYMENT_ID_RE.fullmatch(values["NANO_DEPLOYMENT_ID"]):
        raise ConvertError(
            "NANO_DEPLOYMENT_ID in --license-env-file is not a deployment ID like deploy_01h2x3y4z5... "
            f"Copy it from {LICENSE_PAGE_HINT}"
        )
    return License("online", url=url, token=values["LICENSE_TOKEN"], deployment_id=values["NANO_DEPLOYMENT_ID"])


def load_offline_license(path: pathlib.Path) -> License:
    try:
        info = path.lstat()
    except OSError as error:
        raise ConvertError(f"--license-file not found: {path}") from error
    if not stat.S_ISREG(info.st_mode):
        raise ConvertError(f"--license-file must be a regular file: {path}")
    if not 1 <= info.st_size <= OFFLINE_LICENSE_MAX_BYTES:
        raise ConvertError(f"--license-file must be 1 to {OFFLINE_LICENSE_MAX_BYTES} bytes: {path}")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ConvertError(f"--license-file is not a signed license JSON file: {path}") from error
    if not isinstance(document, dict):
        raise ConvertError(f"--license-file is not a signed license JSON file: {path}")
    return License("offline", file=str(path.resolve()))


# --------------------------------------------------------------------------
# Package and control tree
# --------------------------------------------------------------------------

@dataclasses.dataclass
class PackageInfo:
    path: pathlib.Path
    version: str
    top: str
    files: list[str]
    directories: list[str]
    edition_marker: str
    customer_api_ref: str
    supports_convert: bool
    sha256: str


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def safe_relative(name: str) -> bool:
    parts = pathlib.PurePosixPath(name).parts
    return bool(parts) and not name.startswith("/") and ".." not in parts


def inspect_package(path: pathlib.Path) -> PackageInfo:
    """List the enterprise compose package without extracting it: one top
    directory nano-<version>/, regular files and directories only, no host
    state, the enterprise marker, the customer lock and a converting installer."""
    if path.is_symlink() or not path.is_file():
        raise ConvertError(f"--package must be a regular file: {path}")
    files: list[str] = []
    directories: list[str] = []
    top = ""
    marker = ""
    customer_ref = ""
    supports = False
    try:
        with tarfile.open(path, "r:gz") as archive:
            for member in archive:
                name = member.name.rstrip("/")
                if name.startswith("./"):
                    name = name[2:]
                if not safe_relative(name):
                    raise ConvertError(f"{path.name} has an unsafe path: {member.name!r}")
                head, _, rest = name.partition("/")
                top = top or head
                if head != top or not re.fullmatch(r"nano-[0-9]+\.[0-9]+\.[0-9]+", head):
                    raise ConvertError(f"{path.name} is not one nano-<version>/ tree (found {head!r})")
                if not rest:
                    continue
                if member.isdir():
                    directories.append(rest)
                    continue
                if not member.isfile():
                    raise ConvertError(f"{path.name} holds a link or special file: {rest}")
                if pathlib.PurePosixPath(rest).name in HOST_STATE_FILES or rest in HOST_STATE_FILES:
                    raise ConvertError(f"{path.name} contains host state ({rest}); refusing to extract it")
                files.append(rest)
                if rest in (".nano-edition", CUSTOMER_LOCK, "install.sh"):
                    handle = archive.extractfile(member)
                    content = handle.read().decode("utf-8", "replace") if handle else ""
                    if rest == ".nano-edition":
                        marker = content.strip()
                    elif rest == CUSTOMER_LOCK:
                        for line in content.splitlines():
                            fields = line.split()
                            if len(fields) >= 2 and fields[0].endswith("-api") and fields[1].startswith("sha256:"):
                                customer_ref = f"{fields[0]}@{fields[1]}"
                                break
                    else:
                        supports = "NANO_CONVERT_EDITION" in content
    except (tarfile.TarError, OSError, EOFError) as error:
        raise ConvertError(f"cannot read {path.name}: {error}") from error
    if not top:
        raise ConvertError(f"{path.name} is empty")
    return PackageInfo(
        path=path, version=top[len("nano-"):], top=top, files=sorted(files),
        directories=sorted(directories), edition_marker=marker, customer_api_ref=customer_ref,
        supports_convert=supports, sha256=sha256_file(path),
    )


def control_tree_size(install_dir: pathlib.Path) -> tuple[int, list[str]]:
    """Bytes the control tree tar holds, and paths it could not read."""
    total = 0
    unreadable: list[str] = []
    for root, dirs, names in os.walk(install_dir):
        rel_root = pathlib.Path(root).relative_to(install_dir)
        if rel_root == pathlib.Path("."):
            dirs[:] = [d for d in dirs if d not in CONTROL_TREE_EXCLUDES]
            names = [n for n in names if n not in CONTROL_TREE_EXCLUDES]
        for name in names:
            path = pathlib.Path(root, name)
            try:
                info = path.lstat()
            except OSError:
                unreadable.append(str(path.relative_to(install_dir)))
                continue
            if stat.S_ISREG(info.st_mode):
                if not os.access(path, os.R_OK):
                    unreadable.append(str(path.relative_to(install_dir)))
                total += info.st_size
        for name in dirs:
            path = pathlib.Path(root, name)
            if not path.is_symlink() and not os.access(path, os.R_OK | os.X_OK):
                unreadable.append(str(path.relative_to(install_dir)) + "/")
    return total, unreadable


def unwritable_paths(install_dir: pathlib.Path, package_files: Iterable[str]) -> list[str]:
    """Directories the conversion or its rollback must change but this user
    cannot: every directory of the control tree (tar replaces a file by
    unlinking it and writing a new one, so the directory is what counts; the
    git metadata is only renamed), and the nearest existing directory of
    every path the package writes."""
    bad: set[str] = set()
    for root, dirs, _ in os.walk(install_dir):
        rel = pathlib.Path(root).relative_to(install_dir)
        if rel == pathlib.Path("."):
            dirs[:] = [d for d in dirs if d not in CONTROL_TREE_EXCLUDES and d != ".git"]
        dirs[:] = [d for d in dirs if not pathlib.Path(root, d).is_symlink()]
        if not os.access(root, os.W_OK | os.X_OK):
            bad.add(f"{rel}/")
    for name in package_files:
        parent = (install_dir / name).parent
        while not parent.exists() and parent != install_dir:
            parent = parent.parent
        if not os.access(parent, os.W_OK | os.X_OK):
            bad.add(f"{parent.relative_to(install_dir)}/")
    return sorted(bad)


def write_control_tree(install_dir: pathlib.Path, output: pathlib.Path) -> list[str]:
    """Tar everything in the install directory but the backups folder and
    convert's own files: Compose files, scripts, generated configuration,
    .env, PKI and, on a git install, .git. Data volumes are not in it."""
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        return tar_control_tree(install_dir, handle)


def tar_control_tree(install_dir: pathlib.Path, handle: Any) -> list[str]:
    names: list[str] = []

    def keep(info: tarfile.TarInfo) -> tarfile.TarInfo | None:
        first = info.name.split("/", 1)[0]
        if info.name != "." and first in CONTROL_TREE_EXCLUDES:
            return None
        if info.name != ".":
            names.append(info.name)
        return info

    with tarfile.open(fileobj=handle, mode="w|") as archive:
        for entry in sorted(os.listdir(install_dir)):
            if entry in CONTROL_TREE_EXCLUDES:
                continue
            archive.add(str(install_dir / entry), arcname=entry, recursive=True, filter=keep)
    return names


def control_tree_members(path: pathlib.Path) -> list[str]:
    with tarfile.open(path, "r") as archive:
        return [member.name for member in archive]


def inside(root: pathlib.Path, path: pathlib.Path) -> bool:
    """True when path (resolved, through any symlinked parent) is root or
    below it."""
    resolved_root = root.resolve()
    resolved = path.resolve()
    return resolved == resolved_root or resolved_root in resolved.parents


def rollback_removals(package_files: Iterable[str], package_dirs: Iterable[str],
                      control_members: Iterable[str]) -> tuple[list[str], list[str]]:
    """Files the enterprise package added (it had them, the open tree did not)
    and the directories it created. Host state is never on either list."""
    control = set(control_members)
    package_files = set(package_files)
    package_dirs = set(package_dirs)
    for name in package_files:  # every ancestor, listed in the archive or not
        parent = pathlib.PurePosixPath(name).parent
        while str(parent) not in (".", ""):
            package_dirs.add(str(parent))
            parent = parent.parent
    files = sorted(
        name for name in package_files
        if name not in control and pathlib.PurePosixPath(name).name not in HOST_STATE_FILES and safe_relative(name)
    )
    dirs = sorted(
        (name for name in package_dirs if name not in control and safe_relative(name)),
        key=lambda name: name.count("/"), reverse=True,
    )
    return files, dirs


# --------------------------------------------------------------------------
# System access (fake in tests)
# --------------------------------------------------------------------------

class Runner:
    def run(self, argv: Sequence[str], *, input_text: str | None = None, timeout: float = 600,
            check: bool = True, env: dict[str, str] | None = None, cwd: str | None = None,
            capture: bool = True, new_session: bool = False) -> subprocess.CompletedProcess:
        try:
            result = subprocess.run(
                list(argv), input=input_text, text=True, timeout=timeout, env=env, cwd=cwd,
                stdout=subprocess.PIPE if capture else None,
                stderr=subprocess.PIPE if capture else None,
                stdin=None if input_text is not None else subprocess.DEVNULL,
                start_new_session=new_session, check=False,
            )
        except FileNotFoundError as error:
            raise ConvertError(f"{argv[0]} is not installed") from error
        except subprocess.TimeoutExpired as error:
            raise ConvertError(f"{argv[0]} did not finish within {int(timeout)}s") from error
        if check and result.returncode != 0:
            tail = [line for line in (result.stderr or "").splitlines() if line.strip()][-3:]
            raise ConvertError(f"{argv[0]} {argv[1] if len(argv) > 1 else ''} failed (exit {result.returncode})"
                               + (": " + " | ".join(tail) if tail else ""))
        return result


class System:
    """Everything convert reads from or does to the host."""

    def __init__(self, install_dir: pathlib.Path, runner: Runner | None = None,
                 script_dir: pathlib.Path = SCRIPT_DIR):
        self.install_dir = install_dir
        self.runner = runner or Runner()
        self.script_dir = script_dir

    # -- environment ----------------------------------------------------
    def env(self) -> dict[str, str]:
        return read_env(self.install_dir / ".env")

    def docker(self, *args: str, input_text: str | None = None, timeout: float = 120,
               check: bool = True) -> subprocess.CompletedProcess:
        return self.runner.run(["docker", *args], input_text=input_text, timeout=timeout, check=check)

    def inspect(self, container: str) -> dict[str, Any] | None:
        result = self.docker("inspect", container, check=False)
        if result.returncode != 0:
            return None
        try:
            value = json.loads(result.stdout)
        except json.JSONDecodeError:
            return None
        return value[0] if isinstance(value, list) and value and isinstance(value[0], dict) else None

    def pg(self, sql: str, timeout: float = 120) -> str:
        env = self.env()
        user = env.get("POSTGRES_USER") or "nanosiem"
        database = env.get("POSTGRES_DB") or "nanosiem"
        result = self.docker("exec", "-i", "nano-postgres", "psql", "-X", "-v", "ON_ERROR_STOP=1",
                             f"--username={user}", f"--dbname={database}", "--tuples-only", "--no-align",
                             input_text=sql + "\n", timeout=timeout)
        return result.stdout.strip()

    def ch(self, sql: str, timeout: float = 600) -> str:
        password = self.env().get("CLICKHOUSE_ADMIN_PASSWORD", "")
        if not password:
            raise ConvertError("CLICKHOUSE_ADMIN_PASSWORD is missing from .env")
        result = self.docker("exec", "-i", "nano-clickhouse", "sh", "-ec", CH_QUERY_SCRIPT,
                             input_text=password + "\n" + sql + "\n", timeout=timeout)
        return result.stdout.strip()

    def api_get(self, path: str) -> str:
        result = self.docker("exec", "nano-api", "wget", "-qO-", f"http://127.0.0.1:3000{path}",
                             timeout=30, check=False)
        if result.returncode != 0:
            raise ConvertError(f"nano-api did not answer {path} (exit {result.returncode})")
        return result.stdout

    # -- reads ----------------------------------------------------------
    def api_health(self) -> str:
        self.api_get("/health")
        info = self.inspect("nano-api") or {}
        health = ((info.get("State") or {}).get("Health") or {}).get("Status", "")
        if health and health != "healthy":
            raise ConvertError(f"nano-api is {health}")
        return "healthy"

    def capabilities(self) -> dict[str, Any]:
        try:
            value = json.loads(self.api_get("/api/capabilities"))
        except json.JSONDecodeError as error:
            raise ConvertError("nano-api /api/capabilities is not JSON") from error
        if not isinstance(value, dict):
            raise ConvertError("nano-api /api/capabilities is not a JSON object")
        return value

    def compose_identity(self) -> dict[str, Any]:
        """The Compose project and the named volumes the databases run on."""
        identity: dict[str, Any] = {"project": "", "volumes": {}}
        for container in ("nano-postgres", "nano-clickhouse"):
            info = self.inspect(container)
            if info is None:
                raise ConvertError(f"container {container} not found")
            state = info.get("State") or {}
            if not state.get("Running"):
                raise ConvertError(f"container {container} is not running")
            labels = (info.get("Config") or {}).get("Labels") or {}
            project = labels.get("com.docker.compose.project", "")
            if identity["project"] and project != identity["project"]:
                raise ConvertError("nano-postgres and nano-clickhouse belong to different Compose projects")
            identity["project"] = project
            identity["volumes"][container] = sorted(
                f"{mount.get('Name')}:{mount.get('Destination')}"
                for mount in info.get("Mounts") or [] if mount.get("Type") == "volume"
            )
        return identity

    def pg_counts(self) -> dict[str, int | None]:
        names = ",".join(f"'{table}'" for table in COUNT_TABLES)
        present = set(self.pg(
            "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
            f"WHERE n.nspname = 'public' AND c.relkind IN ('r','p') AND c.relname IN ({names}) ORDER BY 1"
        ).split())
        counts: dict[str, int | None] = {table: None for table in COUNT_TABLES}
        if present:
            query = " UNION ALL ".join(
                f"SELECT '{table}', count(*) FROM public.{table}" for table in COUNT_TABLES if table in present
            )
            for line in self.pg(query).splitlines():
                table, _, value = line.partition("|")
                if table in counts and value.strip().isdigit():
                    counts[table] = int(value)
        return counts

    def pg_enterprise_migrations(self) -> int:
        value = self.pg(
            "SELECT count(*) FROM _sqlx_migrations "
            f"WHERE version > {ENTERPRISE_MIGRATION_FLOOR} AND success"
        )
        return int(value or 0)

    def license_row(self) -> dict[str, Any]:
        present = self.pg("SELECT to_regclass('public.license_status') IS NOT NULL")
        if present != "t":
            return {}
        line = self.pg(
            "SELECT status, valid, coalesce(replace(locked_reason, '|', '/'), ''), "
            "coalesce((raw_response ? 'token_rejected')::text, 'false') FROM license_status WHERE id"
        )
        if not line:
            return {}
        status, valid, reason, rejected = (line.split("|") + ["", "", "", ""])[:4]
        return {"status": status, "valid": valid == "t", "locked_reason": reason, "token_rejected": rejected == "true"}

    def ch_event_snapshot(self) -> dict[str, dict[str, Any]]:
        present = set(self.ch(
            "SELECT name FROM system.tables WHERE database = 'nanosiem' "
            f"AND name IN ({','.join(repr(t) for t in EVENT_TABLES)}) ORDER BY name"
        ).split())
        snapshot: dict[str, dict[str, Any]] = {}
        for table in EVENT_TABLES:
            if table not in present:
                continue
            line = self.ch(f"SELECT count(), toString(max(_inserted_at)) FROM nanosiem.{table}")
            rows, _, newest = line.partition("\t")
            snapshot[table] = {"rows": int(rows or 0), "max_inserted_at": newest.strip()}
        return snapshot

    def ch_rows_up_to(self, table: str, newest: str) -> int:
        if table not in EVENT_TABLES or not re.fullmatch(r"[0-9: .-]{10,32}", newest):
            raise ConvertError("invalid event snapshot")
        return int(self.ch(
            f"SELECT count() FROM nanosiem.{table} WHERE _inserted_at <= toDateTime64('{newest}', 6, 'UTC')"
        ) or 0)

    def ch_enterprise_migrations(self) -> int:
        return int(self.ch(
            "SELECT count() FROM nanosiem._migrations "
            f"WHERE toUInt64OrZero(version) > {ENTERPRISE_MIGRATION_FLOOR}"
        ) or 0)

    def ch_enterprise_objects(self) -> list[str]:
        out = self.ch(
            "SELECT name FROM system.tables WHERE database = 'nanosiem' AND (name LIKE 'logs_per_source_1h%' "
            "OR name LIKE 'sovereign_license_%') ORDER BY name"
        )
        return [line for line in out.splitlines() if line]

    def database_size(self) -> int:
        return int(self.pg("SELECT pg_database_size(current_database())") or 0)

    # -- package --------------------------------------------------------
    def verify_package(self, package: pathlib.Path) -> dict[str, Any]:
        result = self.runner.run(
            [str(self.script_dir / "nano"), "bundle", "verify", str(package), "--json"],
            timeout=1800, check=False,
        )
        try:
            manifest = json.loads(result.stdout or "{}")
        except json.JSONDecodeError as error:
            raise ConvertError(f"bundle verifier failed (exit {result.returncode}) for {package.name}") from error
        if result.returncode != 0 or not isinstance(manifest, dict) or "error" in manifest:
            reason = manifest.get("error", f"exit {result.returncode}") if isinstance(manifest, dict) else "invalid output"
            raise ConvertError(f"cannot verify {package.name}: {reason}")
        return manifest

    def registry_probe(self, lic: License, image_ref: str) -> str:
        """Ask the license API for a registry pull credential, as install.sh
        will, before anything changes. The credential lands in a private
        temporary docker config that is removed here."""
        helper = self.script_dir / "lib" / "registry-login.sh"
        if not helper.is_file():
            return "skipped (this tree has no registry-login.sh)"
        scratch = pathlib.Path(tempfile.mkdtemp(prefix="nano-convert-registry."))
        try:
            os.chmod(scratch, 0o700)
            config = scratch / "docker"
            config.mkdir(mode=0o700)
            lines = [f"{key}={value}" for key, value in lic.environment().items()]
            lines.append("NANO_LICENSE_MODE=online")
            proxy = self.env().get("HTTPS_PROXY", "")
            if proxy:
                lines.append(f"HTTPS_PROXY={proxy}")
            env_file = scratch / "license.env"
            atomic_write(env_file, ("\n".join(lines) + "\n").encode())
            result = self.runner.run(
                ["bash", str(helper), "--env-file", str(env_file), "--docker-config", str(config), "--even-if-local"],
                input_text=image_ref + "\n", timeout=180, check=False,
            )
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
        if result.returncode != 0:
            messages = [line.strip() for line in (result.stderr or "").splitlines() if line.strip()]
            detail = messages[-1] if messages else f"exit {result.returncode}"
            if lic.token:
                detail = detail.replace(lic.token, "[REDACTED]")
            if re.search(r"HTTP 409|bound to another|another install", detail, re.IGNORECASE):
                detail = (
                    "STOP: the license API says this license is bound to another installation. Do not "
                    "work around it: contact nano support or release the license on app.nano.rs. " + detail
                )
            raise ConvertError(detail)
        outcome = (result.stdout or "").strip().splitlines()
        return outcome[-1] if outcome else "unchanged"

    # -- actions --------------------------------------------------------
    def run_backup(self, key_file: pathlib.Path, output: pathlib.Path) -> None:
        self.runner.run(
            [str(self.script_dir / "nano"), "backup", "--key-file", str(key_file), "--output", str(output),
             "--install-dir", str(self.install_dir)],
            timeout=6 * 3600, capture=False,
        )

    def extract_package(self, package: pathlib.Path) -> None:
        self.runner.run(
            ["tar", "-x", "-z", "--strip-components=1", "-f", str(package), "-C", str(self.install_dir)],
            timeout=1800,
        )

    def extract_control_tree(self, archive: pathlib.Path, exclude_git: bool) -> None:
        # Options first, then -f ARCHIVE: a bundled `-xpf` takes the very next
        # argument as the archive (the first lab rollback passed it
        # "--exclude=.git"). GNU and BSD tar both accept this order.
        excludes = ["--exclude=.git", "--exclude=.git/*"] if exclude_git else []
        self.runner.run(
            ["tar", "-x", "-p", *excludes, "-f", str(archive), "-C", str(self.install_dir)],
            timeout=1800,
        )

    def clear_pipeline_identity(self) -> bool:
        """NAN-5564: forget which pipeline identity the Vector config was
        rendered for, so a Vector started on a rolled-back tree waits for the
        api to render it again instead of trusting a marker the other edition
        wrote. Removed through whichever container mounts the volume."""
        for container, path in (("nano-vector", "/etc/vector/dynamic/.nano-pipeline-identity"),
                                ("nano-api", "/app/config/vector/.nano-pipeline-identity")):
            if self.docker("exec", container, "rm", "-f", path, check=False).returncode == 0:
                return True
        return False

    def run_installer(self, extra_env: dict[str, str]) -> int:
        environment = {
            key: value for key, value in os.environ.items()
            if key not in {"NANO_EDITION", "NANO_VERSION", "NANO_IMAGES_LOCK", "NANO_CONVERT_EDITION", "NANO_CONVERT_RUN",
                           "LICENSE_URL", "LICENSE_TOKEN", "DEPLOYMENT_TOKEN", "NANO_DEPLOYMENT_ID",
                           "NANO_LICENSE_MODE", "NANO_LICENSE_FILE", "NANO_INSTALLER_SCRIPT_PATH"}
        }
        environment.update({"NANO_INSTALL_DIR": str(self.install_dir), "NANO_SKIP_GIT_UPDATE": "1"})
        environment.update(extra_env)
        # A new session has no controlling terminal: install.sh runs unattended
        # and never prompts.
        result = self.runner.run(
            ["bash", str(self.install_dir / "install.sh")], env=environment, cwd=str(self.install_dir),
            timeout=4 * 3600, check=False, capture=False, new_session=True,
        )
        return result.returncode

    # -- rollback material, encrypted like `nano backup` ----------------
    def write_encrypted_control_tree(self, output: pathlib.Path, key_file: pathlib.Path) -> list[str]:
        """The control tree streamed into `openssl cms -encrypt` (AES-256-GCM
        to the backup key's certificate): it holds .env, so no plaintext copy
        is ever written."""
        process = subprocess.Popen(
            ["openssl", "cms", "-encrypt", "-binary", "-aes-256-gcm", "-outform", "DER",
             "-out", str(output), str(key_file)],
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        assert process.stdin is not None
        names: list[str] = []
        try:
            names = tar_control_tree(self.install_dir, process.stdin)
        except BrokenPipeError:
            pass  # openssl exited early; its exit status below says why
        finally:
            with _suppress(BrokenPipeError):
                process.stdin.close()
        error = process.stderr.read().decode("utf-8", "replace") if process.stderr else ""
        if process.wait() != 0:
            raise ConvertError(f"openssl could not encrypt the control tree: {error.strip()[-300:]}")
        os.chmod(output, 0o600)
        return names

    def encrypt_bytes(self, data: bytes, output: pathlib.Path, key_file: pathlib.Path) -> None:
        result = subprocess.run(
            ["openssl", "cms", "-encrypt", "-binary", "-aes-256-gcm", "-outform", "DER",
             "-out", str(output), str(key_file)],
            input=data, capture_output=True, check=False,
        )
        if result.returncode != 0:
            raise ConvertError("openssl could not encrypt the rollback copy of .env")
        os.chmod(output, 0o600)

    def decrypt_to(self, source: pathlib.Path, output: pathlib.Path, key_file: pathlib.Path) -> None:
        self.runner.run(
            ["openssl", "cms", "-decrypt", "-binary", "-inform", "DER", "-in", str(source),
             "-recip", str(key_file), "-inkey", str(key_file), "-out", str(output)],
            timeout=1800,
        )
        os.chmod(output, 0o600)

    def stop_app_services(self) -> None:
        """Stop everything that can run PostgreSQL migrations or write to the
        database, so the rollback's migration check cannot race them."""
        for container in ("nano-api", "nano-jobs", "nano-search", "nano-clickhouse-migrate"):
            info = self.inspect(container)
            if info and (info.get("State") or {}).get("Running"):
                self.docker("stop", "--time", "60", container, timeout=120)

    def run_restore(self, key_file: pathlib.Path, bundle: pathlib.Path) -> None:
        self.runner.run(
            [str(self.install_dir / "scripts" / "nano"), "restore", "--key-file", str(key_file),
             "--from", str(bundle), "--force", "--install-dir", str(self.install_dir)],
            timeout=6 * 3600, capture=False,
        )

    def ch_forget_enterprise_migrations(self) -> None:
        self.ch(
            "ALTER TABLE nanosiem._migrations DELETE WHERE toUInt64OrZero(version) > "
            f"{ENTERPRISE_MIGRATION_FLOOR} SETTINGS mutations_sync = 2"
        )

    def probe_ingest(self, marker: str) -> None:
        env = self.env()
        token = env.get("NANO_PLATFORM_INGEST_TOKEN", "")
        if not token:
            raise ConvertError("--probe-ingest needs NANO_PLATFORM_INGEST_TOKEN in .env")
        tls = "docker-compose.tls.yml" in env.get("NANO_COMPOSE_OVERLAYS", "").split()
        url = "https://127.0.0.1:443/ingest" if tls else f"http://127.0.0.1:{env.get('NANO_HOST_PORT') or 80}/ingest"
        body = json.dumps({"source_type": "nano_convert_probe", "message": marker, "timestamp": utc_now()}).encode()
        request = urllib.request.Request(url, data=body, method="POST", headers={
            "Authorization": f"Bearer {token}", "Content-Type": "application/json"})
        context = ssl._create_unverified_context() if tls else None  # loopback; the certificate names the public host
        try:
            with urllib.request.urlopen(request, timeout=30, context=context) as response:
                if response.status >= 300:
                    raise ConvertError(f"ingest probe answered HTTP {response.status}")
        except urllib.error.HTTPError as error:
            raise ConvertError(f"ingest probe answered HTTP {error.code}") from error
        except (urllib.error.URLError, OSError) as error:
            raise ConvertError(f"ingest probe could not reach {url}: {error.__class__.__name__}") from error
        table = "ocsf_logs" if env.get("NANO_SCHEMA_PROFILE") == "ocsf" else "logs"
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            rows = self.ch(
                f"SELECT count() FROM nanosiem.{table} WHERE timestamp > now() - INTERVAL 10 MINUTE "
                f"AND position(message, '{marker}') > 0"
            )
            if rows not in ("", "0"):
                return
            time.sleep(3)
        raise ConvertError("the ingest probe event did not become searchable within 120s")


# --------------------------------------------------------------------------
# Journal
# --------------------------------------------------------------------------

class Journal:
    def __init__(self, install_dir: pathlib.Path):
        self.path = install_dir / JOURNAL_NAME
        self.data: dict[str, Any] = {}

    def exists(self) -> bool:
        return self.path.exists() or self.path.is_symlink()

    def load(self) -> dict[str, Any]:
        require_private_file(self.path, "convert journal")
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ConvertError(f"convert journal is unreadable: {self.path}") from error
        if not isinstance(data, dict) or data.get("format") != JOURNAL_FORMAT:
            raise ConvertError(f"convert journal has an unknown format: {self.path}")
        if data.get("state") not in FORWARD_STATES + ROLLBACK_STATES:
            raise ConvertError(f"convert journal has an unknown state: {data.get('state')!r}")
        self.data = data
        return data

    def create(self, data: dict[str, Any]) -> None:
        """A new journal, created exclusively (never over another run's)."""
        descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.close(descriptor)
        self.data = data
        self.save()

    @property
    def state(self) -> str:
        return str(self.data.get("state", ""))

    def save(self) -> None:
        encoded = (json.dumps(self.data, indent=2, sort_keys=True) + "\n").encode()
        atomic_write(self.path, encoded)
        run_dir = self.data.get("run_dir")
        if run_dir and pathlib.Path(run_dir).is_dir():
            atomic_write(pathlib.Path(run_dir) / "journal.json", encoded)

    def advance(self, state: str, **fields: Any) -> None:
        if state not in FORWARD_STATES + ROLLBACK_STATES:
            raise ValueError(state)
        self.data.update(fields)
        self.data["state"] = state
        self.data.setdefault("history", []).append({"state": state, "at": utc_now()})
        self.save()


def at_or_after(state: str, target: str) -> bool:
    return FORWARD_STATES.index(state) >= FORWARD_STATES.index(target)


def incomplete_upgrade_journals(install_dir: pathlib.Path) -> list[str]:
    directory = install_dir / "upgrade-journal"
    found: list[str] = []
    if not directory.is_dir():
        return found
    for path in sorted(directory.glob("upgrade-*.jsonl")):
        try:
            events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        except (OSError, json.JSONDecodeError):
            found.append(path.name)
            continue
        if events and not any(e.get("event") in {"run_completed", "rollback_completed", "run_abandoned"} for e in events):
            found.append(path.name)
    return found


def compose_project_name(install_dir: pathlib.Path, env: dict[str, str]) -> str:
    """Same rule as install.sh compose_project_name."""
    name = (os.environ.get("COMPOSE_PROJECT_NAME") or env.get("COMPOSE_PROJECT_NAME") or install_dir.name).lower()
    name = re.sub(r"[^a-z0-9_-]", "", name)
    return name.lstrip("_-")


# --------------------------------------------------------------------------
# Convert
# --------------------------------------------------------------------------

@dataclasses.dataclass
class Options:
    install_dir: pathlib.Path
    package: pathlib.Path | None = None
    backup_key_file: pathlib.Path | None = None
    backup_output: pathlib.Path | None = None
    license: License | None = None
    dry_run: bool = False
    resume: bool = False
    rollback: bool = False
    backup: pathlib.Path | None = None
    probe_ingest: bool = False
    license_wait: int = 300
    ack_postgres_data_loss: bool = False


def age_text(since: str) -> str:
    try:
        then = dt.datetime.fromisoformat(since.replace("Z", "+00:00"))
    except ValueError:
        return "of unknown age"
    minutes = int((dt.datetime.now(dt.timezone.utc) - then).total_seconds() // 60)
    if minutes < 120:
        return f"{minutes} minutes old"
    if minutes < 48 * 60:
        return f"{minutes // 60} hours old"
    return f"{minutes // 1440} days old"


class Converter:
    def __init__(self, options: Options, system: System | None = None,
                 sleep: Callable[[float], None] = time.sleep, out: Callable[[str], None] = print):
        self.o = options
        self.install_dir = options.install_dir
        self.system = system or System(options.install_dir)
        self.journal = Journal(options.install_dir)
        self.sleep = sleep
        self.say = out
        self._lock: Any = None

    # -- preflight ------------------------------------------------------
    def preflight(self) -> tuple[list[Check], dict[str, Any], PackageInfo | None]:
        checks: list[Check] = []
        snapshot: dict[str, Any] = {}
        package: PackageInfo | None = None

        def check(name: str, function: Callable[[], str], warning: bool = False) -> bool:
            try:
                detail = function()
            except ConvertError as error:
                checks.append(Check(name, False, str(error)))
                return False
            checks.append(Check(name, True, detail, warning))
            return True

        install = self.install_dir.resolve()
        env_path = install / ".env"
        env: dict[str, str] = {}

        def owner() -> str:
            info = install.lstat()
            if not stat.S_ISDIR(info.st_mode):
                raise ConvertError(f"{install} is not a directory")
            if info.st_uid != os.geteuid():
                raise ConvertError(
                    f"{install} is owned by uid {info.st_uid}; run convert as that user "
                    f"(this is uid {os.geteuid()})"
                )
            require_private_file(env_path, ".env")
            return f"uid {os.geteuid()} owns {install} and .env"
        check("owner", owner)
        with _suppress(ConvertError):
            env = read_env(env_path)

        def topology() -> str:
            if (install / ".nano-role.env").exists():
                raise ConvertError("this is a role-split install (.nano-role.env); convert supports single-node installs only")
            return "single node"
        check("topology", topology)

        def edition() -> str:
            recorded = env.get("NANO_EDITION", "")
            if recorded and recorded != "open":
                raise ConvertError(f"this install is already the {recorded} edition")
            if recorded != "open":
                raise ConvertError(".env records no NANO_EDITION=open; re-run the open install.sh once to record it")
            if env.get("NANO_IMAGE_PREFIX") != OPEN_IMAGE_PREFIX:
                raise ConvertError(
                    f".env records NANO_IMAGE_PREFIX={env.get('NANO_IMAGE_PREFIX') or '(none)'}, "
                    f"not {OPEN_IMAGE_PREFIX}"
                )
            return f"open ({OPEN_IMAGE_PREFIX}-*)"
        check("edition", edition)

        installed = env.get("NANO_VERSION", "")

        def version() -> str:
            parts = semver(installed)
            if parts < MIN_CONVERT_VERSION:
                raise ConvertError(
                    f"installed {installed}; convert needs {version_text(MIN_CONVERT_VERSION)} or newer. "
                    "Upgrade the open install first (scripts/nano upgrade)"
                )
            return f"installed {installed}"
        check("version", version)

        def package_check() -> str:
            nonlocal package
            if self.o.package is None:
                raise ConvertError("--package nano-compose-enterprise-<version>.tar.gz is required")
            info = self.verified_package(self.o.package)
            if installed and info.version != installed:
                raise ConvertError(
                    f"package is {info.version}, this install runs {installed}. Convert never changes the "
                    f"release: upgrade the open install to {info.version} first, or use the "
                    f"nano-compose-enterprise-{installed}.tar.gz package"
                )
            package = info
            return (f"{self.o.package.name}: signature verified (sha256 {info.sha256[:12]}...), "
                    f"enterprise {info.version}, {len(info.files)} files")
        check("package", package_check)

        def writable() -> str:
            bad = unwritable_paths(install, package.files if package else [])
            if bad:
                raise ConvertError(
                    f"{len(bad)} director{'y' if len(bad) == 1 else 'ies'} in the install cannot be changed by "
                    f"this user (first: {bad[0]}); give them back to the install owner"
                )
            return "every directory the package and a rollback change is writable"
        check("writable", writable)

        def license_check() -> str:
            if self.o.license is None:
                raise ConvertError("give the license: --license-env-file FILE (online) or --license-file FILE (offline)")
            return self.o.license.describe()
        if check("license", license_check) and self.o.license and self.o.license.mode == "online" and package:
            check("license-api", lambda: "registry pull credential: " + self.system.registry_probe(
                self.o.license, package.customer_api_ref))
        elif self.o.license and self.o.license.mode == "offline":
            checks.append(Check(
                "license-api", True,
                "offline license: no registry credential is requested; load the image bundle "
                "(scripts/nano bundle load) or docker login before converting", warning=True))

        def journals() -> str:
            blocked = incomplete_upgrade_journals(install)
            if blocked:
                raise ConvertError(f"an upgrade is incomplete ({', '.join(blocked)}); finish or roll it back first")
            for marker in (".nano-restore-recovery", ".nano-legacy-restore.json"):
                if (install / marker).exists():
                    raise ConvertError(f"an interrupted restore left {marker}; finish it first")
            if self.journal.exists():
                data = self.journal.load()
                if data.get("state") not in TERMINAL_STATES:
                    raise ConvertError(
                        f"a conversion is in progress (state {data.get('state')}); run --resume or --rollback"
                    )
            return "no upgrade, restore or conversion in progress"
        check("journals", journals)

        def stack() -> str:
            identity = self.system.compose_identity()
            expected = compose_project_name(install, env)
            if identity["project"] != expected:
                raise ConvertError(
                    f"the running databases belong to Compose project {identity['project']!r}, "
                    f"but this directory is project {expected!r}"
                )
            health = self.system.api_health()
            edition_now = self.system.capabilities().get("edition")
            if edition_now != "open":
                raise ConvertError(f"nano-api reports the {edition_now} edition")
            snapshot["compose"] = identity
            return f"project {identity['project']}, nano-api {health}, open edition running"
        check("stack", stack)

        def data() -> str:
            snapshot["pg_counts"] = self.system.pg_counts()
            snapshot["pg_enterprise_migrations"] = self.system.pg_enterprise_migrations()
            snapshot["events"] = self.system.ch_event_snapshot()
            snapshot["taken_at"] = utc_now()
            rows = sum(item["rows"] for item in snapshot["events"].values())
            present = sum(1 for value in snapshot["pg_counts"].values() if value is not None)
            return f"{present} PostgreSQL tables counted, {rows} ClickHouse events"
        check("snapshot", data)

        def backup_target() -> str:
            if self.o.backup_key_file is None or not self.o.backup_key_file.is_file():
                raise ConvertError("--backup-key-file KEY.pem is required (scripts/nano backup-keygen)")
            if self.o.backup_output is None:
                raise ConvertError("--backup-output DIR (outside the install directory) is required")
            target = self.o.backup_output.resolve()
            if target == install or install in target.parents:
                raise ConvertError("--backup-output must be outside the install directory")
            probe = target
            while not probe.exists():
                probe = probe.parent
            if not os.access(probe, os.W_OK | os.X_OK):
                raise ConvertError(f"{probe} is not writable")
            size, unreadable = control_tree_size(install)
            if unreadable:
                raise ConvertError(
                    f"{len(unreadable)} path(s) in the install directory are not readable by this user "
                    f"(first: {unreadable[0]}); give them back to the install owner"
                )
            package_bytes = self.o.package.stat().st_size if self.o.package and self.o.package.is_file() else 0
            need = size + package_bytes + int(self.system.database_size() * 1.5) + (512 << 20)
            free = shutil.disk_usage(probe).free
            if free < need:
                raise ConvertError(f"{probe} has {free >> 20} MiB free; the backup needs about {need >> 20} MiB")
            return f"{target}: {free >> 20} MiB free, about {need >> 20} MiB needed"
        check("backup", backup_target)

        if (install / ".git").exists():
            checks.append(Check(
                "git", True, f"git checkout: .git is moved to {OPEN_GIT_NAME} so install.sh never resets "
                "this install to the open repository", warning=True))
        return checks, snapshot, package

    def verified_package(self, path: pathlib.Path) -> PackageInfo:
        """The signed manifest names the package's sha256; the listed tree must
        be exactly that file, an enterprise package that can convert."""
        manifest = self.system.verify_package(path)
        if manifest.get("edition") != "enterprise":
            raise ConvertError(f"{path.name} is the {manifest.get('edition')} edition, not enterprise")
        info = inspect_package(path)
        signed = str(manifest.get("package_sha256", ""))
        if not re.fullmatch(r"[0-9a-f]{64}", signed) or signed != info.sha256:
            raise ConvertError(f"{path.name} is not the file its signed statement names (package_sha256 differs)")
        if str(manifest.get("version", "")).lstrip("v") != info.version:
            raise ConvertError("the signed manifest and the package tree disagree on the release")
        if info.edition_marker != "enterprise":
            raise ConvertError(f"{path.name} has no enterprise .nano-edition marker")
        if not info.customer_api_ref:
            raise ConvertError(f"{path.name} has no {CUSTOMER_LOCK}")
        if not info.supports_convert:
            raise ConvertError(f"the {info.version} enterprise installer cannot convert an install (no NANO_CONVERT_EDITION)")
        return info

    def private_copy(self, package: PackageInfo, run_dir: pathlib.Path) -> PackageInfo:
        """Copy the verified package into the 0700 run directory and work only
        from that copy: nobody can swap the file between the signature check
        and the extract."""
        directory = run_dir / "packages"
        directory.mkdir(mode=0o700, exist_ok=True)
        target = directory / f"{package.sha256[:16]}-{package.path.name}"
        if not target.is_file():
            temporary = directory / f".{target.name}.part"
            shutil.copyfile(package.path, temporary)
            os.chmod(temporary, 0o600)
            os.replace(temporary, target)
        copy = inspect_package(target)
        if copy.sha256 != package.sha256:
            target.unlink()
            raise ConvertError(f"{package.path.name} changed while it was copied; run the command again")
        return copy

    # -- locking --------------------------------------------------------
    def acquire_lock(self) -> None:
        path = self.install_dir / LOCK_NAME
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            os.close(descriptor)
            raise ConvertError(f"another scripts/nano convert is running on {self.install_dir}") from error
        self._lock = descriptor

    def release_lock(self) -> None:
        if self._lock is not None:
            with _suppress(OSError):
                fcntl.flock(self._lock, fcntl.LOCK_UN)
                os.close(self._lock)
            self._lock = None

    # -- forward --------------------------------------------------------
    def run(self) -> int:
        self.acquire_lock()
        try:
            if self.o.rollback:
                return self.rollback()
            if self.o.resume:
                return self.resume()
            return self.start()
        finally:
            self.release_lock()

    def start(self) -> int:
        checks, snapshot, package = self.preflight()
        print_checks(checks)
        if not all(c.passed for c in checks):
            self.say("Nothing was changed.")
            return 1
        assert package is not None and self.o.backup_output is not None
        if self.o.dry_run:
            self.say("Dry run: nothing was changed. Run the same command without --dry-run to convert.")
            return 0
        run_id = f"nano-convert-{dt.datetime.now(dt.timezone.utc):%Y%m%dT%H%M%SZ}-{secrets.token_hex(3)}"
        run_dir = self.o.backup_output.resolve() / run_id
        run_dir.mkdir(mode=0o700, parents=True)
        package = self.private_copy(package, run_dir)
        self.retire_previous_journal()
        self.journal.create({
            "format": JOURNAL_FORMAT, "run_id": run_id, "install_dir": str(self.install_dir),
            "run_dir": str(run_dir), "version": package.version, "created_at": utc_now(),
            "package": {"path": str(package.path), "sha256": package.sha256},
            "license_mode": self.o.license.mode if self.o.license else "",
            "git_checkout": (self.install_dir / ".git").exists(),
            "encrypted": True, "snapshot": snapshot, "history": [],
        })
        self.journal.advance("started")
        return self.forward(package)

    def retire_previous_journal(self) -> None:
        """A finished (verified or rolled back) conversion's journal moves
        aside so the new one is created exclusively."""
        if not self.journal.exists():
            return
        data = self.journal.load()
        if data.get("state") not in TERMINAL_STATES:
            raise ConvertError(f"a conversion is in progress (state {data.get('state')})")
        os.replace(self.journal.path, self.install_dir / PREVIOUS_JOURNAL_NAME)

    def resume(self) -> int:
        if not self.journal.exists():
            raise ConvertError(f"no conversion to resume ({self.journal.path} not found)")
        data = self.journal.load()
        state = data["state"]
        if state in ROLLBACK_STATES:
            raise ConvertError(f"a rollback is in progress (state {state}); run --rollback to finish it")
        if state == "verified":
            self.say("This install was already converted and verified.")
            return 0
        if not at_or_after(state, "started-enterprise") and self.o.license is None:
            raise ConvertError("give the license again (--license-env-file or --license-file) to resume")
        package: PackageInfo | None = None
        if self.o.package is not None and not at_or_after(state, "started-enterprise") \
                and sha256_file(self.o.package) != data["package"]["sha256"]:
            package = self.adopt_package(self.o.package)
        elif not at_or_after(state, "tree-switched"):
            package = inspect_package(pathlib.Path(data["package"]["path"]))
            if package.sha256 != data["package"]["sha256"]:
                raise ConvertError("the recorded package copy differs from the one this conversion verified")
        self.say(f"Resuming conversion {data['run_id']} from state {self.journal.state}")
        return self.forward(package)

    def adopt_package(self, path: pathlib.Path) -> PackageInfo:
        """--resume with a rebuilt enterprise package of the same release (a
        fixed installer): verify it like the original, copy it into the run
        directory, record it, and when the tree was already switched, extract
        it over the install again. Rollback removes every file either
        package added."""
        data = self.journal.data
        package = self.verified_package(path)
        if package.version != data.get("version"):
            raise ConvertError(f"{path.name} is release {package.version}; this conversion is for {data.get('version')}")
        run_dir = pathlib.Path(data["run_dir"])
        package = self.private_copy(package, run_dir)
        listing_path = run_dir / "package-files.json"
        if listing_path.is_file():
            listing = json.loads(listing_path.read_text(encoding="utf-8"))
            listing = {
                "files": sorted(set(listing.get("files", [])) | set(package.files)),
                "directories": sorted(set(listing.get("directories", [])) | set(package.directories)),
            }
            atomic_write(listing_path, json.dumps(listing).encode())
        data.setdefault("replaced_packages", []).append(data["package"])
        data["package"] = {"path": str(package.path), "sha256": package.sha256}
        self.journal.save()
        self.say(f"==> Using the verified package {path.name} (sha256 {package.sha256[:12]}...)")
        if self.journal.state in ("tree-switched", "env-switched"):
            self.say("==> Extracting it over the install directory again")
            self.system.extract_package(package.path)
            marker = (self.install_dir / ".nano-edition").read_text(encoding="utf-8").strip()
            if marker != "enterprise":
                raise ConvertError("the extracted tree is not marked enterprise")
        return package

    def backup_step(self, package: PackageInfo) -> None:
        data = self.journal.data
        run_dir = pathlib.Path(data["run_dir"])
        if self.o.backup_key_file is None:
            raise ConvertError("--backup-key-file is required to take the backup")
        self.say("==> Backing up PostgreSQL, configuration and the install directory")
        bundle = run_dir / "nano-backup"
        if bundle.exists():
            # `nano backup` builds in a temporary folder and renames it into
            # place at the very end, so an existing bundle is a complete one.
            if not ((bundle / "manifest.json").is_file() and (bundle / "manifest.sig").is_file()):
                raise ConvertError(
                    f"{bundle} is incomplete (no signed manifest); delete it (and any {run_dir}/.nano-backup.* "
                    "folder), then run --resume"
                )
            self.say(f"    reusing the complete backup from the interrupted run: {bundle}")
        else:
            self.say("    (scripts/nano backup stops nano-api, nano-search, nano-jobs, the connector runner and "
                     "Vector for its PostgreSQL snapshot and starts them again: the UI and ingest pause briefly, "
                     "senders retry)")
            self.system.run_backup(self.o.backup_key_file, bundle)
        control = run_dir / "control-tree.tar.cms"
        with _suppress(FileNotFoundError):
            control.unlink()
        members = self.system.write_encrypted_control_tree(control, self.o.backup_key_file)
        if ".env" not in members:
            raise ConvertError("the control tree backup does not hold .env")
        if data.get("git_checkout") and ".git/HEAD" not in members:
            raise ConvertError("the control tree backup does not hold the git checkout (.git)")
        env_copy = run_dir / "env.pre.cms"
        with _suppress(FileNotFoundError):
            env_copy.unlink()
        self.system.encrypt_bytes((self.install_dir / ".env").read_bytes(), env_copy, self.o.backup_key_file)
        atomic_write(run_dir / "package-files.json", json.dumps(
            {"files": package.files, "directories": package.directories}).encode())
        self.journal.advance("backed-up", backup_bundle=str(bundle), control_tree=str(control),
                             env_copy=str(env_copy))

    def forward(self, package: PackageInfo | None) -> int:
        data = self.journal.data
        run_dir = pathlib.Path(data["run_dir"])
        run_env = {"NANO_CONVERT_RUN": data["run_id"]}
        if self.journal.state == "started":
            assert package is not None
            self.backup_step(package)
        if self.journal.state == "backed-up":
            assert package is not None
            self.say("==> Switching the install directory to the enterprise release files")
            git = self.install_dir / ".git"
            aside = self.install_dir / OPEN_GIT_NAME
            if git.exists():
                if aside.exists():
                    raise ConvertError(f"both .git and {OPEN_GIT_NAME} exist; resolve that by hand, then --resume")
                os.rename(git, aside)
            if sha256_file(package.path) != data["package"]["sha256"]:
                raise ConvertError(f"the package copy {package.path} changed since it was verified")
            self.system.extract_package(package.path)
            marker = (self.install_dir / ".nano-edition").read_text(encoding="utf-8").strip()
            if marker != "enterprise":
                raise ConvertError("the extracted tree is not marked enterprise")
            self.journal.advance("tree-switched")
        if self.journal.state in ("tree-switched", "env-switched"):
            assert self.o.license is not None
            self.say("==> Running the enterprise installer (NANO_CONVERT_EDITION=enterprise)")
            code = self.system.run_installer(
                {"NANO_CONVERT_EDITION": "enterprise", **run_env, **self.o.license.environment()})
            edition = self.system.env().get("NANO_EDITION", "")
            if code != 0:
                if edition == "enterprise" and self.journal.state != "env-switched":
                    self.journal.advance("env-switched")
                raise ConvertError(
                    f"install.sh failed (exit {code}); see its output above. Fix the cause (for a license "
                    "refusal, check the values on app.nano.rs), then run scripts/nano convert --resume, "
                    "or scripts/nano convert --rollback to return to the open edition"
                )
            if edition != "enterprise":
                raise ConvertError("install.sh finished but .env does not record NANO_EDITION=enterprise")
            if self.journal.state != "env-switched":
                self.journal.advance("env-switched")
            identity = self.system.compose_identity()
            before = data.get("snapshot", {}).get("compose")
            if before and identity != before:
                raise ConvertError(
                    "the databases now run on a different Compose project or volumes "
                    f"(before {before}, after {identity}); stop and run scripts/nano convert --rollback"
                )
            self.journal.advance("started-enterprise")
        if self.journal.state == "started-enterprise":
            checks = self.verify()
            print_checks(checks, "Verification")
            if not all(c.passed for c in checks):
                self.say(
                    "Verification failed. The enterprise stack is running. Fix the cause and run "
                    "scripts/nano convert --resume to verify again, or scripts/nano convert --rollback."
                )
                return 1
            self.journal.advance("verified")
            self.say(
                f"Converted to enterprise {data['version']}. Backup and rollback material (encrypted to the "
                f"backup key): {run_dir}. "
                + (f"The old git metadata is in {self.install_dir / OPEN_GIT_NAME}; delete it once you no "
                   "longer need a rollback. " if data.get("git_checkout") else "")
            )
        return 0

    # -- verification ---------------------------------------------------
    def verify(self) -> list[Check]:
        checks: list[Check] = []
        snapshot = self.journal.data.get("snapshot", {})
        offline = self.journal.data.get("license_mode") == "offline"

        def add(name: str, function: Callable[[], str]) -> None:
            try:
                checks.append(Check(name, True, function()))
            except ConvertError as error:
                checks.append(Check(name, False, str(error)))

        add("api-health", self.system.api_health)

        def edition() -> str:
            value = self.system.capabilities().get("edition")
            if value != "enterprise":
                raise ConvertError(f"nano-api reports the {value} edition")
            return "nano-api reports enterprise"
        add("edition", edition)

        def migrations() -> str:
            pg = self.system.pg_enterprise_migrations()
            if pg <= 0:
                raise ConvertError("no enterprise PostgreSQL migrations (9000001+) in _sqlx_migrations")
            ch = self.system.ch_enterprise_migrations()
            return f"{pg} enterprise PostgreSQL and {ch} enterprise ClickHouse migrations applied"
        add("migrations", migrations)

        def counts() -> str:
            before = snapshot.get("pg_counts", {})
            after = self.system.pg_counts()
            notes = []
            for table in COUNT_TABLES:
                old, new = before.get(table), after.get(table)
                if old is None:
                    continue
                if new is None or new < old:
                    raise ConvertError(f"{table}: {old} rows before, {new} after")
                notes.append(f"{table} {old}" + (f"->{new}" if new != old else ""))
            return ", ".join(notes) or "no tables to compare"
        add("records", counts)
        add("events", self.events_unchanged)
        checks.append(self.license_check(offline))

        if self.o.probe_ingest:
            def ingest() -> str:
                marker = f"nano-convert-probe-{secrets.token_hex(8)}"
                self.system.probe_ingest(marker)
                return f"event {marker} (source_type nano_convert_probe) ingested and searchable"
            add("ingest", ingest)
        return checks

    def events_unchanged(self) -> str:
        notes = []
        for table, item in self.journal.data.get("snapshot", {}).get("events", {}).items():
            now = self.system.ch_rows_up_to(table, item["max_inserted_at"])
            if now != item["rows"]:
                raise ConvertError(
                    f"{table}: {item['rows']} events up to {item['max_inserted_at']} before, {now} now "
                    "(a retention TTL that dropped a partition meanwhile also shows here)"
                )
            notes.append(f"{table} {item['rows']}")
        return ", ".join(notes) + " events unchanged" if notes else "no event tables"

    def license_check(self, offline: bool) -> Check:
        deadline = time.monotonic() + self.o.license_wait
        while True:
            try:
                licensed = bool((self.system.capabilities().get("capabilities") or {}).get("cases"))
                row = {} if offline else self.system.license_row()
            except ConvertError as error:
                return Check("license", False, str(error))
            if licensed:
                return Check("license", True, "license active (licensed features available)")
            if row.get("token_rejected"):
                return Check("license", False,
                             "the license API rejected LICENSE_TOKEN; regenerate it on " + LICENSE_PAGE_HINT)
            reason = row.get("locked_reason", "")
            if row.get("status") == "locked" and reason and BINDING_RE.search(reason):
                return Check("license", False,
                             f"STOP: the license API says this license is bound to another installation ({reason}). "
                             "Do not work around it: contact nano support or release the license on app.nano.rs, "
                             "then run scripts/nano convert --resume (or --rollback)")
            if row.get("status") == "locked" and reason and row.get("valid") is False and "not been initialized" not in reason:
                return Check("license", False, f"license locked: {reason}")
            if offline:
                return Check("license", True,
                             "offline license: import it under Settings > License (the installer imports it "
                             "only when given the admin password)", warning=True)
            if time.monotonic() >= deadline:
                return Check("license", False,
                             f"no successful license check-in within {self.o.license_wait}s "
                             f"(status {row.get('status') or 'none'}); check nano-jobs logs, then --resume")
            self.sleep(10)

    # -- rollback -------------------------------------------------------
    def backup_age(self) -> str:
        for entry in self.journal.data.get("history", []):
            if entry.get("state") == "backed-up":
                return f"taken {entry.get('at')}, {age_text(str(entry.get('at')))}"
        return "of unknown age"

    def require_data_loss_ack(self) -> None:
        if self.o.ack_postgres_data_loss or self.journal.data.get("postgres_loss_acknowledged"):
            return
        raise ConvertError(
            "the enterprise release already ran on this database. Rollback restores PostgreSQL from the backup "
            f"{self.backup_age()}: every PostgreSQL change since then (users, rules, cases, alerts, settings) "
            "is lost. ClickHouse events stay. Re-run with --ack-postgres-data-loss to roll back anyway. "
            "Nothing was changed"
        )

    def rollback(self) -> int:
        if not self.journal.exists():
            raise ConvertError(f"no conversion to roll back ({self.journal.path} not found)")
        data = self.journal.load()
        state = data["state"]
        if state == "rolled-back":
            self.say("This conversion was already rolled back.")
            return 0
        if state == "started":
            self.journal.advance("rolled-back")
            self.say("Nothing had changed yet (the backup had not finished); the conversion is cancelled.")
            return 0
        current = self.system.env().get("NANO_VERSION", "")
        if state in FORWARD_STATES and current and current != data.get("version"):
            raise ConvertError(
                f"this install now runs {current}, not {data.get('version')} as converted; a conversion "
                "rolls back only on the release it was made on. Restore a backup instead (scripts/nano restore)"
            )
        if self.o.backup_key_file is None:
            raise ConvertError("--backup-key-file (the backup recovery key) is required to restore PostgreSQL")
        bundle = self.o.backup or pathlib.Path(data["backup_bundle"])
        if not bundle.is_dir():
            raise ConvertError(f"backup not found: {bundle}")
        if state in FORWARD_STATES:
            # Read-only check before anything changes. The PostgreSQL step
            # checks again once the application is stopped.
            if state in ("started-enterprise", "verified") or self.system.pg_enterprise_migrations() > 0:
                self.require_data_loss_ack()
            self.journal.advance("rollback-started", rolled_back_from=state,
                                 postgres_loss_acknowledged=self.o.ack_postgres_data_loss)
        if self.journal.state == "rollback-started":
            self.say("==> Restoring the open release files and .env")
            self.restore_tree()
            self.journal.advance("rollback-tree-restored")
        if self.journal.state == "rollback-tree-restored":
            self.say("==> Stopping nano-api, nano-jobs, nano-search and the migrator")
            self.system.stop_app_services()
            data = self.journal.data
            migrated = self.system.pg_enterprise_migrations() > 0 or bool(data.get("snapshot", {}).get("pg_enterprise_migrations"))
            if data.get("postgres_restore_started") or migrated:
                if not data.get("postgres_restore_started"):
                    self.require_data_loss_ack()
                    self.journal.data["postgres_restore_started"] = utc_now()
                    self.journal.save()
                self.say(f"==> Restoring PostgreSQL from the pre-conversion backup ({self.backup_age()}); "
                         "ClickHouse events stay in place")
                self.system.run_restore(self.o.backup_key_file, bundle)
                restored = True
            else:
                # The enterprise migrator never ran (install.sh stopped before
                # starting anything): the database is still the open one, and
                # keeping it keeps every write made since the backup.
                self.say("==> PostgreSQL was never migrated to enterprise; keeping it as it is")
                restored = False
            # Open backups record the highest ClickHouse ledger version; the
            # enterprise rows (9000001+) would make every later open backup
            # unrestorable on open. The enterprise tables themselves stay.
            self.system.ch_forget_enterprise_migrations()
            self.journal.advance("rollback-postgres-restored", postgres_restored=restored)
        if self.journal.state == "rollback-postgres-restored":
            if not self.system.clear_pipeline_identity():
                self.say("note: could not clear the Vector pipeline identity marker (no running Vector or API); "
                         "the open api's first render rewrites it")
            self.say("==> Starting the open release (install.sh, no git update)")
            code = self.system.run_installer({"NANO_CONVERT_RUN": self.journal.data["run_id"]})
            if code != 0:
                raise ConvertError(f"install.sh failed (exit {code}); fix the cause and re-run --rollback")
            self.journal.advance("rollback-reinstalled")
        if self.journal.state == "rollback-reinstalled":
            checks = self.verify_rollback()
            print_checks(checks, "Rollback verification")
            if not all(c.passed for c in checks):
                return 1
            self.journal.advance("rolled-back")
            self.say("Rolled back to the open edition.")
        return 0

    def restore_tree(self) -> None:
        data = self.journal.data
        run_dir = pathlib.Path(data["run_dir"])
        control = pathlib.Path(data["control_tree"])
        env_copy = pathlib.Path(data["env_copy"])
        listing = json.loads((run_dir / "package-files.json").read_text(encoding="utf-8"))
        scratch = pathlib.Path(tempfile.mkdtemp(prefix=".rollback.", dir=str(run_dir)))
        try:
            os.chmod(scratch, 0o700)
            if data.get("encrypted"):
                assert self.o.backup_key_file is not None
                self.system.decrypt_to(control, scratch / "control-tree.tar", self.o.backup_key_file)
                self.system.decrypt_to(env_copy, scratch / "env", self.o.backup_key_file)
                control, env_copy = scratch / "control-tree.tar", scratch / "env"
            members = control_tree_members(control)
            files, dirs = rollback_removals(listing["files"], listing["directories"], members)
            root = self.install_dir
            for name in files:
                path = root / name
                # Never follow a symlinked directory out of the install.
                if not inside(root, path.parent):
                    continue
                if path.is_file() or path.is_symlink():
                    path.unlink()
            for name in dirs:
                path = root / name
                if path.is_symlink() or not inside(root, path):
                    continue
                with _suppress(OSError):
                    path.rmdir()
            aside = root / OPEN_GIT_NAME
            git = root / ".git"
            if aside.is_dir():
                if git.exists():
                    shutil.rmtree(git)
                os.rename(aside, git)
            # The git metadata never left the install (it was only renamed), so
            # the copy in the control tree is not extracted over it. A resumed
            # rollback finds .git already moved back.
            git_in_place = bool(data.get("git_checkout")) and (git / "HEAD").is_file()
            self.system.extract_control_tree(control, exclude_git=git_in_place)
            atomic_write(root / ".env", env_copy.read_bytes())
        finally:
            shutil.rmtree(scratch, ignore_errors=True)

    def verify_rollback(self) -> list[Check]:
        checks: list[Check] = []
        snapshot = self.journal.data.get("snapshot", {})

        def add(name: str, function: Callable[[], str]) -> None:
            try:
                checks.append(Check(name, True, function()))
            except ConvertError as error:
                checks.append(Check(name, False, str(error)))

        add("api-health", self.system.api_health)

        def edition() -> str:
            value = self.system.capabilities().get("edition")
            if value != "open":
                raise ConvertError(f"nano-api reports the {value} edition")
            return "nano-api reports open"
        add("edition", edition)

        def migrations() -> str:
            pg = self.system.pg_enterprise_migrations()
            ch = self.system.ch_enterprise_migrations()
            if pg or ch:
                raise ConvertError(
                    f"enterprise migrations are still recorded: {pg} in PostgreSQL _sqlx_migrations, "
                    f"{ch} in the ClickHouse ledger"
                )
            return "no enterprise migration left in PostgreSQL or the ClickHouse ledger"
        add("migrations", migrations)

        def records() -> str:
            before = snapshot.get("pg_counts", {})
            after = self.system.pg_counts()
            for table, old in before.items():
                new = after.get(table)
                if old is not None and (new is None or new < old):
                    raise ConvertError(f"{table}: {old} rows before the conversion, {new} now")
            return "no PostgreSQL table has fewer rows than before the conversion"
        add("records", records)

        def events() -> str:
            result = self.events_unchanged()
            leftover = self.system.ch_enterprise_objects()
            return result + (
                f"; enterprise ClickHouse objects left in place (unused by open): {', '.join(leftover)}"
                if leftover else "")
        add("events", events)
        return checks


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def parse_args(argv: Sequence[str]) -> Options:
    parser = argparse.ArgumentParser(
        prog="scripts/nano convert",
        description="Convert this open install to enterprise (Self-run), same release, keeping all data.",
    )
    parser.add_argument("--to", choices=["enterprise"])
    parser.add_argument("--package", type=pathlib.Path, help="nano-compose-enterprise-<version>.tar.gz (.sha256 and .sha256.sig beside it)")
    parser.add_argument("--backup-key-file", type=pathlib.Path)
    parser.add_argument("--backup-output", type=pathlib.Path, help="directory outside the install for the backup and rollback material")
    license_group = parser.add_mutually_exclusive_group()
    license_group.add_argument("--license-env-file", type=pathlib.Path,
                               help="0600 file with LICENSE_URL, LICENSE_TOKEN and NANO_DEPLOYMENT_ID lines")
    license_group.add_argument("--license-file", type=pathlib.Path, help="offline license JSON file")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--rollback", action="store_true")
    parser.add_argument("--backup", type=pathlib.Path, help="with --rollback: the nano backup to restore PostgreSQL from")
    parser.add_argument("--probe-ingest", action="store_true", help="also send one event through the ingest edge")
    parser.add_argument("--ack-postgres-data-loss", action="store_true",
                        help="with --rollback after the enterprise release ran: accept losing PostgreSQL changes "
                             "made since the conversion's backup")
    parser.add_argument("--license-wait", type=int, default=300, help="seconds to wait for the first license check-in")
    parser.add_argument("--install-dir", type=pathlib.Path, default=DEFAULT_INSTALL_DIR)
    args = parser.parse_args(argv)
    modes = sum([args.dry_run, args.resume, args.rollback])
    if modes > 1:
        parser.error("--dry-run, --resume and --rollback are exclusive")
    if not args.rollback and not args.resume and args.to != "enterprise":
        parser.error("--to enterprise is required")
    if (args.backup or args.ack_postgres_data_loss) and not args.rollback:
        parser.error("--backup and --ack-postgres-data-loss are only for --rollback")
    lic: License | None = None
    try:
        if args.license_env_file:
            lic = load_license_env_file(args.license_env_file)
        elif args.license_file:
            lic = load_offline_license(args.license_file)
    except ConvertError as error:
        parser.error(str(error))
    install_dir = args.install_dir.resolve()
    return Options(
        install_dir=install_dir, package=args.package.resolve() if args.package else None,
        backup_key_file=args.backup_key_file.resolve() if args.backup_key_file else None,
        backup_output=args.backup_output, license=lic, dry_run=args.dry_run, resume=args.resume,
        rollback=args.rollback, backup=args.backup.resolve() if args.backup else None,
        probe_ingest=args.probe_ingest, license_wait=max(0, args.license_wait),
        ack_postgres_data_loss=args.ack_postgres_data_loss,
    )


def main(argv: Sequence[str] | None = None) -> int:
    # scripts/nano runs with umask 077; the release files extracted here are
    # bind-mounted into non-root containers and must stay readable (install.sh
    # uses 022 for the same reason). Secret files are created 0600 explicitly.
    os.umask(0o022)
    options = parse_args(list(sys.argv[1:] if argv is None else argv))
    try:
        return Converter(options).run()
    except ConvertError as error:
        print(f"nano convert: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("nano convert: interrupted; run scripts/nano convert --resume or --rollback", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
