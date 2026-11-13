"""Offline C05 trial license for enterprise e2e stacks (NAN-5331).

An offline C05 license is bound to the installation identity
(installation_id, organization_id) in PostgreSQL's singleton
`sovereign_license_installation` row. The enterprise overlay migration
(9000087) creates that row with random UUIDs, so every `--fresh` stack would
need its own license. Two env vars let one trial license serve every run:

- `NANO_E2E_INSTALLATION_ID` + `NANO_E2E_INSTALLATION_ORG_ID`: the runner
  replaces the migration-generated identity with this one AFTER the migrator
  and BEFORE any app process starts (`seed_sql`). Nothing else is derived from
  the row: the fingerprint is computed from the two ids on every read, and the
  only identity-bound state (`sovereign_license_state`, the audit ledger, the
  ClickHouse clock witness) does not exist until a license is imported. The
  update therefore refuses to run once any license state or audit row exists,
  and re-running it with the same identity is a no-op.
- `NANO_E2E_C05_LICENSE_FILE`: after the stack is healthy and the admin
  exists, the runner imports the file through `POST /api/license/import` and
  fails unless `GET /api/license` then reports an active license
  (`import_license`).

The license file's contents are never printed, logged, journaled or copied:
they are read only to send them to the API, and the artifact guard scrubs
them by reading the same file (`artifact_guard scrub --secret-file`).

Stdlib only: the runner calls it with the system python3, and pytest's
deferred first-run setup imports it too.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
# Same bound as nanosiem-enterprise `MAX_LICENSE_BYTES`.
MAX_LICENSE_BYTES = 256 * 1024
ENV_INSTALLATION = "NANO_E2E_INSTALLATION_ID"
ENV_ORGANIZATION = "NANO_E2E_INSTALLATION_ORG_ID"
ENV_LICENSE_FILE = "NANO_E2E_C05_LICENSE_FILE"


class LicenseError(RuntimeError):
    """A configuration or import failure. Messages never carry file contents."""


# ---------------------------------------------------------------- configuration
def pinned_identity(environ: dict[str, str] | None = None) -> tuple[str, str] | None:
    """The pinned (installation_id, organization_id), or None when unset.

    Both or neither; each must satisfy the product's identifier CHECK."""
    env = os.environ if environ is None else environ
    iid = env.get(ENV_INSTALLATION, "")
    oid = env.get(ENV_ORGANIZATION, "")
    if not iid and not oid:
        return None
    if not iid or not oid:
        raise LicenseError(f"{ENV_INSTALLATION} and {ENV_ORGANIZATION} must be set together")
    for name, value in ((ENV_INSTALLATION, iid), (ENV_ORGANIZATION, oid)):
        if not IDENTIFIER.fullmatch(value):
            raise LicenseError(f"{name} must match ^[a-z0-9][a-z0-9_-]{{0,63}}$")
    return iid, oid


def read_license_file(path: str | os.PathLike[str], repo_root: str | os.PathLike[str] | None = None) -> bytes:
    """Read the license file after checking it is private: a regular file (no
    symlink), owned by this user, mode 0600 or stricter, 1..256 KiB, and not
    inside the repository checkout (it must never be committed)."""
    p = Path(path)
    if not p.is_absolute():
        raise LicenseError(f"{ENV_LICENSE_FILE} must be an absolute path")
    if repo_root is not None:
        real = Path(os.path.realpath(p))
        root = Path(os.path.realpath(repo_root))
        if real == root or root in real.parents:
            raise LicenseError(f"{ENV_LICENSE_FILE} must live outside the repository checkout")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(p, flags)
    except OSError as exc:
        raise LicenseError(f"{ENV_LICENSE_FILE} cannot be opened: {exc.strerror}") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise LicenseError(f"{ENV_LICENSE_FILE} must be a regular file")
        if info.st_uid != os.getuid():
            raise LicenseError(f"{ENV_LICENSE_FILE} must be owned by the current user")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise LicenseError(f"{ENV_LICENSE_FILE} must have mode 0600 (chmod 600 <file>)")
        if not 0 < info.st_size <= MAX_LICENSE_BYTES:
            raise LicenseError(f"{ENV_LICENSE_FILE} must be 1 to {MAX_LICENSE_BYTES} bytes")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            data = handle.read(MAX_LICENSE_BYTES + 1)
    finally:
        os.close(fd)
    if not data or len(data) > MAX_LICENSE_BYTES:
        raise LicenseError(f"{ENV_LICENSE_FILE} must be 1 to {MAX_LICENSE_BYTES} bytes")
    return data


# ---------------------------------------------------------------- seeding
# psql script; the ids arrive as psql variables (`-v iid=... -v oid=...`) and
# are quoted by psql (:'var'), never interpolated by the harness. One
# transaction: the lock keeps an import from racing the guard, and the
# guard refuses to rebind an installation that already holds license state or
# ledger rows (that would orphan them against the new fingerprint).
SEED_SQL = """\\set ON_ERROR_STOP on
BEGIN;
LOCK TABLE sovereign_license_installation, sovereign_license_state, sovereign_license_audit
    IN SHARE ROW EXCLUSIVE MODE;
UPDATE sovereign_license_installation
   SET installation_id = :'iid', organization_id = :'oid'
 WHERE singleton = TRUE
   AND (installation_id, organization_id) IS DISTINCT FROM (:'iid', :'oid')
   AND NOT EXISTS (SELECT 1 FROM sovereign_license_state)
   AND NOT EXISTS (SELECT 1 FROM sovereign_license_audit);
SELECT installation_id || '|' || organization_id || '|' ||
       (EXISTS (SELECT 1 FROM sovereign_license_state))::text
  FROM sovereign_license_installation WHERE singleton = TRUE;
COMMIT;
"""

# Read-only identity query for `scripts/e2e.sh license-ids`.
IDS_SQL = """\\set ON_ERROR_STOP on
BEGIN READ ONLY;
SELECT installation_id || '|' || organization_id || '|' ||
       (EXISTS (SELECT 1 FROM sovereign_license_state))::text
  FROM sovereign_license_installation WHERE singleton = TRUE;
COMMIT;
"""


@dataclass(frozen=True)
class IdentityRow:
    installation_id: str
    organization_id: str
    licensed: bool


def parse_identity_row(output: str) -> IdentityRow:
    """Parse the single `iid|oid|true|false` line the SQL above prints."""
    lines = [line for line in output.splitlines() if line.strip()]
    if len(lines) != 1:
        raise LicenseError("sovereign_license_installation singleton is missing or ambiguous")
    parts = lines[0].strip().split("|")
    if len(parts) != 3 or parts[2] not in ("true", "false"):
        raise LicenseError("unexpected sovereign_license_installation row shape")
    iid, oid, licensed = parts
    if not IDENTIFIER.fullmatch(iid) or not IDENTIFIER.fullmatch(oid):
        raise LicenseError("sovereign_license_installation holds an invalid identifier")
    return IdentityRow(iid, oid, licensed == "true")


def check_seeded(output: str, want: tuple[str, str]) -> IdentityRow:
    """The row after SEED_SQL must equal the pinned identity; otherwise the
    guard refused (a license or ledger already exists for another identity)."""
    row = parse_identity_row(output)
    if (row.installation_id, row.organization_id) != want:
        raise LicenseError(
            "installation identity NOT pinned: this stack already holds license state "
            f"for installation {row.installation_id} (org {row.organization_id}); "
            "use a --fresh stack"
        )
    return row


# ---------------------------------------------------------------- import
def _request(method: str, url: str, api_key: str, body: bytes | None = None) -> tuple[int, dict]:
    if not url.startswith(("http://", "https://")):
        raise LicenseError("the API URL must be http(s)")
    headers = {"X-API-Key": api_key, "Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, method=method, headers=headers)  # noqa: S310 - scheme checked
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 - loopback stack URL
            status, raw = resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read()
    try:
        doc = json.loads(raw or b"{}")
    except ValueError:
        doc = {}
    return status, doc if isinstance(doc, dict) else {}


def _error_message(doc: dict) -> str:
    err = doc.get("error")
    msg = err.get("message") if isinstance(err, dict) else err
    return str(msg or "")[:300]


def verify_status(status: dict, want: tuple[str, str] | None) -> None:
    """GET /api/license must report an active, valid, offline C05 license
    (bound to the pinned identity when one is pinned)."""
    if status.get("valid") is not True or status.get("state") != "active":
        raise LicenseError(
            "license NOT active after import: "
            f"state={status.get('state')!r} valid={status.get('valid')!r} "
            f"reason={status.get('locked_reason') or status.get('notice')!r}"
        )
    if status.get("mode") != "offline":
        raise LicenseError(f"license mode is {status.get('mode')!r}, expected 'offline'")
    if want and (status.get("installation_id"), status.get("organization_id")) != want:
        raise LicenseError("active license reports a different installation identity than the pinned one")


def import_license(
    api_url: str,
    api_key: str,
    license_file: str,
    *,
    repo_root: str | None = None,
    want: tuple[str, str] | None = None,
) -> dict:
    """Import the license as admin, then require an active license. Returns
    the GET /api/license document (no license contents in it)."""
    artifact = read_license_file(license_file, repo_root)
    base = api_url.rstrip("/")
    code, doc = _request("POST", f"{base}/api/license/import", api_key, artifact)
    del artifact
    if code != 200:
        raise LicenseError(f"POST /api/license/import -> {code}: {_error_message(doc)}")
    code, status = _request("GET", f"{base}/api/license", api_key)
    if code != 200:
        raise LicenseError(f"GET /api/license -> {code}: {_error_message(status)}")
    verify_status(status, want)
    return status


def import_from_env(api_url: str, api_key: str, edition: str) -> dict | None:
    """Import NANO_E2E_C05_LICENSE_FILE when set on an enterprise stack."""
    path = os.environ.get(ENV_LICENSE_FILE, "")
    if not path or edition != "enterprise":
        return None
    return import_license(api_url, api_key, path, want=pinned_identity())


def _summary(status: dict) -> str:
    return (
        f"C05 license active: license_id={status.get('license_id')} "
        f"type={status.get('license_type')} expires_at={status.get('expires_at')} "
        f"installation_id={status.get('installation_id')}"
    )


# ---------------------------------------------------------------- CLI
IMPORT_HELP = "import NANO_E2E_C05_LICENSE_FILE as admin (E2E_API_URL, E2E_ADMIN_ENV)"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="nano_e2e.c05_license")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check-env", help="validate the NANO_E2E_* license env (no side effects)")
    c.add_argument("--repo-root", required=True)
    sub.add_parser("seed-sql", help="print the identity seeding psql script")
    sub.add_parser("ids-sql", help="print the read-only identity psql script")
    sub.add_parser("check-seeded", help="verify SEED_SQL output (stdin) against the pinned identity")
    sub.add_parser("parse-ids", help="print installation/organization ids from IDS_SQL output (stdin)")
    imp = sub.add_parser("import", help=IMPORT_HELP)
    imp.add_argument("--repo-root", required=True)
    a = ap.parse_args(argv)
    try:
        if a.cmd == "check-env":
            pinned_identity()
            path = os.environ.get(ENV_LICENSE_FILE, "")
            if path:
                read_license_file(path, a.repo_root)
        elif a.cmd == "seed-sql":
            sys.stdout.write(SEED_SQL)
        elif a.cmd == "ids-sql":
            sys.stdout.write(IDS_SQL)
        elif a.cmd == "check-seeded":
            want = pinned_identity()
            if want is None:
                raise LicenseError("no pinned identity")
            check_seeded(sys.stdin.read(), want)
        elif a.cmd == "parse-ids":
            row = parse_identity_row(sys.stdin.read())
            print(f"installation_id={row.installation_id}")
            print(f"organization_id={row.organization_id}")
            print(f"license_installed={'yes' if row.licensed else 'no'}")
        elif a.cmd == "import":
            key = ""
            for line in Path(os.environ["E2E_ADMIN_ENV"]).read_text().splitlines():
                if line.startswith("NANOSIEM_API_KEY="):
                    key = line.partition("=")[2]
            if not key:
                raise LicenseError("admin API key missing from admin.env")
            status = import_license(
                os.environ["E2E_API_URL"],
                key,
                os.environ[ENV_LICENSE_FILE],
                repo_root=a.repo_root,
                want=pinned_identity(),
            )
            print(_summary(status), file=sys.stderr)
    except LicenseError as exc:
        print(f"E2E-LICENSE: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
