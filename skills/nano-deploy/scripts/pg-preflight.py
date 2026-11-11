#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Read-only check that an external PostgreSQL can host nano.

Run it before `helm install` (or before a Compose install with an external
PostgreSQL) when the database is reachable. It checks what the migrator's own
preflight checks, but before anything is deployed:

  version    PostgreSQL 16 or newer.
  platform   RDS / Cloud SQL / Azure flexible server / other (for the fix text).
  schema     the nano user can CREATE in schema `public`. PostgreSQL 15+ no
             longer grants that to every role, and Azure flexible server makes
             azure_pg_admin the owner of `public` in new databases, so the
             first migration fails with "permission denied for schema public".
  extensions pg_trgm, pgcrypto and uuid-ossp are installed or the nano user can
             create them. Each CREATE EXTENSION runs in a transaction that is
             rolled back: nothing is installed or changed.

Two ways to reach the database (standard library only, no password on any
command line):

  # From inside the cluster (reaches private-IP databases). A one-shot pod
  # reads the password from the same Secret the chart uses:
  python3 -I scripts/pg-preflight.py kube --namespace nano \\
      --host DB_HOST --user nanosiem --database nanosiem \\
      --password-secret nano-pg --password-key password
  # or with a full DATABASE_URL Secret (postgresql.external.urlSecret):
  python3 -I scripts/pg-preflight.py kube --namespace nano --url-secret nano-pg-url --url-key database_url

  # From this machine with psql; the password comes from PGPASSWORD or
  # ~/.pgpass that the operator set, never from an argument:
  python3 -I scripts/pg-preflight.py local --host DB_HOST --user nanosiem --database nanosiem

Exit 0 = ready, 1 = a check failed (the fix is printed), 2 = could not run.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import subprocess
import sys

MIN_VERSION_NUM = 160000
MIN_VERSION = "16"
REQUIRED_EXTENSIONS = ("pg_trgm", "pgcrypto", "uuid-ossp")
# The chart's bundled PostgreSQL image (values.yaml images.postgres): it has psql.
DEFAULT_IMAGE = "postgres:17"

PROBE_SQL = """\\set ON_ERROR_STOP 1
SELECT 'NANO_VERSION ' || current_setting('server_version_num') || ' ' || current_setting('server_version');
SELECT 'NANO_PLATFORM ' || CASE
  WHEN current_setting('azure.extensions', true) IS NOT NULL
    OR EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'azure_pg_admin') THEN 'azure'
  WHEN current_setting('rds.extensions', true) IS NOT NULL
    OR EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rds_superuser') THEN 'rds'
  WHEN EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cloudsqlsuperuser') THEN 'cloudsql'
  ELSE 'other' END;
SELECT 'NANO_AZURE_EXTENSIONS ' || coalesce(current_setting('azure.extensions', true), '');
SELECT 'NANO_SCHEMA ' || coalesce((SELECT CASE WHEN has_schema_privilege(current_user, n.oid, 'CREATE')
         THEN 'create' ELSE 'nocreate' END || '|' || quote_ident(pg_get_userbyid(n.nspowner)::text)
       FROM pg_namespace n WHERE n.nspname = 'public'), 'absent|')
  || '|' || quote_ident(current_user::text) || '|' || quote_ident(current_database()::text);
BEGIN;
DO $nano$
DECLARE e text;
BEGIN
  FOREACH e IN ARRAY ARRAY[%(exts)s] LOOP
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = e) THEN
      RAISE NOTICE 'NANO_EXT %%|installed|', e;
      CONTINUE;
    END IF;
    BEGIN
      EXECUTE format('CREATE EXTENSION IF NOT EXISTS %%I WITH SCHEMA public', e);
      RAISE NOTICE 'NANO_EXT %%|creatable|', e;
    EXCEPTION WHEN others THEN
      RAISE NOTICE 'NANO_EXT %%|missing|%%', e, replace(SQLERRM, chr(10), ' ');
    END;
  END LOOP;
END
$nano$;
ROLLBACK;
SELECT 'NANO_DONE';
""" % {"exts": ", ".join("'%s'" % e for e in REQUIRED_EXTENSIONS)}

# Runs inside the probe pod (dash). Splits the DATABASE_URL from the Secret into
# libpq environment variables with shell builtins only, so the URL and its
# password never appear on any process's argv (psql "$URL" would). The chart
# requires URL-safe passwords, so no percent-decoding is needed.
URL_TO_PGENV_SH = r"""set -eu
u=${NANO_PG_URL#*://}
unset NANO_PG_URL
case $u in *@*) creds=${u%%@*}; u=${u#*@} ;; *) creds= ;; esac
if [ -n "$creds" ]; then
  PGUSER=${creds%%:*}; export PGUSER
  case $creds in *:*) PGPASSWORD=${creds#*:}; export PGPASSWORD ;; esac
fi
case $u in *\?*) q=${u#*\?}; u=${u%%\?*} ;; *) q= ;; esac
case $u in */*) PGDATABASE=${u#*/}; export PGDATABASE; u=${u%%/*} ;; esac
case $u in *:*) PGPORT=${u##*:}; export PGPORT; u=${u%:*} ;; esac
PGHOST=$u; export PGHOST
for kv in $(printf '%s' "$q" | tr '&' ' '); do
  case $kv in sslmode=*) PGSSLMODE=${kv#sslmode=}; export PGSSLMODE ;; esac
done
exec psql -X -q -A -t -f -
"""

FIXES = {
    "azure": "Azure flexible server: add them to the `azure.extensions` server parameter, e.g.\n"
             "    az postgres flexible-server parameter set -g RG -s SERVER --name azure.extensions "
             "--value <existing>," + ",".join(REQUIRED_EXTENSIONS) + "\n"
             "  (keep any values already there). It applies without a restart.",
    "cloudsql": "Cloud SQL: no database flags are needed for these extensions. Connect as a user "
                "created through Cloud SQL (gcloud sql users create: member of cloudsqlsuperuser) with CREATE on "
                "the database; roles created with CREATE ROLE in SQL cannot create extensions.",
    "rds": "Amazon RDS: if the DB parameter group sets `rds.allowed_extensions`, add "
           + ",".join(REQUIRED_EXTENSIONS) + " (the default `*` allows them). The user needs CREATE "
           "on the database.",
    "other": "Self-managed PostgreSQL: install postgresql-contrib and grant the nano user CREATE on "
             "the database, or have a superuser run CREATE EXTENSION for each one first.",
}


ADMIN_BY_PLATFORM = {
    "azure": "the server admin user",
    "cloudsql": "the postgres user",
    "rds": "the master user",
    "other": "a superuser or the schema owner",
}


def schema_fix(platform: str, schema: dict) -> str:
    user = schema.get("user") or "<nano user>"
    db = schema.get("database") or "<nano database>"
    admin = ADMIN_BY_PLATFORM.get(platform, ADMIN_BY_PLATFORM["other"])
    if schema.get("state") == "absent":
        return (f"database {db} has no schema public. As {admin}, connected to database {db}, run:\n"
                f"    CREATE SCHEMA public AUTHORIZATION {user};")
    return (f"as {admin}, connected to database {db} (psql -d {db}), run:\n"
            f"    ALTER SCHEMA public OWNER TO {user};\n"
            f"  or, to keep the current owner:\n"
            f"    GRANT ALL ON SCHEMA public TO {user};\n"
            f"  (ALTER SCHEMA ... OWNER needs the admin to be a member of {user}: GRANT {user} TO <admin>.)")


def parse_probe(output: str) -> dict:
    """Parse the probe's tagged lines (stdout and NOTICE lines on stderr mixed)."""
    result = {"version_num": None, "version": "", "platform": "other", "extensions": {},
              "azure_extensions": None, "schema": None, "done": False}
    for raw in output.splitlines():
        line = raw.strip()
        idx = line.find("NANO_")
        if idx < 0:
            continue
        line = line[idx:]
        if line.startswith("NANO_VERSION "):
            parts = line.split(" ", 2)
            try:
                result["version_num"] = int(parts[1])
            except (IndexError, ValueError):
                pass
            result["version"] = parts[2] if len(parts) > 2 else ""
        elif line.startswith("NANO_PLATFORM "):
            result["platform"] = line.split(" ", 1)[1].strip() or "other"
        elif line.startswith("NANO_AZURE_EXTENSIONS"):
            result["azure_extensions"] = line[len("NANO_AZURE_EXTENSIONS"):].strip()
        elif line.startswith("NANO_SCHEMA "):
            parts = (line[len("NANO_SCHEMA "):].split("|") + ["", "", "", ""])[:4]
            result["schema"] = {"state": parts[0].strip(), "owner": parts[1].strip(),
                                "user": parts[2].strip(), "database": parts[3].strip()}
        elif line.startswith("NANO_EXT "):
            name, _, rest = line[len("NANO_EXT "):].partition("|")
            state, _, reason = rest.partition("|")
            result["extensions"][name.strip()] = (state.strip(), reason.strip())
        elif line.startswith("NANO_DONE"):
            result["done"] = True
    return result


def evaluate(result: dict) -> tuple[list[tuple[str, bool | None, str]], bool]:
    """Rows (check, ok, detail) and whether every hard check passed."""
    rows: list[tuple[str, bool | None, str]] = []
    vnum = result.get("version_num")
    if vnum is None:
        rows.append(("version", False, "could not read server_version_num (connection or permission failure)"))
        return rows, False
    rows.append(("version", vnum >= MIN_VERSION_NUM,
                 f"PostgreSQL {result.get('version') or vnum}"
                 + ("" if vnum >= MIN_VERSION_NUM else f": nano needs {MIN_VERSION} or newer")))
    platform = result.get("platform") or "other"
    rows.append(("platform", None if platform == "other" else True, platform))
    schema = result.get("schema")
    if not schema:
        rows.append(("schema", False, "probe did not report CREATE on schema public"))
    elif schema["state"] == "create":
        rows.append(("schema", True, f"{schema['user']} can CREATE in public (owner {schema['owner']})"))
    else:
        detail = ("schema public does not exist" if schema["state"] == "absent" else
                  f"{schema['user']} cannot CREATE in schema public (owner {schema['owner']}); "
                  "the first migration would fail with 'permission denied for schema public'")
        rows.append(("schema", False, detail))
        rows.append(("fix", False, schema_fix(platform, schema)))
    exts = result.get("extensions", {})
    missing = []
    for ext in REQUIRED_EXTENSIONS:
        state, reason = exts.get(ext, ("unknown", "probe did not report this extension"))
        if state in ("installed", "creatable"):
            rows.append(("extension", True, f"{ext}: {state}"))
        else:
            missing.append(ext)
            rows.append(("extension", False, f"{ext}: {reason or state}"))
    if missing:
        order = [platform] + [p for p in ("azure", "cloudsql", "rds", "other") if p != platform]
        rows.append(("fix", False, "missing " + ", ".join(missing) + ". " + FIXES.get(order[0], FIXES["other"])))
        if platform == "azure" and result.get("azure_extensions") is not None:
            rows.append(("fix", None, f"current azure.extensions = '{result['azure_extensions']}'"))
    ok = all(r[1] is not False for r in rows)
    return rows, ok


def run_local(a: argparse.Namespace) -> tuple[int, str]:
    env = dict(os.environ)
    for flag, var in (("host", "PGHOST"), ("port", "PGPORT"), ("user", "PGUSER"),
                      ("database", "PGDATABASE"), ("sslmode", "PGSSLMODE")):
        value = getattr(a, flag)
        if value:
            env[var] = str(value)
    proc = subprocess.run(["psql", "-X", "-q", "-A", "-t", "-f", "-"], input=PROBE_SQL,
                          capture_output=True, text=True, env=env, timeout=120)
    return proc.returncode, proc.stdout + "\n" + proc.stderr


def kube_pod_overrides(a: argparse.Namespace, name: str) -> dict:
    env = [{"name": "PGCONNECT_TIMEOUT", "value": "15"}]
    if a.url_secret:
        env.append({"name": "NANO_PG_URL",
                    "valueFrom": {"secretKeyRef": {"name": a.url_secret, "key": a.url_key}}})
        command = ["sh", "-c", URL_TO_PGENV_SH]
    else:
        env += [{"name": "PGHOST", "value": a.host}, {"name": "PGPORT", "value": str(a.port)},
                {"name": "PGUSER", "value": a.user}, {"name": "PGDATABASE", "value": a.database},
                {"name": "PGSSLMODE", "value": a.sslmode},
                {"name": "PGPASSWORD",
                 "valueFrom": {"secretKeyRef": {"name": a.password_secret, "key": a.password_key}}}]
        command = ["psql", "-X", "-q", "-A", "-t", "-f", "-"]
    container = {"name": name, "image": a.image, "command": command, "stdin": True, "stdinOnce": True,
                 "env": env,
                 "securityContext": {"runAsNonRoot": True, "runAsUser": 999, "allowPrivilegeEscalation": False,
                                     "capabilities": {"drop": ["ALL"]}}}
    return {"apiVersion": "v1", "spec": {"restartPolicy": "Never", "containers": [container]}}


def run_kube(a: argparse.Namespace) -> tuple[int, str]:
    if not a.url_secret and not (a.host and a.password_secret):
        raise SystemExit("kube mode needs --url-secret, or --host and --password-secret")
    name = "nano-pg-preflight-" + secrets.token_hex(3)
    base = ["kubectl"] + (["--context", a.context] if a.context else []) + ["-n", a.namespace]
    cmd = base + ["run", name, "--rm", "-i", "--quiet", "--restart=Never", f"--image={a.image}",
                  f"--overrides={json.dumps(kube_pod_overrides(a, name))}", "--pod-running-timeout=3m"]
    try:
        proc = subprocess.run(cmd, input=PROBE_SQL, capture_output=True, text=True, timeout=300)
    finally:
        # `--rm` does not run when kubectl is killed (timeout) or loses the
        # attach; never leave a probe pod behind.
        subprocess.run(base + ["delete", "pod", name, "--ignore-not-found", "--wait=false"],
                       capture_output=True, text=True, timeout=60)
    return proc.returncode, proc.stdout + "\n" + proc.stderr


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="mode", required=True)
    for mode in ("local", "kube"):
        p = sub.add_parser(mode)
        # local: unset flags fall back to the operator's PG* environment.
        kube = mode == "kube"
        p.add_argument("--host")
        p.add_argument("--port", type=int, default=5432 if kube else None)
        p.add_argument("--user", default="nanosiem" if kube else None)
        p.add_argument("--database", default="nanosiem" if kube else None)
        p.add_argument("--sslmode", default="require" if kube else None)
        if mode == "kube":
            p.add_argument("--namespace", "-n", default="nano")
            p.add_argument("--context")
            p.add_argument("--password-secret", help="Secret holding the password (postgresql.external.passwordSecret)")
            p.add_argument("--password-key", default="password")
            p.add_argument("--url-secret", help="Secret holding a full DATABASE_URL (postgresql.external.urlSecret)")
            p.add_argument("--url-key", default="database_url")
            p.add_argument("--image", default=DEFAULT_IMAGE, help="image with psql (a mirror in air-gapped installs)")
    a = ap.parse_args()
    try:
        rc, output = run_kube(a) if a.mode == "kube" else run_local(a)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        print(f"could not run the probe: {exc}", file=sys.stderr)
        return 2
    result = parse_probe(output)
    if result["version_num"] is None:
        tail = " ".join(l for l in output.splitlines() if l.strip() and "NANO_" not in l)[-400:]
        print(f"FAIL connect     could not query PostgreSQL (exit {rc}): {tail}")
        return 2
    rows, ok = evaluate(result)
    for check, good, detail in rows:
        status = "PASS" if good else ("WARN" if good is None else "FAIL")
        print(f"{status:<4} {check:<10} {detail}")
    print("POSTGRES-READY" if ok else "POSTGRES-NOT-READY")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
