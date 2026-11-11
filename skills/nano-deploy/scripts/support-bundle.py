#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""nano support bundle: one redacted .tar.gz for nano support.

  scripts/nano support-bundle [--since 24h] [--max-log-mb 20] [--out-dir DIR]
                              [--inventory FILE] [--remote-install-dir DIR] [--local-only]
  python3 nano/scripts/nano-support-bundle --kubernetes [--namespace nano]
                              [--release nano] [--context CTX] [--since 24h]

Compose (single node or role split): run it on ANY one host of the install.
On a role-split cluster it reads the host inventory (--inventory, default
/etc/nano/inventory.yaml) and collects every other host over SSH, the same
BatchMode SSH that `scripts/nano backup-set` uses: this script is streamed to
each host on stdin, so the other hosts need only python3. Helm: run it from
any machine with kubectl (and helm) access to the release's namespace.

Collected: versions and release markers, the install ID, host facts, clock
skew between hosts, disk and mount state (whether data directories are
mountpoints), Compose service state and health, cluster-health output, Patroni
/ etcd / Sentinel / Valkey roles, HAProxy backend states, ClickHouse
diagnostics (recent system.errors, replication queue, read-only replicas,
parts counts, disks, mutations, dictionaries), Vector component errors and
buffer metrics, the nano services' own logs since --since (size-capped),
recent configuration-change audit entries (action and object only), and, on
Helm, pods, events, describe output, logs and the release values.

NEVER collected: event data, raw logs your sources sent to nano, search or
query results, .env values of secret keys, private keys, license files.

Every file is redacted before it is written (secret .env values, tokens,
JWTs, PEM blocks, passwords in URLs, the license token, Authorization and
Cookie headers, key=value secrets, ingest tokens). Logs of the ingest data
plane (Vector, ClickHouse, Tenzir, connector-runner) keep warning and error
lines only, with payload fragments removed; in nano's own service logs, quoted
SQL literals in database errors and search text in request URIs are removed
(search terms are customer data). The archive is mode 0600: review
it before you send it (`tar -xzf FILE -O | less`).
"""
from __future__ import annotations

import argparse
import contextlib
import datetime as _dt
import hashlib
import io
import json
import os
import re
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request

TOOL_VERSION = "1"
DEFAULT_SINCE = "24h"
DEFAULT_MAX_LOG_MB = 20
DEFAULT_INVENTORY = "/etc/nano/inventory.yaml"
SSH_HOST_TIMEOUT = 900

# --------------------------------------------------------------------------------------------
# Redaction
# --------------------------------------------------------------------------------------------

# .env / env keys whose VALUES are secret. Keys with a descriptive suffix (a mode, a path, an
# id, a port) are not, even when they contain a secret-looking word (NANO_LICENSE_MODE).
SECRET_KEY_RE = re.compile(
    r"(PASSWORD|PASSWD|PASSPHRASE|_PASS$|^PASS_|TOKEN|SECRET|_KEY$|_KEY_|APIKEY|API_KEY|PRIVATE"
    r"|CREDENTIAL|COOKIE|SALT|DSN|AUTH|LICEN[CS]E$|SIGNING|ENCRYPTION|WEBHOOK)",
    re.I,
)
NON_SECRET_SUFFIX_RE = re.compile(
    r"_(MODE|FILE|PATH|DIR|ENABLED|ENABLE|REQUIRED|ID|GID|UID|PORT|HOST|USER|USERNAME|TTL|DAYS"
    r"|SECONDS|EXPIRY|ALGORITHM|TYPE|NAME|URL_ALLOWLIST|STRICT|PROVIDER|ISSUER|AUDIENCE)$",
    re.I,
)

_KV_WORDS = (
    r"password|passwd|passphrase|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key"
    r"|client[_-]?secret|credential|cookie|session[_-]?id|licen[cs]e|signature|x-api-key"
)
PATTERNS = [
    # PEM blocks (keys, certificates, CSRs), and a private key cut off before its END line.
    (re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----[\s\S]*?-----END \1-----"), r"[REDACTED:PEM \1]"),
    (re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----(?:\s*[A-Za-z0-9+/=]{8,})*"), "[REDACTED:PEM PRIVATE KEY]"),
    # JSON Web Tokens.
    (re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"), "[REDACTED:JWT]"),
    # Authorization / Proxy-Authorization headers with any scheme (Bearer, Basic, HEC schemes).
    (re.compile(r"(?i)(\b(?:proxy-)?authorization\b[\"']?\s*[:=]\s*[\"']?)(?:[A-Za-z][A-Za-z0-9_-]*\s+)?(?!\[REDACTED)[^\s\"',;]+"),
     r"\1[REDACTED]"),
    (re.compile(r"(?i)\bbearer\s+(?!\[REDACTED)[A-Za-z0-9._~+/=-]{8,}"), "Bearer [REDACTED]"),
    (re.compile(r"(?i)(\b(?:set-)?cookie\b[\"']?\s*[:=]\s*)[^\r\n]+"), r"\1[REDACTED]"),
    # Credentials in URLs: scheme://user:password@host.
    (re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)([^:/@\s\"']*):(?!\[REDACTED)([^@/\s\"']+)@"), r"\1\2:[REDACTED]@"),
    # Secrets in query strings.
    (re.compile(r"(?i)([?&](?:token|access_token|id_token|refresh_token|api_key|apikey|key|sig|signature"
                r"|password|code|client_secret|x-amz-signature|x-amz-credential|sv|se)=)(?!\[REDACTED)[^&\s\"'#]+"),
     r"\1[REDACTED]"),
    # key=value / "key": "value" / `KEY:  value` pairs whose key names a secret: see _kv_sub.
    (re.compile(r"(?i)([A-Za-z0-9_.-]*(?:" + _KV_WORDS + r")[A-Za-z0-9_.-]*)([\"']?[ \t]*[:=][ \t]*)"
                r"(\"(?:[^\"\\\r\n]|\\.)*\"?|'[^'\r\n]*'?|[^\s\"'][^\r\n\t&]*)"), None),
    # Well-known token shapes.
    (re.compile(r"\bnit_[A-Za-z0-9_-]{8,}"), "[REDACTED:INGEST_TOKEN]"),
    (re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "[REDACTED:AWS_KEY_ID]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"), "[REDACTED:GITHUB_TOKEN]"),
    (re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}"), "[REDACTED:CHAT_TOKEN]"),
    (re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_-]{20,}"), "[REDACTED:AI_KEY]"),
]


def is_secret_key(key: str) -> bool:
    return bool(SECRET_KEY_RE.search(key)) and not NON_SECRET_SUFFIX_RE.search(key)


def _kv_sub(m) -> str:
    """Redact a secret-keyed value to its END: a quoted value whole (quotes kept),
    an unquoted one to the end of the line or tab-separated field."""
    key, sep, value = m.group(1), m.group(2), m.group(3)
    if NON_SECRET_SUFFIX_RE.search(key) or value.lstrip("\"'").startswith("[REDACTED"):
        return m.group(0)
    if value[0] in "\"'":
        return f"{key}{sep}{value[0]}[REDACTED]{value[0]}"
    return f"{key}{sep}[REDACTED]"


def _scrubbable(value: str) -> bool:
    """A value long and random enough to replace verbatim wherever it appears."""
    if len(value) < 8 or value.startswith("/"):
        return False
    if re.fullmatch(r"[a-z]+|[0-9]+|true|false|null|none", value, re.I):
        return False
    return True


class Redactor:
    """Replaces known secret values, then every pattern above. Counts replacements."""

    def __init__(self, secrets: dict | None = None):
        self.secrets: dict = {}
        self.count = 0
        for value, key in (secrets or {}).items():
            self.add(value, key)

    def add(self, value: str, key: str) -> None:
        if not isinstance(value, str) or not _scrubbable(value):
            return
        self.secrets[value] = key
        quoted = urllib.parse.quote(value, safe="")
        if quoted != value:
            self.secrets[quoted] = key

    def add_env(self, env: dict) -> None:
        for key, value in env.items():
            if is_secret_key(key):
                self.add(value, key)

    def __call__(self, text: str) -> str:
        if not text:
            return text
        # PEM first: a key block must go whole, before value scrubbing splits it.
        for rx, rep in PATTERNS[:2]:
            text, n = rx.subn(rep, text)
            self.count += n
        for value in sorted(self.secrets, key=len, reverse=True):
            if value in text:
                self.count += text.count(value)
                text = text.replace(value, f"[REDACTED:{self.secrets[value]}]")
        for rx, rep in PATTERNS[2:]:
            text, n = rx.subn(rep if rep is not None else _kv_sub, text)
            self.count += n
        return text


# Logs of the ingest data plane can quote fragments of a customer's events inside an error
# (a ClickHouse parse error prints the bytes it choked on). Keep warning/error lines only and
# cut anything that looks like payload.
DATA_PLANE_SERVICES = ("clickhouse", "vector", "tenzir", "connector-runner", "connector")
EXCLUDED_SERVICES = ("vector-tap",)        # vector-tap prints sampled events by design
LEVEL_RE = re.compile(r"(?i)\b(warn|warning|error|err|fatal|panic|critical|crit|exception)\b|<(Error|Warning|Fatal)>")
PAYLOAD_RES = [
    (re.compile(r"(?i)\b(before|parsed text|value|event|raw|payload|record|row data|input)(\s*[:=]\s*).*$"),
     r"\1\2[REDACTED:payload]"),
    (re.compile(r"\{[^{}]{40,}\}"), "{[REDACTED:payload]}"),
    (re.compile(r"\"[^\"]{120,}\""), "\"[REDACTED:long string]\""),
    (re.compile(r"'[^']{120,}'"), "'[REDACTED:long string]'"),
]
DATA_PLANE_LINE_MAX = 400


def scrub_payload(line: str) -> str:
    for rx, rep in PAYLOAD_RES:
        line = rx.sub(rep, line)
    if len(line) > DATA_PLANE_LINE_MAX:
        line = line[:DATA_PLANE_LINE_MAX] + " [truncated]"
    return line


# nano's own services (api, search, jobs) log ClickHouse/PostgreSQL errors that quote the SQL
# of a search, and request URIs that carry the search text: hunt literals are customer data.
SQL_HINT_RE = re.compile(r"(?i)\b(select|insert|where|from|ilike|DB::Exception|Code: \d+|syntax error|query)\b")
SQL_LITERAL_RE = re.compile(r"'(?:[^'\\\r\n]|\\.)*'")
SEARCH_PARAM_RE = re.compile(r"(?i)([?&](?:q|query|search|npl|filter|expr|term|value|values)=)[^&\s\"']+")


def scrub_app_line(line: str) -> str:
    line = SEARCH_PARAM_RE.sub(r"\1[REDACTED:search]", line)
    if SQL_HINT_RE.search(line):
        line = SQL_LITERAL_RE.sub("'[REDACTED:literal]'", line)
        for rx, rep in PAYLOAD_RES[1:]:
            line = rx.sub(rep, line)
    return line


def filter_app_log(text: str) -> str:
    return "\n".join(scrub_app_line(line) for line in text.splitlines()) + ("\n" if text else "")


def filter_data_plane(text: str) -> str:
    kept = [scrub_payload(line) for line in text.splitlines() if LEVEL_RE.search(line)]
    return "\n".join(kept) + ("\n" if kept else "")


def is_data_plane(name: str) -> bool:
    n = name.lower()
    return any(s in n for s in DATA_PLANE_SERVICES) and "proxy" not in n and "migrate" not in n


def is_excluded(name: str) -> bool:
    n = name.lower()
    return any(s in n for s in EXCLUDED_SERVICES)


# --------------------------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------------------------

def read_env(path: str) -> dict:
    out: dict = {}
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                if key.startswith("export "):
                    key = key[7:].strip()
                value = value.strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
                    value = value[1:-1]
                out[key] = value
    except (FileNotFoundError, PermissionError, IsADirectoryError):
        pass
    return out


def describe_env(env: dict) -> str:
    """KEY=value lines; values of secret keys are replaced (absolute paths are shown)."""
    lines = []
    for key in sorted(env):
        value = env[key]
        if is_secret_key(key) and not (value.startswith("/") and " " not in value):
            value = "[REDACTED]" if value else "[empty]"
        lines.append(f"{key}={value}")
    return "\n".join(lines) + "\n"


def run(cmd: list, timeout: int = 60, input_text: str | None = None) -> tuple:
    """(returncode, stdout+stderr). Never raises."""
    try:
        p = subprocess.run(cmd, input=input_text, capture_output=True, text=True, timeout=timeout,
                           errors="replace", **({} if input_text is not None else {"stdin": subprocess.DEVNULL}))
        out = p.stdout or ""
        if p.stderr and p.stderr.strip():
            out += ("\n" if out and not out.endswith("\n") else "") + "[stderr] " + p.stderr
        return p.returncode, out
    except FileNotFoundError:
        return 127, f"[not available: {cmd[0]} not found]\n"
    except subprocess.TimeoutExpired:
        return 124, f"[timed out after {timeout}s: {' '.join(cmd[:4])} ...]\n"
    except OSError as err:
        return 126, f"[failed: {err}]\n"


def out_of(cmd: list, timeout: int = 60, input_text: str | None = None) -> str:
    return run(cmd, timeout, input_text)[1]


def section(title: str, body: str) -> str:
    return f"## {title}\n{body.rstrip()}\n\n"


def parse_since(text: str) -> int:
    m = re.fullmatch(r"\s*(\d+)\s*([smhd]?)\s*", text or "")
    if not m:
        raise argparse.ArgumentTypeError("use a duration such as 90m, 24h or 3d")
    value = int(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]
    if not 60 <= value <= 30 * 86400:
        raise argparse.ArgumentTypeError("--since must be between 1m and 30d")
    return value


def utc_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def tail_bytes(cmd: list, cap: int, timeout: int = 180) -> tuple:
    """Run cmd, keep only the LAST `cap` bytes of stdout+stderr. Returns (text, total, truncated)."""
    buf = bytearray()
    total = 0
    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    except OSError as err:
        return f"[failed: {err}]\n", 0, False
    deadline = time.monotonic() + timeout
    assert proc.stdout is not None
    try:
        while True:
            if time.monotonic() > deadline:
                proc.kill()
                buf += f"\n[timed out after {timeout}s]\n".encode()
                break
            chunk = proc.stdout.read(65536)
            if not chunk:
                break
            total += len(chunk)
            buf += chunk
            if len(buf) > cap * 2:
                del buf[: len(buf) - cap]
    finally:
        with contextlib.suppress(Exception):
            proc.wait(timeout=10)
    truncated = len(buf) > cap
    if truncated:
        del buf[: len(buf) - cap]
        cut = buf.find(b"\n")
        if 0 <= cut < 4096:
            del buf[: cut + 1]
    return buf.decode("utf-8", "replace"), total, truncated


TYPEID_ALPHABET = "0123456789abcdefghjkmnpqrstvwxyz"


def install_typeid(uuid_text: str) -> str:
    """inst_<26 Crockford base32> exactly as nanosiem-core's typeid::encode."""
    n = int(uuid_text.replace("-", "").strip(), 16)
    return "inst_" + "".join(TYPEID_ALPHABET[(n >> (5 * (25 - i))) & 0x1F] for i in range(26))


# --------------------------------------------------------------------------------------------
# Shared database diagnostics (Compose and Kubernetes provide the runners)
# --------------------------------------------------------------------------------------------

def clickhouse_queries(since_s: int) -> list:
    s = int(since_s)
    return [
        ("version", "SELECT version() AS version, uptime() AS uptime_s, hostName() AS host"),
        ("clusters", "SELECT cluster, shard_num, replica_num, host_name, port, is_local, errors_count, "
                     "slowdowns_count FROM system.clusters ORDER BY cluster, shard_num, replica_num"),
        ("errors-recent", "SELECT name, code, value, last_error_time, remote, "
                          "substring(replaceAll(last_error_message, '\\n', ' '), 1, 300) AS last_error_message "
                          f"FROM system.errors WHERE last_error_time > now() - INTERVAL {s} SECOND "
                          "ORDER BY last_error_time DESC LIMIT 100"),
        ("replicas", "SELECT database, table, is_readonly, is_session_expired, is_leader, absolute_delay, "
                     "queue_size, inserts_in_queue, merges_in_queue, log_pointer, last_queue_update "
                     "FROM system.replicas ORDER BY is_readonly DESC, absolute_delay DESC LIMIT 200"),
        ("replicas-readonly", "SELECT database, table, zookeeper_path, replica_name "
                              "FROM system.replicas WHERE is_readonly OR is_session_expired"),
        ("replication-queue", "SELECT database, table, type, count() AS entries, max(num_tries) AS max_tries, "
                              "min(create_time) AS oldest, any(substring(replaceAll(last_exception, '\\n', ' '), 1, 200)) "
                              "AS sample_exception FROM system.replication_queue GROUP BY database, table, type "
                              "ORDER BY entries DESC LIMIT 100"),
        ("distribution-queue", "SELECT database, table, is_blocked, error_count, data_files, "
                               "formatReadableSize(data_compressed_bytes) AS bytes, "
                               "substring(replaceAll(last_exception, '\\n', ' '), 1, 200) AS last_exception "
                               "FROM system.distribution_queue ORDER BY data_files DESC LIMIT 100"),
        ("distributed-ddl-queue", "SELECT cluster, status, count() AS entries, max(query_create_time) AS newest "
                                  "FROM system.distributed_ddl_queue GROUP BY cluster, status"),
        ("parts-by-table", "SELECT database, table, count() AS active_parts, sum(rows) AS rows, "
                           "formatReadableSize(sum(bytes_on_disk)) AS on_disk, max(level) AS max_level, "
                           "uniqExact(partition) AS partitions FROM system.parts WHERE active "
                           "GROUP BY database, table ORDER BY active_parts DESC LIMIT 60"),
        ("parts-hot-partitions", "SELECT database, table, partition, count() AS active_parts FROM system.parts "
                                 "WHERE active GROUP BY database, table, partition ORDER BY active_parts DESC LIMIT 25"),
        ("merges", "SELECT database, table, round(elapsed) AS elapsed_s, round(progress, 2) AS progress, "
                   "num_parts, formatReadableSize(total_size_bytes_compressed) AS size, is_mutation "
                   "FROM system.merges ORDER BY elapsed DESC LIMIT 50"),
        ("mutations-pending", "SELECT database, table, mutation_id, create_time, parts_to_do, is_done, "
                              "substring(replaceAll(latest_fail_reason, '\\n', ' '), 1, 200) AS latest_fail_reason "
                              "FROM system.mutations WHERE NOT is_done ORDER BY create_time LIMIT 50"),
        ("disks", "SELECT name, path, formatReadableSize(free_space) AS free, formatReadableSize(total_space) AS total, "
                  "round(100 * (1 - free_space / greatest(total_space, 1)), 1) AS used_pct, type FROM system.disks"),
        ("dictionaries", "SELECT database, name, status, element_count, last_successful_update_time, "
                         "substring(replaceAll(last_exception, '\\n', ' '), 1, 200) AS last_exception "
                         "FROM system.dictionaries ORDER BY status, name"),
        ("metrics", "SELECT metric, value FROM system.metrics WHERE metric IN ('Query', 'Merge', "
                    "'PartMutation', 'ReplicatedFetch', 'ReplicatedSend', 'DelayedInserts', 'ReadonlyReplica', "
                    "'MemoryTracking', 'TCPConnection', 'HTTPConnection', 'ZooKeeperSession', "
                    "'DistributedFilesToInsert', 'BackgroundMergesAndMutationsPoolTask')"),
        ("asynchronous-metrics", "SELECT metric, value FROM system.asynchronous_metrics WHERE metric LIKE "
                                 "'%MaxPartCountForPartition%' OR metric IN ('Uptime', 'ReplicasMaxAbsoluteDelay', "
                                 "'ReplicasMaxQueueSize', 'OSMemoryAvailable', 'OSMemoryTotal', "
                                 "'NumberOfTables') ORDER BY metric"),
    ]


def collect_clickhouse(run_sql, since_s: int) -> str:
    """run_sql(sql) -> (ok, text) as TSVWithNames. Message columns are payload-scrubbed."""
    body = ""
    for name, sql in clickhouse_queries(since_s):
        ok, text = run_sql(sql)
        lines = text.splitlines()
        if len(lines) > 201:
            lines = lines[:201] + [f"[{len(lines) - 201} more rows omitted]"]
        # Error and exception columns can quote the bytes a parse choked on: scrub every row.
        text = "\n".join(scrub_payload(line) for line in lines)
        body += section(f"{name}{'' if ok else ' (FAILED)'}", text or "(no rows)")
    return body


def postgres_queries(since_s: int) -> list:
    s = int(since_s)
    return [
        ("server", "SELECT version(), pg_is_in_recovery() AS in_recovery, now() AS now, "
                   "pg_size_pretty(pg_database_size(current_database())) AS db_size"),
        ("migrations", "SELECT count(*) AS applied, max(version) AS head, "
                       "count(*) FILTER (WHERE NOT success) AS failed FROM _sqlx_migrations"),
        ("replication", "SELECT application_name, client_addr, state, sync_state, write_lag, flush_lag, "
                        "replay_lag FROM pg_stat_replication"),
        ("wal-receiver", "SELECT status, sender_host, slot_name, latest_end_time FROM pg_stat_wal_receiver"),
        ("activity", "SELECT state, wait_event_type, count(*) FROM pg_stat_activity GROUP BY 1, 2 ORDER BY 3 DESC"),
        # No query text: statements can carry literal values.
        ("long-running", "SELECT pid, state, now() - xact_start AS xact_age, wait_event_type, wait_event, "
                         "backend_type FROM pg_stat_activity "
                         "WHERE xact_start < now() - interval '5 minutes' ORDER BY xact_start LIMIT 20"),
        # Configuration changes: action and object only (no details, user agent or source address).
        ("audit-config-changes", "SELECT \"timestamp\", action, resource_type, resource_id, success FROM audit_logs "
                                 f"WHERE \"timestamp\" > now() - interval '{s} seconds' "
                                 "AND action ~* '(setting|config|creat|updat|delet|deploy|publish|enabl|disabl|licen"
                                 "|role|permission|api_key|token|install|upgrade|restore|backup|retention|source|parser"
                                 "|rule|pipeline)' AND action !~* '(search|query|login|logout|view|read|list|export)' "
                                 "ORDER BY \"timestamp\" DESC LIMIT 200"),
    ]


def collect_postgres(run_sql, since_s: int) -> tuple:
    """(text, install_id or None)."""
    body = ""
    install_id = None
    ok, text = run_sql("SELECT install_id::text, created_at FROM install_identity LIMIT 1")
    # psql -A prints a header and a "(1 row)" footer around the row;
    # reading the last line found the footer, so every bundle said None.
    first = next((line for line in (text.splitlines() if ok else [])
                  if re.match(r"[0-9a-fA-F]{8}-[0-9a-fA-F-]{27}\t", line)), "")
    m = re.match(r"([0-9a-fA-F-]{36})", first)
    if m:
        install_id = install_typeid(m.group(1))
        body += section("install-identity", f"install_id={install_id}\ncreated_at={first.split(chr(9))[-1]}")
    else:
        body += section("install-identity", "not available (install_identity table absent or unreadable)")
    for name, sql in postgres_queries(since_s):
        ok, text = run_sql(sql)
        body += section(f"{name}{'' if ok else ' (FAILED)'}", text or "(no rows)")
    return body, install_id


VECTOR_METRIC_RE = re.compile(
    r"^(# (HELP|TYPE) )?[a-z_]*(component_errors_total|component_discarded_events_total|buffer_byte_size"
    r"|buffer_events|buffer_max_byte_size|buffer_max_event_size|buffer_discarded_events_total|buffer_received"
    r"|buffer_sent|component_received_events_total|component_sent_events_total|utilization|http_client_errors"
    r"|http_client_responses_total|config_reload|reload|started_total|stopped_total|uptime_seconds"
    r"|build_info)"
)


def filter_vector_metrics(text: str) -> str:
    keep = [line for line in text.splitlines() if VECTOR_METRIC_RE.search(line)]
    return "\n".join(keep) + "\n" if keep else text[:2000]


# --------------------------------------------------------------------------------------------
# Compose host collection
# --------------------------------------------------------------------------------------------

GATEWAYS = ("clickhouse-proxy", "app-api-proxy", "ingest-proxy", "postgres-router", "valkey-router")
HAPROXY_STAT = 'echo "show stat" | socat stdio /tmp/haproxy.sock'
VALKEY_TLS = ["--tls", "--insecure", "--cert", "/etc/nano/tls/server.crt", "--key", "/etc/nano/tls/server.key"]
CH_CLIENT_SH = r'''
IFS= read -r password
[ -n "$password" ] || { echo "ClickHouse admin credential is empty" >&2; exit 1; }
umask 077
config=$(mktemp /tmp/nano-support-ch.XXXXXX.xml)
trap 'rm -f -- "$config"' EXIT
escaped=$(printf "%s" "$password" | sed -e "s/&/\\&amp;/g" -e "s/</\\&lt;/g" -e "s/>/\\&gt;/g")
printf "<clickhouse><password>%s</password></clickhouse>\n" "$escaped" > "$config"
clickhouse-client --config-file "$config" --host 127.0.0.1 --user nanosiem_admin \
    --format TSVWithNames --max_execution_time 60 --query "$1"
'''


class ComposeHost:
    def __init__(self, install_dir: str, since_s: int, max_log_bytes: int, redact: Redactor,
                 progress=None):
        self.d = install_dir
        self.since_s = since_s
        self.max_log_bytes = max_log_bytes
        self.redact = redact
        self.env = read_env(os.path.join(install_dir, ".env"))
        self.role = read_env(os.path.join(install_dir, ".nano-role.env"))
        self.files: dict = {}
        self.notes: list = []
        self.containers: list = []
        self.install_id = None
        self.progress = progress or (lambda msg: None)
        redact.add_env(self.env)
        redact.add_env(self.role)
        redact.add_env(read_env(os.path.expanduser("~/.nano-admin-credentials")))

    # -- compose plumbing --
    @property
    def role_split(self) -> bool:
        return bool(self.role)

    @property
    def host_name(self) -> str:
        return self.role.get("NANO_HOST_NAME") or socket.gethostname().split(".", 1)[0]

    def compose(self) -> list:
        d = self.d
        envf = ["--env-file", os.path.join(d, ".env")] if os.path.isfile(os.path.join(d, ".env")) else []
        if self.role_split:
            f = os.path.join(d, "deploy/compose/docker-compose.enterprise.yml")
            return ["docker", "compose", "--project-directory", os.path.dirname(f), *envf,
                    "--env-file", os.path.join(d, ".nano-role.env"), "-f", f]
        if os.path.isfile(os.path.join(d, "docker-compose.opensource.yml")):
            cmd = ["docker", "compose", "--project-directory", d, *envf,
                   "-f", os.path.join(d, "docker-compose.opensource.yml")]
            for overlay in self.env.get("NANO_COMPOSE_OVERLAYS", "").split():
                if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*\.ya?ml", overlay) and \
                        os.path.isfile(os.path.join(d, overlay)):
                    cmd += ["-f", os.path.join(d, overlay)]
            return cmd
        cmd = ["docker", "compose", "--project-directory", d, *envf]
        for name in ("docker-compose.yml", "docker-compose.override.yml"):
            if os.path.isfile(os.path.join(d, name)):
                cmd += ["-f", os.path.join(d, name)]
        return cmd

    def discover(self) -> None:
        rc, out = run(self.compose() + ["ps", "-a", "--format", "json"], timeout=60)
        rows: list = []
        if rc == 0:
            text = out.split("[stderr]")[0].strip()
            try:
                parsed = json.loads(text) if text.startswith("[") else [json.loads(x) for x in text.splitlines() if x.strip()]
                rows = [r for r in parsed if isinstance(r, dict)]
            except ValueError:
                rows = []
        if not rows:
            self.notes.append("compose ps returned no services; fell back to docker ps for nano-* containers")
            rc, out = run(["docker", "ps", "-a", "--filter", "name=^nano", "--format",
                           "{{.Names}}\t{{.Label \"com.docker.compose.service\"}}\t{{.State}}\t{{.Status}}"])
            for line in out.splitlines() if rc == 0 else []:
                parts = line.split("\t")
                if len(parts) >= 3:
                    rows.append({"Name": parts[0], "Service": parts[1] or parts[0], "State": parts[2],
                                 "Status": parts[3] if len(parts) > 3 else ""})
        self.containers = [{"name": r.get("Name", ""), "service": r.get("Service", ""),
                            "state": str(r.get("State", "")), "health": str(r.get("Health", "")),
                            "status": str(r.get("Status", "")), "image": str(r.get("Image", ""))}
                           for r in rows if r.get("Name")]

    def container(self, service: str, running: bool = True):
        for c in self.containers:
            if c["service"] == service and (not running or c["state"] == "running"):
                return c["name"]
        return None

    def put(self, name: str, text: str) -> None:
        self.files[name] = self.redact(text)

    # -- collectors --
    def host_facts(self) -> None:
        self.progress("host facts")
        t = section("host", f"hostname: {socket.gethostname()}\nnano host name: {self.host_name}\n"
                            f"collected_utc: {utc_now()}\nepoch: {time.time():.3f}\n"
                            f"install_dir: {self.d}\nmode: {'role-split' if self.role_split else 'single-node'}\n"
                            f"roles: {self.role.get('NANO_ROLE_PROFILES', 'app,ingest,clickhouse,postgres (single node)')}")
        for title, cmd in (("uname", ["uname", "-a"]), ("os-release", ["cat", "/etc/os-release"]),
                           ("cpus", ["nproc"]), ("memory", ["free", "-m"]), ("uptime", ["uptime"]),
                           ("time sync", ["timedatectl"]), ("chrony", ["chronyc", "-n", "tracking"]),
                           ("vm.max_map_count", ["sysctl", "-n", "vm.max_map_count"]),
                           ("vm.overcommit_memory", ["sysctl", "-n", "vm.overcommit_memory"]),
                           ("transparent hugepages", ["cat", "/sys/kernel/mm/transparent_hugepage/enabled"]),
                           ("firewall", ["sh", "-c", "for s in firewalld ufw nftables; do printf '%s: ' $s; "
                                                     "systemctl is-active $s 2>/dev/null || echo n/a; done"]),
                           ("docker version", ["docker", "version"]),
                           ("compose version", ["docker", "compose", "version"]),
                           ("docker info", ["docker", "info"])):
            t += section(title, out_of(cmd, timeout=30))
        self.put("host.txt", t)

    def release(self) -> None:
        t = ""
        for key in ("NANO_VERSION", "NANO_EDITION", "NANO_SCHEMA_PROFILE", "NANO_IMAGE_PREFIX",
                    "NANO_DEPLOYMENT_ID", "NANO_LICENSE_MODE", "AIRGAP_MODE"):
            if key in self.env:
                t += f"{key}={self.env[key]}\n"
        for name in (".nano-edition", ".nano-bundle", ".nano-legacy-layout-restored"):
            p = os.path.join(self.d, name)
            if os.path.isfile(p):
                with open(p, encoding="utf-8", errors="replace") as fh:
                    t += f"{name}: {fh.read(400).strip()}\n"
        for lock in ("images.enterprise.customer.lock", "images.enterprise.lock", "images.lock"):
            p = os.path.join(self.d, lock)
            if os.path.isfile(p):
                with open(p, encoding="utf-8", errors="replace") as fh:
                    t += section(lock, fh.read(20000))
        names = [c["name"] for c in self.containers]
        if names:
            t += section("container images (name, image, image id)", out_of(
                ["docker", "inspect", "--format", "{{.Name}}\t{{.Config.Image}}\t{{.Image}}", *names]))
        self.put("release.txt", t)

    def env_keys(self) -> None:
        self.put("env.txt", describe_env(self.env))
        if self.role:
            self.put("role-env.txt", describe_env(self.role))

    def compose_state(self) -> None:
        self.progress("compose state")
        t = section("compose ps", out_of(self.compose() + ["ps", "-a"], timeout=60))
        # Only this install's containers: other workloads on the host are not ours to report.
        running = [c["name"] for c in self.containers if c["state"] == "running"]
        if running:
            t += section("docker stats", out_of(["docker", "stats", "--no-stream", "--format",
                                                 "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.PIDs}}",
                                                 *running], timeout=60))
        self.put("compose.txt", t)
        state = ""
        for c in self.containers:
            state += section(c["name"], out_of(["docker", "inspect", "--format",
                                               "service={{index .Config.Labels \"com.docker.compose.service\"}} "
                                               "restarts={{.RestartCount}} oom={{.State.OOMKilled}} "
                                               "exit={{.State.ExitCode}} started={{.State.StartedAt}} "
                                               "finished={{.State.FinishedAt}} error={{.State.Error}}\n"
                                               "health={{if .State.Health}}{{.State.Health.Status}} "
                                               "failing_streak={{.State.Health.FailingStreak}}"
                                               "{{range .State.Health.Log}}\n  {{.End}} exit={{.ExitCode}} "
                                               "{{printf \"%.200s\" .Output}}{{end}}{{end}}\n"
                                               "mem_limit={{.HostConfig.Memory}} "
                                               "nano_cpus={{.HostConfig.NanoCpus}}", c["name"]]))
        self.put("containers.txt", state)

    def disk(self) -> None:
        self.progress("disk and mounts")
        t = ""
        for title, cmd in (("df -hT", ["df", "-hT"]), ("df -i", ["df", "-i"]),
                           ("lsblk", ["lsblk", "-o", "NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,ROTA"]),
                           ("findmnt", ["findmnt", "-rno", "TARGET,SOURCE,FSTYPE,OPTIONS", "-t",
                                        "ext4,xfs,btrfs,zfs,nfs,nfs4,overlay,tmpfs"])):
            t += section(title, out_of(cmd, timeout=30))
        paths: dict = {"install dir": self.d}
        root = out_of(["docker", "info", "--format", "{{.DockerRootDir}}"]).strip().splitlines()
        if root and root[0].startswith("/"):
            paths["docker root"] = root[0]
        project = ""
        if self.containers:
            project = out_of(["docker", "inspect", "--format",
                              "{{index .Config.Labels \"com.docker.compose.project\"}}",
                              self.containers[0]["name"]]).strip().splitlines()[:1]
            project = project[0] if project and re.fullmatch(r"[a-z0-9][a-z0-9_-]*", project[0]) else ""
        rc, vols = run(["docker", "volume", "ls", "-q", "--filter", f"label=com.docker.compose.project={project}"]) \
            if project else (1, "")
        for v in vols.split() if rc == 0 else []:
            mp = out_of(["docker", "volume", "inspect", "--format", "{{.Mountpoint}}", v]).strip()
            if mp.startswith("/"):
                paths[f"volume {v}"] = mp
        for key, value in sorted({**self.env, **self.role}.items()):
            if re.search(r"(_DIR|_PATH|_DATA|_ROOT)$", key) and value.startswith("/") and os.path.isdir(value):
                paths[key] = value
        rows = ["what\tpath\tis_mountpoint\tmount_target\tsource\tfstype\tused\tfree"]
        for label, path in paths.items():
            try:
                is_mp = "yes" if os.path.ismount(path) else "no"
            except OSError:
                is_mp = "unknown"
            mnt = out_of(["findmnt", "-n", "-o", "TARGET,SOURCE,FSTYPE", "-T", path], timeout=10).split()
            mnt = (mnt + ["?", "?", "?"])[:3] if mnt and not mnt[0].startswith("[") else ["?", "?", "?"]
            try:
                u = shutil.disk_usage(path)
                used, free = f"{u.used / 2**30:.1f}G", f"{u.free / 2**30:.1f}G"
            except OSError:
                used = free = "?"
            rows.append("\t".join([label, path, is_mp, *mnt, used, free]))
        t += section("data directories (is each its own mount?)", "\n".join(rows))
        self.put("disk.txt", t)

    def logs(self) -> None:
        self.progress("service logs")
        targets = [c for c in self.containers if not is_excluded(c["service"] or c["name"])]
        if not targets:
            return
        per = max(256 * 1024, self.max_log_bytes // max(1, len(targets)))
        summary = ["container\tservice\tbytes_seen\tbytes_kept\ttruncated\tfilter"]
        for c in targets:
            text, total, truncated = tail_bytes(
                ["docker", "logs", "--timestamps", "--since", f"{self.since_s}s", c["name"]], per)
            data_plane = is_data_plane(c["service"] or c["name"])
            text = filter_data_plane(text) if data_plane else filter_app_log(text)
            text = self.redact(text)
            self.files[f"logs/{c['name']}.log"] = text
            summary.append(f"{c['name']}\t{c['service']}\t{total}\t{len(text.encode())}\t"
                           f"{'yes' if truncated else 'no'}\t{'warn/error only, payload removed' if data_plane else 'full, SQL literals and search text removed'}")
        excluded = [c["name"] for c in self.containers if is_excluded(c["service"] or c["name"])]
        if excluded:
            summary.append(f"\nnot collected (prints customer events): {', '.join(excluded)}")
        self.put("logs/_summary.tsv", "\n".join(summary) + "\n")

    def ch_sql(self, sql: str) -> tuple:
        name = self.container("clickhouse")
        if not name:
            return False, "clickhouse is not running on this host"
        password = self.env.get("CLICKHOUSE_ADMIN_PASSWORD", "")
        if not password:
            return False, "CLICKHOUSE_ADMIN_PASSWORD is not in .env"
        if self.role_split:
            return self._ch_http(sql, password)
        rc, out = run(["docker", "exec", "-i", name, "sh", "-c", CH_CLIENT_SH, "sh", sql],
                      timeout=90, input_text=password + "\n")
        return rc == 0, out

    def _ch_http(self, sql: str, password: str) -> tuple:
        role = self.role
        tls = role.get("NANO_PRIVATE_TLS") == "true"
        address = role.get("NANO_HOST_ADDRESS", "127.0.0.1")
        port = role.get("NANO_CLICKHOUSE_PUBLISH_HTTP_PORT") or role.get("NANO_CLICKHOUSE_HTTP_PORT") or "8123"
        url = f"{'https' if tls else 'http'}://{address}:{port}/?" + urllib.parse.urlencode(
            {"default_format": "TSVWithNames", "max_execution_time": "60"})
        import base64
        auth = base64.b64encode(f"nanosiem_admin:{password}".encode()).decode()
        try:
            ctx = ssl.create_default_context(cafile=role.get("NANO_TLS_CA")) if tls else None
            req = urllib.request.Request(url, data=sql.encode(), method="POST",
                                         headers={"Authorization": "Basic " + auth})
            with urllib.request.urlopen(req, timeout=90, context=ctx) as resp:
                return True, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as err:
            return False, f"HTTP {err.code}: {err.read().decode('utf-8', 'replace')[:300]}"
        except (urllib.error.URLError, OSError, ssl.SSLError, ValueError) as err:
            return False, f"{type(err).__name__}: {err}"

    def clickhouse(self) -> None:
        if not self.container("clickhouse"):
            return
        self.progress("clickhouse diagnostics")
        self.put("clickhouse.txt", collect_clickhouse(self.ch_sql, self.since_s))

    def pg_sql(self, sql: str) -> tuple:
        name = self.container("postgres-ha") or self.container("postgres")
        if not name:
            return False, "postgres is not running on this host"
        user = self.env.get("POSTGRES_USER") or "nanosiem"
        db = self.env.get("POSTGRES_DB") or "nanosiem"
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,62}", user) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,62}", db):
            return False, "unsafe POSTGRES_USER / POSTGRES_DB"
        rc, out = run(["docker", "exec", "-i", name, "psql", "-X", "-q", "-P", "pager=off", "-F", "\t", "-A",
                       f"--username={user}", f"--dbname={db}", "-v", "ON_ERROR_STOP=1",
                       "-c", "SET statement_timeout = '30s'", "-c", sql], timeout=60)
        return rc == 0, out

    def postgres(self) -> None:
        if not (self.container("postgres-ha") or self.container("postgres")):
            return
        self.progress("postgres diagnostics")
        text, self.install_id = collect_postgres(self.pg_sql, self.since_s)
        self.put("postgres.txt", text)

    def vector(self) -> None:
        name = self.container("vector")
        if not name:
            return
        self.progress("vector metrics")
        t = section("vector version", out_of(["docker", "exec", name, "vector", "--version"]))
        rc, out = run(["docker", "exec", name, "sh", "-c",
                       "(wget -qO- http://127.0.0.1:9598/metrics || curl -fsS http://127.0.0.1:9598/metrics) 2>&1"],
                      timeout=30)
        t += section("internal metrics (errors, discards, buffers, throughput)",
                     filter_vector_metrics(out) if rc == 0 else out)
        self.put("vector.txt", t)

    def ha(self) -> None:
        t = ""
        for service in GATEWAYS:
            name = self.container(service)
            if not name:
                continue
            rc, out = run(["docker", "exec", name, "sh", "-c", HAPROXY_STAT], timeout=20)
            t += section(f"haproxy {service} backends", haproxy_summary(out) if rc == 0 else out)
        pg = self.container("postgres-ha")
        if pg:
            t += section("patroni", out_of(["docker", "exec", pg, "patronictl", "-c", "/run/patroni/patroni.yml",
                                            "list"], timeout=30))
            t += section("patroni history", out_of(["docker", "exec", pg, "patronictl", "-c",
                                                    "/run/patroni/patroni.yml", "history"], timeout=30)[-4000:])
        etcd = self.container("etcd")
        if etcd:
            base = ["docker", "exec", etcd, "/usr/local/bin/etcdctl", "--endpoints=https://127.0.0.1:2379",
                    "--cacert=/etc/nano/tls/ca.crt", "--cert=/etc/nano/tls/server.crt",
                    "--key=/etc/nano/tls/server.key", "--insecure-skip-tls-verify", "--command-timeout=5s"]
            t += section("etcd endpoint status", out_of(base + ["endpoint", "status", "--cluster", "-w", "table"]))
            t += section("etcd endpoint health", out_of(base + ["endpoint", "health", "--cluster", "-w", "table"]))
        sentinel = self.container("valkey-sentinel")
        if sentinel:
            base = ["docker", "exec", sentinel, "valkey-cli", *VALKEY_TLS, "-p", "26379"]
            t += section("sentinel master", out_of(base + ["sentinel", "get-master-addr-by-name", "nano"]))
            t += section("sentinel ckquorum", out_of(base + ["sentinel", "ckquorum", "nano"]))
            t += section("sentinel replicas", sentinel_summary(out_of(base + ["sentinel", "replicas", "nano"])))
        valkey = self.container("valkey-ha")
        if valkey:
            t += section("valkey-ha role", out_of(["docker", "exec", valkey, "valkey-cli", *VALKEY_TLS,
                                                   "-p", "6379", "role"]))
        for service in ("dragonfly", "valkey"):
            name = self.container(service)
            if name:
                t += section(f"{service} replication", out_of(
                    ["docker", "exec", name, "sh", "-c",
                     "(valkey-cli -p 6379 info replication || redis-cli -p 6379 info replication) 2>&1 | head -20"]))
        keeper = self.container("keeper")
        if keeper:
            t += section("keeper mntr", out_of(["docker", "exec", keeper, "sh", "-c",
                                                "echo mntr | (nc -w 3 127.0.0.1 9181 || true) 2>&1 | head -40"]))
        if t:
            self.put("ha.txt", t)

    def cluster_health(self) -> bool:
        """Run this install's cluster-health check. False when no copy is on this host."""
        if not self.role_split:
            return True
        for path in cluster_health_candidates(self.d):
            self.progress("cluster health")
            self.put("cluster-health.txt",
                     out_of([sys.executable or "python3", "-I", path, "--install-dir", self.d], timeout=300))
            return True
        return False

    def collect(self) -> dict:
        self.discover()
        for step in (self.host_facts, self.release, self.env_keys, self.compose_state, self.disk,
                     self.postgres, self.clickhouse, self.vector, self.ha):
            try:
                step()
            except Exception as err:  # one failed collector never loses the rest
                self.notes.append(f"{step.__name__}: {type(err).__name__}: {err}")
        if not self.cluster_health():
            self.notes.append("cluster-health: no copy on this host")
        try:
            self.logs()
        except Exception as err:
            self.notes.append(f"logs: {type(err).__name__}: {err}")
        meta = {"host": self.host_name, "hostname": socket.gethostname(), "epoch": time.time(),
                "mode": "role-split" if self.role_split else "single-node",
                "roles": self.role.get("NANO_ROLE_PROFILES", ""), "install_id": self.install_id,
                "version": self.env.get("NANO_VERSION", ""), "edition": self.env.get("NANO_EDITION", ""),
                "notes": self.notes}
        self.files["host.json"] = self.redact(json.dumps(meta, indent=2)) + "\n"
        return self.files


def script_dir() -> str:
    path = str(globals().get("__file__", ""))
    return os.path.dirname(os.path.abspath(path)) if path and not path.startswith("<") else ""


def cluster_health_candidates(install_dir: str) -> list:
    """The install's shipped copy first, then a copy beside this script (the nano-deploy skill)."""
    here = script_dir()
    paths = [os.path.join(install_dir, "scripts", "nano-cluster-health")]
    if here:
        paths += [os.path.join(here, "nano-cluster-health"), os.path.join(here, "cluster-health.py")]
    return [p for p in paths if os.path.isfile(p)]


def haproxy_summary(text: str) -> str:
    lines = text.splitlines()
    if not lines or not lines[0].startswith("# "):
        return text[:4000]
    import csv
    reader = csv.DictReader(io.StringIO("\n".join([lines[0][2:]] + lines[1:])))
    out = ["backend\tserver\tstatus\tcheck\tlast_change_s\tdowntime_s\tsessions\tactive\tbackup"]
    for rec in reader:
        if rec.get("type") in ("1", "2"):
            out.append("\t".join(rec.get(k, "") or "" for k in
                                 ("pxname", "svname", "status", "check_status", "lastchg", "downtime", "scur",
                                  "act", "bck")))
    return "\n".join(out)


def sentinel_summary(text: str) -> str:
    keep = {"name", "ip", "port", "flags", "master-link-status", "slave-repl-offset", "role-reported"}
    lines = [x.strip() for x in text.splitlines()]
    out, i = [], 0
    while i + 1 < len(lines):
        if lines[i] in keep:
            out.append(f"{lines[i]}={lines[i + 1]}")
            i += 2
        else:
            i += 1
    return "\n".join(out) or text[:2000]


# --------------------------------------------------------------------------------------------
# Inventory (role-split) and remote hosts
# --------------------------------------------------------------------------------------------

SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
SAFE_ADDR = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:_-]{0,252}$")


def load_inventory(path: str, install_dir: str) -> list:
    """[{name, address, ssh_user, ssh_port, ssh_identity, roles}] from a v1 host inventory."""
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    raw = None
    if text.lstrip().startswith("{"):
        raw = json.loads(text)
    else:
        renderer = os.path.join(install_dir, "deploy", "compose", "render-inventory.py")
        if not os.path.isfile(renderer):
            raise ValueError("YAML inventory needs deploy/compose/render-inventory.py (enterprise bundle)")
        import importlib.util
        spec = importlib.util.spec_from_file_location("nano_inventory_support", renderer)
        if spec is None or spec.loader is None:
            raise ValueError("cannot load the inventory parser")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        raw = module._parse_yaml_subset(text)
    if not isinstance(raw, dict) or not isinstance(raw.get("hosts"), list):
        raise ValueError("inventory has no hosts list")
    cluster = raw.get("cluster") if isinstance(raw.get("cluster"), dict) else {}
    hosts = []
    for h in raw["hosts"]:
        if not isinstance(h, dict):
            continue
        name, address = str(h.get("name", "")), str(h.get("address", ""))
        user = h.get("ssh_user", cluster.get("ssh_user"))
        port = h.get("ssh_port", cluster.get("ssh_port", 22))
        identity = h.get("ssh_identity", cluster.get("ssh_identity"))
        if not SAFE_NAME.match(name) or not SAFE_ADDR.match(address):
            raise ValueError(f"inventory host {name!r} has an invalid name or address")
        if user is not None and not SAFE_NAME.match(str(user)):
            raise ValueError(f"inventory host {name} has an invalid ssh_user")
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError(f"inventory host {name} has an invalid ssh_port")
        if identity is not None and not (isinstance(identity, str) and identity.startswith("/")):
            raise ValueError(f"inventory host {name} ssh_identity must be an absolute path")
        hosts.append({"name": name, "address": address, "ssh_user": user, "ssh_port": port,
                      "ssh_identity": identity, "roles": [str(r) for r in h.get("roles") or []]})
    return hosts


def ssh_command(host: dict) -> list:
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-p", str(host["ssh_port"])]
    if host.get("ssh_identity"):
        cmd += ["-i", host["ssh_identity"]]
    target = f"{host['ssh_user']}@{host['address']}" if host.get("ssh_user") else host["address"]
    return cmd + [target]


def probe_clock(host: dict) -> dict:
    t0 = time.time()
    rc, out = run(ssh_command(host) + ["python3 -c 'import time; print(repr(time.time()))'"], timeout=30)
    t1 = time.time()
    try:
        remote = float(out.split("[stderr]")[0].strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {"ok": False, "detail": out.strip()[:200]}
    return {"ok": True, "skew_s": round(remote - (t0 + t1) / 2, 3), "rtt_s": round(t1 - t0, 3)}


def safe_member(name: str) -> bool:
    return bool(name) and not name.startswith("/") and ".." not in name.split("/") and "\\" not in name


def collect_remote(host: dict, script: bytes, args, remote_install_dir: str, redact: Redactor) -> tuple:
    """Stream this script to the host; returns ({path: text}, error or None)."""
    remote = ["python3", "-I", "-", "--host-archive", "--install-dir", remote_install_dir,
              "--since", f"{args.since}s", "--max-log-mb", str(args.max_log_mb)]
    try:
        proc = subprocess.run(ssh_command(host) + [shlex.join(remote)], input=script, capture_output=True,
                              timeout=SSH_HOST_TIMEOUT)
    except subprocess.TimeoutExpired:
        return {}, f"timed out after {SSH_HOST_TIMEOUT}s"
    except OSError as err:
        return {}, f"ssh failed: {err}"
    if proc.returncode != 0:
        tail = proc.stderr.decode("utf-8", "replace").strip().splitlines()[-3:]
        return {}, f"exit {proc.returncode}: {' | '.join(tail)[:400]}"
    files: dict = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(proc.stdout), mode="r:gz") as tar:
            for m in tar.getmembers():
                if not m.isfile() or not safe_member(m.name) or m.size > 64 * 2**20:
                    continue
                fh = tar.extractfile(m)
                if fh is not None:
                    # Re-redacted with THIS host's secrets too (the .env is shared cluster-wide).
                    files[m.name] = redact(fh.read().decode("utf-8", "replace"))
    except (tarfile.TarError, OSError) as err:
        return {}, f"unreadable host archive: {err}"
    return files, None


def remote_cluster_health(host: dict, script_path: str, remote_install_dir: str) -> str:
    with open(script_path, "rb") as fh:
        source = fh.read()
    try:
        proc = subprocess.run(ssh_command(host) + [shlex.join(["python3", "-I", "-", "--install-dir",
                                                               remote_install_dir])],
                              input=source, capture_output=True, timeout=300)
        return proc.stdout.decode("utf-8", "replace") + proc.stderr.decode("utf-8", "replace")
    except (subprocess.TimeoutExpired, OSError) as err:
        return f"[failed: {err}]\n"


# --------------------------------------------------------------------------------------------
# Kubernetes (Helm) collection
# --------------------------------------------------------------------------------------------

_VALUES_SECRET_KEY = re.compile(r"(?i)(password|secret|token|apikey|api_key|privatekey|licen[cs]e|(^|[._-])key$)")
_VALUES_EXEMPT_KEY = re.compile(r"(?i)(secretname|existingsecret|secretref|name|enabled|create)$")
_B64_RE = re.compile(r"^[A-Za-z0-9+/_-]{40,}={0,2}$")


def looks_like_pem(value) -> bool:
    """PEM text, or base64 that decodes to a PEM block (`LS0tLS1CRUdJTi...` = '-----BEGIN')."""
    if not isinstance(value, str):
        return False
    v = value.strip()
    if "-----BEGIN" in v or v.startswith("LS0tLS1CRUdJTi"):
        return True
    compact = re.sub(r"\s+", "", v)
    if _B64_RE.match(compact):
        import base64
        import binascii
        try:
            padded = compact + "=" * (-len(compact) % 4)
            decoded = base64.b64decode(padded.replace("-", "+").replace("_", "/"), validate=False)
        except (binascii.Error, ValueError):
            return False
        return b"-----BEGIN" in decoded[:64]
    return False


def _secret_values_key(k: str) -> bool:
    return (is_secret_key(k) or bool(_VALUES_SECRET_KEY.search(k))) and not _VALUES_EXEMPT_KEY.search(k)


def redact_values(obj, path: str = ""):
    """Helm values with every secret-looking value removed: secret-named keys, Kubernetes
    `{name, value}` env items whose NAME is secret (extraEnv), and anything PEM-shaped."""
    if isinstance(obj, dict):
        name = obj.get("name")
        env_item = isinstance(name, str) and "value" in obj and (
            is_secret_key(name) or bool(_VALUES_SECRET_KEY.search(name)))
        out = {}
        for key, value in obj.items():
            k = str(key)
            scalar = not isinstance(value, (dict, list))
            if scalar and value not in (None, "", False) and (
                    (env_item and k == "value") or _secret_values_key(k) or looks_like_pem(value)):
                out[k] = "[REDACTED]"
            else:
                out[k] = redact_values(value, f"{path}.{k}")
        return out
    if isinstance(obj, list):
        return [redact_values(v, path) for v in obj]
    return obj


class Kubernetes:
    def __init__(self, args, redact: Redactor, progress):
        self.args = args
        self.redact = redact
        self.progress = progress
        self.files: dict = {}
        self.notes: list = []
        self.install_id = None
        base = ["kubectl"]
        if args.context:
            base += ["--context", args.context]
        self.kube = base
        self.ns = base + ["-n", args.namespace]
        self.helm = ["helm"] + (["--kube-context", args.context] if args.context else []) + ["-n", args.namespace]
        self.pods: list = []

    def put(self, name: str, text: str) -> None:
        self.files[name] = self.redact(text)

    def cluster(self) -> None:
        self.progress("cluster state")
        t = section("collected", f"collected_utc: {utc_now()}\nnamespace: {self.args.namespace}\n"
                                 f"release: {self.args.release}")
        for title, cmd in (("kubectl version", self.kube + ["version"]), ("helm version", ["helm", "version"]),
                           ("nodes", self.kube + ["get", "nodes", "-o", "wide"]),
                           ("node usage", self.kube + ["top", "nodes"]),
                           ("pod usage", self.ns + ["top", "pods", "--containers"]),
                           ("workloads", self.ns + ["get", "deploy,sts,ds,job,cronjob,hpa,pdb", "-o", "wide"]),
                           ("pods", self.ns + ["get", "pods", "-o", "wide"]),
                           ("services and routes", self.ns + ["get", "svc,endpoints,ingress", "-o", "wide"]),
                           ("storage", self.ns + ["get", "pvc", "-o", "wide"]),
                           ("storage classes", self.kube + ["get", "storageclass"]),
                           ("configmaps", self.ns + ["get", "configmap"]),
                           ("secrets (names and types only)", self.ns + ["get", "secret", "-o",
                                                                          "custom-columns=NAME:.metadata.name,TYPE:.type"]),
                           ("clickhouse resources", self.ns + ["get", "clickhouseinstallations,clickhousekeeperinstallations,"
                                                               "clickhouseclusters,keeperclusters", "-o", "wide"])):
            t += section(title, out_of(cmd, timeout=60))
        self.put("cluster.txt", t)
        self.put("events.txt", out_of(self.ns + ["get", "events", "--sort-by=.lastTimestamp"], timeout=60))
        self.put("describe-pods.txt", out_of(self.ns + ["describe", "pods"], timeout=120))
        self.put("describe-workloads.txt", out_of(self.ns + ["describe", "deploy,sts"], timeout=120))
        self.put("describe-nodes.txt", out_of(self.kube + ["describe", "nodes"], timeout=120))

    def helm_release(self) -> None:
        self.progress("helm release")
        t = section("releases", out_of(self.helm + ["list", "-a"]))
        t += section("history", out_of(self.helm + ["history", self.args.release, "--max", "20"]))
        t += section("status", out_of(self.helm + ["status", self.args.release]))
        rc, out = run(self.helm + ["get", "values", self.args.release, "-a", "-o", "json"], timeout=60)
        if rc == 0:
            try:
                values = redact_values(json.loads(out.split("[stderr]")[0]))
                t += section("values (secrets removed)", json.dumps(values, indent=2, sort_keys=True))
            except ValueError:
                t += section("values", "[unparseable; omitted]")
        else:
            t += section("values", out[:400])
        self.put("helm.txt", t)

    def discover(self) -> None:
        rc, out = run(self.ns + ["get", "pods", "-o", "json"], timeout=60)
        if rc != 0:
            self.notes.append(f"cannot list pods: {out.strip()[:200]}")
            return
        try:
            items = json.loads(out.split("[stderr]")[0]).get("items", [])
        except ValueError:
            items = []
        for item in items:
            name = item.get("metadata", {}).get("name", "")
            spec = item.get("spec", {})
            statuses = {s.get("name"): s for s in item.get("status", {}).get("containerStatuses", []) or []}
            containers = [(c.get("name"), c.get("image", "")) for c in spec.get("containers", [])]
            inits = [(c.get("name"), c.get("image", "")) for c in spec.get("initContainers", []) or []]
            self.pods.append({"name": name, "phase": item.get("status", {}).get("phase", ""),
                              "containers": containers, "inits": inits,
                              "restarts": {k: int(v.get("restartCount", 0)) for k, v in statuses.items()}})

    def logs(self) -> None:
        self.progress("pod logs")
        pairs = [(p, c, img, init) for p in self.pods for (c, img), init in
                 [((c, img), False) for c, img in p["containers"]] + [((c, img), True) for c, img in p["inits"]]]
        pairs = [x for x in pairs if not is_excluded(x[0]["name"]) and not is_excluded(x[1])]
        if not pairs:
            return
        per = max(256 * 1024, self.args.max_log_mb * 2**20 // max(1, len(pairs)))
        summary = ["pod\tcontainer\tbytes_kept\tfilter"]
        for pod, cname, image, init in pairs:
            data_plane = is_data_plane(pod["name"]) or is_data_plane(cname) or "clickhouse-server" in image
            for previous in ([False, True] if pod["restarts"].get(cname, 0) > 0 else [False]):
                cmd = self.ns + ["logs", pod["name"], "-c", cname, "--timestamps", f"--since={self.args.since}s",
                                 f"--limit-bytes={per * 2}"] + (["--previous"] if previous else [])
                text, _total, _trunc = tail_bytes(cmd, per, timeout=120)
                text = filter_data_plane(text) if data_plane else filter_app_log(text)
                text = self.redact(text)
                suffix = ".previous" if previous else ""
                self.files[f"logs/{pod['name']}/{cname}{suffix}.log"] = text
                summary.append(f"{pod['name']}\t{cname}{suffix}\t{len(text.encode())}\t"
                               f"{'warn/error only, payload removed' if data_plane else 'full, SQL literals removed'}")
        self.put("logs/_summary.tsv", "\n".join(summary) + "\n")

    def _pods_like(self, predicate) -> list:
        return [p for p in self.pods if p["phase"] == "Running" and predicate(p)]

    def databases(self) -> None:
        ch = self._pods_like(lambda p: any("clickhouse-server" in img or c == "clickhouse"
                                           for c, img in p["containers"]) and "keeper" not in p["name"])
        for pod in ch[:6]:
            self.progress(f"clickhouse {pod['name']}")
            cname = next((c for c, img in pod["containers"] if "clickhouse-server" in img or c == "clickhouse"),
                         pod["containers"][0][0])

            def ch_sql(sql: str, pod=pod, cname=cname) -> tuple:
                script = 'printf "%s\\n" "$CLICKHOUSE_ADMIN_PASSWORD" | sh -c "$0" sh "$1"'
                rc, out = run(self.ns + ["exec", pod["name"], "-c", cname, "--", "sh", "-c", script,
                                         CH_CLIENT_SH, sql], timeout=90)
                return rc == 0, out
            self.put(f"clickhouse/{pod['name']}.txt", collect_clickhouse(ch_sql, self.args.since))
        pg = self._pods_like(lambda p: "postgres" in p["name"] and any("postgres" in img for _c, img in p["containers"]))
        if pg:
            pod = pg[0]
            cname = next((c for c, img in pod["containers"] if "postgres" in img), pod["containers"][0][0])

            def pg_sql(sql: str) -> tuple:
                script = ('psql -X -q -P pager=off -F "$(printf "\\t")" -A -U "${POSTGRES_USER:-nanosiem}" '
                          '-d "${POSTGRES_DB:-nanosiem}" -v ON_ERROR_STOP=1 -c "SET statement_timeout = \'30s\'" -c "$1"')
                rc, out = run(self.ns + ["exec", pod["name"], "-c", cname, "--", "sh", "-c", script, "sh", sql],
                              timeout=60)
                return rc == 0, out
            self.progress("postgres")
            text, self.install_id = collect_postgres(pg_sql, self.args.since)
            self.put("postgres.txt", text)
        else:
            self.notes.append("no in-cluster PostgreSQL pod (external database): PostgreSQL diagnostics skipped")
        vec = self._pods_like(lambda p: any(c == "vector" for c, _img in p["containers"]))
        for pod in vec[:4]:
            rc, out = run(self.ns + ["exec", pod["name"], "-c", "vector", "--", "sh", "-c",
                                     "(wget -qO- http://127.0.0.1:9598/metrics || curl -fsS "
                                     "http://127.0.0.1:9598/metrics) 2>&1"], timeout=30)
            self.put(f"vector/{pod['name']}.txt", filter_vector_metrics(out) if rc == 0 else out)

    def collect(self) -> dict:
        for step in (self.cluster, self.helm_release, self.discover, self.databases, self.logs):
            try:
                step()
            except Exception as err:
                self.notes.append(f"{step.__name__}: {type(err).__name__}: {err}")
        return self.files


# --------------------------------------------------------------------------------------------
# Bundle packaging
# --------------------------------------------------------------------------------------------

README = """# nano support bundle

Created by `nano support-bundle` (tool version {tool_version}) at {created} for {mode}.

## What is in it

- `MANIFEST.json`: every file with its size and SHA-256, the hosts, any
  collection errors, and the collection window (`since_seconds`).
- `hosts/<host>/`: per host: `host.txt` (OS, CPU, memory, time sync, Docker),
  `release.txt` (version, edition, image locks), `env.txt` (configuration KEY
  names; secret values removed), `compose.txt` / `containers.txt` (service
  state, health, restarts, OOM kills), `disk.txt` (filesystems, and whether
  each data directory is its own mount), `postgres.txt`, `clickhouse.txt`,
  `vector.txt`, `ha.txt` (Patroni, etcd, Sentinel, Valkey, HAProxy backends),
  `cluster-health.txt`, and `logs/` (the nano services' own logs).
- `cluster/clock-skew.txt`: each host's clock against the collecting host.
- Kubernetes: `cluster.txt`, `events.txt`, `describe-*.txt`, `helm.txt`
  (release values with secrets removed), `logs/<pod>/<container>.log`.

## What is NOT in it

- No event data: nothing from the `logs` or OCSF tables, no raw logs your
  sources sent to nano, no search or query results, no lookup or IOC contents.
- No secrets: secret `.env` values, tokens, JWTs, PEM blocks (keys and
  certificates), passwords in URLs, the license token, Authorization and
  Cookie headers and key=value secrets are replaced by `[REDACTED...]`
  ({redactions} replacements in this bundle).
- `vector-tap` is not collected (it prints sampled events). Logs of the
  ingest data plane (Vector, ClickHouse, Tenzir, connector-runner) keep warning
  and error lines only, with payload fragments removed.
- nano's own service logs (api, search, jobs, web) are kept, but quoted SQL
  literals in database errors (`'[REDACTED:literal]'`) and search text in
  request URIs (`q=[REDACTED:search]`) are removed: they can hold hunt terms.
- Audit entries are configuration changes only: time, action, object type and
  ID, success. No details, user agents or source addresses.

## Before you send it

Redaction is pattern-based. Review the files before sending the bundle:

    tar -tzf {archive}
    tar -xzf {archive} -O | less

See `GETTING-HELP.md` for what to send with it.
"""

GETTING_HELP = """# Getting help with nano

1. Collect a bundle on any one host of the install (it reaches the others over
   SSH on a role-split cluster):

       cd ~/nano && scripts/nano support-bundle            # last 24 hours
       scripts/nano support-bundle --since 3d              # a longer window

   Kubernetes (Helm), from a machine with kubectl access:

       python3 nano/scripts/nano-support-bundle --kubernetes --namespace nano --release nano

2. Review it (`tar -xzf FILE -O | less`): it is redacted, but you know your
   environment best.

3. Send it with a short report. In nano, use Help > Report a bug (or Get
   support): it records the page, the request IDs and status codes of recent
   failed API calls, and your browser, and formats the report for you; nothing
   is sent automatically. Include:
   - what happened and what you expected;
   - when, with timezone (for example `2026-11-10 14:05 EST`), and whether it
     is still happening;
   - the exact names of the affected objects (rule, log source, parser,
     dashboard, host);
   - the request ID from the error message, when there is one.

Email support@nano.rs, or attach it to your ticket on app.nano.rs. Air-gapped
installs: move the bundle and report out through your normal transfer process.

Never send `.env`, `.nano-admin-credentials`, backup keys, license files or
event data.
"""


def build_archive(out_path: str, prefix: str, files: dict, manifest: dict) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(out_path, flags, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "wb") as raw, tarfile.open(fileobj=raw, mode="w:gz") as tar:
        now = int(time.time())
        for name in sorted(files):
            data = files[name].encode("utf-8")
            info = tarfile.TarInfo(f"{prefix}/{name}")
            info.size, info.mtime, info.mode = len(data), now, 0o600
            tar.addfile(info, io.BytesIO(data))


def finish(args, prefix_label: str, mode: str, files: dict, redact: Redactor, extra: dict) -> str:
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    label = re.sub(r"[^A-Za-z0-9._-]", "-", prefix_label)[:40] or "nano"
    prefix = f"nano-support-{label}-{stamp}"
    out_dir = os.path.abspath(os.path.expanduser(args.out_dir))
    os.makedirs(out_dir, mode=0o700, exist_ok=True)
    out_path = os.path.join(out_dir, prefix + ".tar.gz")
    files = {k: v for k, v in files.items()}
    files["GETTING-HELP.md"] = GETTING_HELP
    entries = [{"path": k, "bytes": len(v.encode()), "sha256": hashlib.sha256(v.encode()).hexdigest()}
               for k, v in sorted(files.items())]
    manifest = {"tool": "nano support-bundle", "tool_version": TOOL_VERSION, "created_utc": utc_now(),
                "mode": mode, "since_seconds": args.since, "max_log_mb": args.max_log_mb,
                "redactions": redact.count, "contains_event_data": False, **extra, "files": entries}
    files["MANIFEST.json"] = redact(json.dumps(manifest, indent=2)) + "\n"
    files["README.md"] = README.format(tool_version=TOOL_VERSION, created=manifest["created_utc"], mode=mode,
                                       redactions=redact.count, archive=os.path.basename(out_path))
    build_archive(out_path, prefix, files, manifest)
    return out_path


def human(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or unit == "GiB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)


def default_install_dir() -> str:
    here = script_dir()
    if here and os.path.basename(here) == "scripts":
        parent = os.path.dirname(here)
        if os.path.isfile(os.path.join(parent, ".env")) or os.path.isfile(os.path.join(parent, "install.sh")):
            return parent
    return os.path.expanduser("~/nano")


def own_source() -> bytes | None:
    path = globals().get("__file__", "")
    if path and not str(path).startswith("<") and os.path.isfile(path):
        with open(path, "rb") as fh:
            return fh.read()
    return None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="nano support-bundle", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--install-dir", default=None, help="Compose install directory (default: this install)")
    ap.add_argument("--since", type=parse_since, default=parse_since(DEFAULT_SINCE),
                    help="log and error window, e.g. 90m, 24h (default), 3d")
    ap.add_argument("--max-log-mb", type=int, default=DEFAULT_MAX_LOG_MB,
                    help="cap on service logs per host, in MiB (default 20)")
    ap.add_argument("--out-dir", default=None, help="where to write the archive (default: <install>/support)")
    ap.add_argument("--inventory", default=None,
                    help=f"role-split host inventory (default {DEFAULT_INVENTORY} when present)")
    ap.add_argument("--remote-install-dir", default=None, help="install directory on the other hosts")
    ap.add_argument("--local-only", action="store_true", help="collect this host only")
    ap.add_argument("--kubernetes", action="store_true", help="collect a Helm install with kubectl")
    ap.add_argument("--namespace", default="nano")
    ap.add_argument("--release", default="nano")
    ap.add_argument("--context", default=None, help="kubectl context")
    ap.add_argument("--host-archive", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--quiet", action="store_true", help=argparse.SUPPRESS)
    args = ap.parse_args(argv)
    if not 1 <= args.max_log_mb <= 500:
        ap.error("--max-log-mb must be between 1 and 500")
    if not SAFE_NAME.match(args.namespace) or not SAFE_NAME.match(args.release):
        ap.error("invalid --namespace or --release")

    def progress(msg: str) -> None:
        if not args.quiet:
            print(f"  .. {msg}", file=sys.stderr, flush=True)

    redact = Redactor()
    if args.kubernetes:
        args.out_dir = args.out_dir or os.getcwd()
        print(f"nano support-bundle: Kubernetes namespace {args.namespace}, release {args.release}", file=sys.stderr)
        k = Kubernetes(args, redact, progress)
        files = k.collect()
        out = finish(args, args.namespace, "kubernetes (Helm)", files, redact,
                     {"install_id": k.install_id, "namespace": args.namespace, "release": args.release,
                      "notes": k.notes})
        return report(out, k.notes)

    install_dir = os.path.abspath(os.path.expanduser(args.install_dir or default_install_dir()))
    host = ComposeHost(install_dir, args.since, args.max_log_mb * 2**20, redact, progress)

    if args.host_archive:  # internal: one host's files as tar.gz on stdout
        files = host.collect()
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for name, text in files.items():
                data = text.encode("utf-8")
                info = tarfile.TarInfo(name)
                info.size, info.mode = len(data), 0o600
                tar.addfile(info, io.BytesIO(data))
        sys.stdout.buffer.write(buf.getvalue())
        sys.stdout.buffer.flush()
        return 0

    if not os.path.isdir(install_dir):
        print(f"nano support-bundle: {install_dir} is not a directory (use --install-dir)", file=sys.stderr)
        return 2
    args.out_dir = args.out_dir or os.path.join(install_dir, "support")
    mode = "Compose role split" if host.role_split else "Compose single node"
    print(f"nano support-bundle: {mode}, install {install_dir}, last {args.since // 3600}h"
          f"{'' if args.since % 3600 == 0 else f' {args.since % 3600 // 60}m'}", file=sys.stderr)
    print(f"collecting on {host.host_name} (this host)", file=sys.stderr)
    local_files = host.collect()
    files = {f"hosts/{host.host_name}/{k}": v for k, v in local_files.items()}
    hosts_meta = [{"name": host.host_name, "local": True, "ok": True, "notes": host.notes}]
    install_id = host.install_id
    notes: list = []

    inventory = args.inventory or (DEFAULT_INVENTORY if host.role_split and os.path.isfile(DEFAULT_INVENTORY) else None)
    skew = [f"collector\t{host.host_name}\t{utc_now()}", "host\tskew_s\trtt_s\tdetail"]
    if host.role_split and not inventory and not args.local_only:
        notes.append(f"role split without an inventory ({DEFAULT_INVENTORY} absent): other hosts NOT collected; "
                     "pass --inventory FILE, or run on each host with --local-only and send every archive")
    if inventory and not args.local_only:
        try:
            nodes = load_inventory(inventory, install_dir)
        except (OSError, ValueError) as err:
            nodes = []
            notes.append(f"inventory {inventory}: {err}; other hosts NOT collected")
        source = own_source()
        ch_script = next(iter(cluster_health_candidates(install_dir)), None)
        remote_dir = args.remote_install_dir or install_dir
        for node in nodes:
            if node["name"] == host.host_name:
                continue
            print(f"collecting on {node['name']} ({node['address']}) over SSH", file=sys.stderr, flush=True)
            clock = probe_clock(node)
            skew.append(f"{node['name']}\t{clock.get('skew_s', '?')}\t{clock.get('rtt_s', '?')}\t"
                        f"{'' if clock['ok'] else clock.get('detail', '')}")
            if source is None:
                hosts_meta.append({"name": node["name"], "ok": False,
                                   "error": "run from an install (scripts/nano support-bundle) to reach other hosts"})
                continue
            remote_files, err = collect_remote(node, source, args, remote_dir, redact)
            if err:
                print(f"  !! {node['name']}: {err}", file=sys.stderr)
            for k, v in remote_files.items():
                files[f"hosts/{node['name']}/{k}"] = v
            meta = {"name": node["name"], "address": node["address"], "ok": err is None, "error": err,
                    "clock": clock}
            if remote_files and "cluster-health.txt" not in remote_files and ch_script:
                files[f"hosts/{node['name']}/cluster-health.txt"] = redact(
                    remote_cluster_health(node, ch_script, remote_dir))
            if remote_files.get("host.json"):
                with contextlib.suppress(ValueError):
                    remote_meta = json.loads(remote_files["host.json"])
                    install_id = install_id or remote_meta.get("install_id")
            hosts_meta.append(meta)
    else:
        skew.append("(single host: see host.txt 'time sync' for NTP state)")
    files["cluster/clock-skew.txt"] = "\n".join(skew) + "\n"
    out = finish(args, host.env.get("NANO_DEPLOYMENT_ID") or host.host_name, mode, files, redact,
                 {"install_id": install_id, "version": host.env.get("NANO_VERSION", ""),
                  "edition": host.env.get("NANO_EDITION", ""), "inventory": inventory, "hosts": hosts_meta,
                  "notes": notes})
    return report(out, notes + [f"{h['name']}: {h.get('error')}" for h in hosts_meta if not h.get("ok")])


def report(path: str, problems: list) -> int:
    size = os.path.getsize(path)
    for p in problems:
        print(f"  note: {p}", file=sys.stderr)
    print(f"\nWrote {path} ({human(size)}, mode 0600).")
    print("It is redacted and holds no event data, but REVIEW IT before sending:")
    print(f"  tar -xzf {shlex.quote(path)} -O | less")
    print("Then send it to nano support with what happened, when (with timezone) and the affected object names.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
