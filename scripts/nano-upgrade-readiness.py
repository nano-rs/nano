#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""nano upgrade readiness check and content export (NAN-5556).

A single, standalone, READ-ONLY file. It runs on any nano Compose install,
including legacy open-core v0.1.x checkouts that do not ship `scripts/nano`,
so it only needs Python 3.8+ (standard library) and the `docker` CLI.

Modes
  report (default)  Writes ONE file, nano-upgrade-readiness-<host>-<utc>.txt:
                    a readable summary followed by the same data as a JSON
                    block. Versions, layout, host, data volume per UTC day,
                    the disk needed for the upgrade, content counts, warnings,
                    and per ingest path (nginx /ingest, :8080, HEC :8088,
                    Vector native :6000, OTLP, :24224, syslog) whether this
                    install uses it and what the upgrade needs for it.
  export            Writes ONE archive, nano-content-export-<host>-<utc>.tgz,
                    holding your CONTENT only (parsers, log sources, detection
                    rules, lookups, saved searches, dashboards). No event data,
                    no logs. Secret columns are removed, not masked.
  export --encrypt  The same archive, encrypted (openssl cms, AES-256-CBC) to
                    nano support's pinned intake certificate (embedded below):
                    writes nano-content-export-<host>-<utc>.tgz.cms, which
                    only nano support can open, and removes the plain .tgz
                    once the .cms is written and verified. If openssl is
                    missing or fails, or the embedded certificate does not
                    match its pinned fingerprint, it keeps the plain .tgz,
                    prints a WARN line and exits 4: send that .tgz to nano
                    support over a secure channel only.

What it never does
  It only runs SELECT queries (PostgreSQL inside BEGIN READ ONLY, ClickHouse
  with readonly=1), `docker ps`/`inspect`/`logs`/`exec` and reads files (the
  exec into Vector reads its metrics endpoint and /proc/net, nothing else). It never
  writes to the install directory, never restarts anything and never prints
  or writes a secret. Before anything is written, the output is scanned for
  every secret value from .env and the database containers; a match aborts
  the run and nothing is written.

Usage
  python3 nano-upgrade-readiness.py [report|export] [--install-dir DIR]
      [--output DIR] [--include-lookup-rows] [--encrypt] [--pg-container NAME]
      [--ch-container NAME] [--ch-database NAME]

Exit codes
  0 ok, 1 Python too old, 2 no database reachable, 3 the secret self-scan
  failed (nothing written), 4 export --encrypt could not encrypt (the plain
  .tgz was kept; send it over a secure channel only).

  On nano 2.x it is also `scripts/nano upgrade-readiness [report|export] ...`.
"""
from __future__ import annotations

import argparse
import base64
import datetime as _dt
import hashlib
import io
import json
import os
import platform
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse

REPORT_FORMAT = "nano-upgrade-readiness-v1"
EXPORT_FORMAT = "nano-content-export-v1"
TOOL_VERSION = "1"

# .env keys whose values are safe to print. Everything else is never output.
ENV_WHITELIST = (
    "NANO_VERSION", "IMAGE_TAG", "NANO_EDITION", "NANO_SCHEMA_PROFILE",
    "NANO_IMAGE_PREFIX", "COMPOSE_PROFILES", "COMPOSE_PROJECT_NAME",
    "NANO_LICENSE_MODE", "NANO_PLANNED_GB_PER_DAY", "NANO_RETENTION_DAYS",
    "NANO_LOG_QUERY_BACKEND", "CLICKHOUSE_MEM_LIMIT", "NANOSIEM_DEV_MODE",
    "RUST_LOG", "NANO_COMPOSE_OVERLAYS", "CLICKHOUSE_DATABASE",
    "NANO_INGEST_ACK_DURABILITY",
)
# URL-valued keys printed as the host name only.
ENV_HOST_ONLY = ("NANO_BASE_URL", "BASE_URL", "PUBLIC_URL")

# Event tables whose per-UTC-day volume is reported. `ocsf_logs` on 0.1.x is
# the OCSF 1.8 store that the 2.x upgrade renames to ocsf_logs_legacy_v179 and
# backfills day by day (the ocsf-legacy-backfill tool in 2.x).
EVENT_TABLES = ("ocsf_logs", "ocsf_logs_legacy_v179", "logs")

# Content exported by `export`: kind -> candidate PostgreSQL tables (every one
# that exists is exported) and an optional filter applied when its column exists.
EXPORT_KINDS = (
    ("parsers", ("log_sources", "parsers"), None),
    ("parser_versions", ("log_source_versions",), None),
    ("source_configs", ("source_configurations",), None),
    ("routing_rules", ("routing_rules",), None),
    ("namespaces", ("namespaces",), None),
    ("feeds", ("feeds",), None),
    ("detection_rules", ("detection_rules",), None),
    ("rule_folders", ("folder_settings",), None),
    ("saved_searches", ("saved_searches", "case_saved_searches"), None),
    ("query_library", ("query_library",), ("is_builtin", "is_builtin IS NOT TRUE")),
    ("dashboards", ("dashboards",), None),
    ("report_definitions", ("report_definitions",), None),
    ("lookups", ("lookup_tables_registry",), None),
)
# Field mapping / alias tables (discovered by name; none exist on 0.1.702).
FIELD_MAPPING_TABLE = re.compile(r"(field_alias|field_mapping|field_map\b|udm_alias|ocsf_alias)")
# JSON columns whose nested keys are scrubbed with the secret-name rule. Other
# JSON (dashboard panels, parser output_fields) holds field names such as
# `process_hash`, which are content, so it is left as is.
CONFIG_JSON_COLUMN = re.compile(r"(config|headers|metadata|settings|params|options|connection|destination)")

# Authoritative secret config keys: config_secrets.rs in the nanosiem-core crate,
# SECRET_CONFIG_KEYS and SECRET_CONFIG_SUBTREES (a unit test pins this copy).
SECRET_CONFIG_KEYS = frozenset((
    "sasl_password", "secret_access_key", "session_token", "credentials_json",
    "connection_string", "checkpoint_connection_string", "azure_client_secret",
    "key_content", "token", "api_key", "password", "client_secret", "valid_tokens",
    "secret", "secret_key", "private_key", "passphrase", "auth_token", "bearer_token",
    "access_token", "refresh_token",
))
SECRET_CONFIG_SUBTREES = frozenset(("_credentials",))

_SECRET_TOKENS = frozenset((
    "token", "tokens", "secret", "secrets", "password", "passwords", "passwd",
    "pwd", "pass", "passphrase", "credential", "credentials", "creds", "auth",
    "cert", "certs", "certificate", "certificates", "hash", "hashes", "nonce",
    "salt", "encrypted", "apikey", "privkey", "pem", "jwt", "totp", "otp", "dsn",
    "bearer", "sas", "signature", "sig",
))
_SECRET_PAIRS = frozenset((
    ("client", "secret"), ("key", "material"), ("connection", "string"),
    ("webhook", "url"), ("conn", "str"),
))
_SECRET_JOINED = ("apikey", "privatekey", "clientsecret", "keymaterial", "authorization",
                  "password", "passwd", "passphrase", "secret", "credential", "accesskey",
                  "connectionstring", "webhookurl")
# Names that look secret by segment but are identifiers or metadata, not secrets.
SECRET_NAME_EXEMPT = frozenset((
    "auth_type", "content_hash", "config_hash", "hash_algorithm", "certificate_fingerprint",
    "credential_id", "key_id", "access_key_id", "primary_key", "key_file", "author",
))
# Segments ending in "key" that are not secrets.
_KEY_SEGMENT_EXEMPT = frozenset(("monkey", "turnkey", "hotkey"))
# .env keys that hold secrets (used for the self-scan, never printed).
_SECRET_ENV_KEY = re.compile(
    r"(PASSWORD|PASSWD|PASSPHRASE|SECRET|TOKEN|KEY($|_)|CREDENTIAL|AUTH|PRIVATE|SALT|DSN|"
    r"(^|_)PASS($|_)|ENCRYPTION|SIGNING|DATABASE_URL|_URI$|CONNECTION_STRING|BEARER)")
# Values never treated as secrets in the self-scan (they are also identifiers).
_TRIVIAL_VALUES = frozenset(("nanosiem", "nanosiem_admin", "postgres", "clickhouse", "default",
                             "nano", "admin", "true", "false", "changeme", "password"))
_UUID = re.compile(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_DIGEST = re.compile(r"(?i)^(sha256|sha512|sha1|md5):[0-9a-f]+$")
# Scheme start: not inside a longer [a-z0-9+.-] run (keeps the scan linear).
_SCHEME = r"(?<![a-z0-9+.-])[a-z][a-z0-9+.-]*"
# Userinfo up to the LAST `@` of the authority, so a password holding `@` goes too.
_URL_CREDS = re.compile(r"(?i)(" + _SCHEME + r":(?:\\?/){2})([^/\s\"'<>\\?#]+)@")
# Credentials in URLs beyond plain userinfo (P2-4). `%(?:25)*XX` is the
# percent-encoded (and double-encoded) form of a delimiter, as in a URL
# passed as another URL's query value.
_PCT = r"%(?:25)*"
# Percent-encoded userinfo: https%3A%2F%2Fuser%3Apass%40host.
_URL_CREDS_ENCODED = re.compile(
    r"(?i)(" + _SCHEME + _PCT + r"3A(?:" + _PCT + r"2F){2})"
    r"((?:(?!" + _PCT + r"(?:2F|3F|23))[^/@\s\"'<>?#&\\])+)" + _PCT + r"40")
# A query string or fragment: from `?` or `#` (raw or encoded) to whitespace,
# a quote, a backtick or a backslash (so `\n` in JSON text ends it too, and
# the self-scan over serialized JSON sees what the scrub saw).
_URL_QUERY = re.compile(r"(?i)(?:[?#]|" + _PCT + r"(?:3F|23))[^\s\"'`\\]*")
# One `name=value` pair inside a query string, delimiters raw or encoded. A
# name never absorbs an encoded delimiter (no backtracking blow-up).
_URL_PARAM = re.compile(
    r"(?i)(?P<pre>[?&;#]|" + _PCT + r"(?:3F|26|3B|23))"
    r"(?P<name>(?:[A-Za-z0-9_.~\-\[\]]|%(?!(?:25)*(?:26|3F|3B|3D|23))[0-9A-F]{2})+)"
    r"(?P<eq>=|" + _PCT + r"3D)"
    r"(?P<val>(?:(?!" + _PCT + r"(?:26|23|3B))[^&;#\s\"'`\\])*)")
# Query parameter names that carry a credential although is_secret_name()
# alone would not say so (short forms used by real APIs).
_URL_SECRET_PARAMS = frozenset((
    "key", "apikey", "api_key", "access_token", "token", "sig", "signature", "secret",
    "password", "pass", "passwd", "pwd", "pw", "passcode", "auth", "client_secret", "session",
    "sessionid", "session_id", "jwt", "credential", "x-amz-credential", "x-amz-signature",
    "x-amz-security-token", "x-goog-signature", "x-goog-credential", "hmac",
))
# Param names is_secret_name() flags that are content in a URL (IOC lookups).
_URL_PARAM_EXEMPT = frozenset(("hash", "hashes", "md5", "sha1", "sha256", "sha512", "imphash"))
# Whole-value templates and regex syntax: not credentials. Detection rules and
# parsers match credentials in URLs (`[?&]token=[^&]+`); those stay intact.
# (`{{` alone is a template cut at its first space: `?t={{ secrets.x }}`.)
_TEMPLATE_VALUE = re.compile(r"^(?:\{\{|\{%|\$\{[^}]*\}|\{\{.*\}\}|\{%.*%\}|<[^<>\s]*>|\$[A-Za-z_][A-Za-z0-9_]*)$")
_REGEX_VALUE = re.compile(r"[()\[\]|^]|\.[*+?]|\{\d+(?:,\d*)?\}|[*+?]\??$")
_IDENT = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
# Secret material recognized by its shape, wherever it appears (B2).
SECRET_SHAPES = (
    ("private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|\Z)")),
    ("SAS / storage key", re.compile(r"(?i)\b(SharedAccessKey|AccountKey|sig)=(?!\[REDACTED\])[^;&\s\"']+")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")),
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
)
# `password=...` style assignments inside free text. Not applied to code columns
# (nPL queries and VRL), where `password=*` is a field search, not a secret.
SECRET_ASSIGNMENT = re.compile(r"(?i)\b((?:password|passwd|secret|token)\s*[=:]\s*)([^\s\"',;&]+)")
CODE_COLUMNS = frozenset((
    "query", "parser_vrl", "extension_vrl", "normalize_vrl", "source_query", "sampling_exclude_condition",
    "converted_npl", "raw_content",
))
# Header-style keys whose sibling `value` is secret when the name is.
_SECRET_HEADER_NAMES = frozenset(("authorization", "proxy-authorization", "cookie", "set-cookie",
                                  "x-api-key", "x-auth-token", "api-key", "apikey"))
REDACTED = "[REDACTED]"

# `export --encrypt` (NAN-5556): nano support's intake certificate. PUBLIC by
# design: the matching private key never leaves nano support. The fingerprint
# is the SHA-256 of the certificate's DER; a copy that does not match it is
# never used to encrypt.
SUPPORT_INTAKE_CERT_PEM = """\
-----BEGIN CERTIFICATE-----
MIIFZTCCA02gAwIBAgIUS86oSfWAtxz19U5T31d+hF0yMHMwDQYJKoZIhvcNAQEL
BQAwQDENMAsGA1UECgwEbmFubzEvMC0GA1UEAwwmbmFubyBzdXBwb3J0IGludGFr
ZSAoY3VzdG9tZXIgZXhwb3J0cykwHhcNMjYxMTE3MTMyNDQxWhcNMzExMTE2MTMy
NDQxWjBAMQ0wCwYDVQQKDARuYW5vMS8wLQYDVQQDDCZuYW5vIHN1cHBvcnQgaW50
YWtlIChjdXN0b21lciBleHBvcnRzKTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
AgoCggIBAMI9Fk9qeOrg5tNtZn+PzEzQQsWkSR7VWy2kCBAu3Mdw9ltnNrhwRGLb
iAFdwaQ3SxLdEfiWVxPlcIDdgkeYKIFw/WOTHybB7uVOam+pIqRiN748eX5w/AKK
H7ENB1YDoNYQYtqGHEaEamB6zzW4rrIQIz0R/Q6pn3FdQruNFJSUkVSXbd4eZpOj
l56oO5Af7B/fqYok4pQ3iTWdomd2O8uxuRVbg4+LCTEbLDxf0c5dL4aELb5k0xIr
T3fkzVXFY6eAAkmsJirpildPSCZWjPm/9K7Cen0Wu5DT6XodZS1+Z81UkV7m0Uf6
PgA53dGOpEFAef9pfSb1kyGjIl/Au7FfLx4M81VwWQq8nODp4rwyMI+Sm1Q+eoOv
90aq38BztasABYxZFNiUj+G2HOSNAwVs9oTT3rPTXmxiJFmln37u917Or2lj8vE0
d+I7L8EgnKYA6LSXFGtAbH2l9jQkMhN7tCouj1QIDosDkIIooAavdFe+oov2Wu4/
/6ooYWp1+IPDUENIjVEizNKYLNrqdK63OM8cPDQ/YFeuHnvgdUkw7kfYt7JMzN7Z
o0+WzNYDqrRzxuFlsGBctQfeZvfMmpP9AKtYNi3ad833zU4OJ6QgVAmPiXVJFY9z
it1Oslvl7Q7VVAbHq/0dMyV3lsHuetjZm+2R0ssk7EKFjSU10wRvAgMBAAGjVzBV
MB0GA1UdDgQWBBTeC7wOtn0OVeJHSZIpGrA6uDBnGTAPBgNVHRMBAf8EBTADAQH/
MA4GA1UdDwEB/wQEAwIEMDATBgNVHSUEDDAKBggrBgEFBQcDBDANBgkqhkiG9w0B
AQsFAAOCAgEAp60Va07SMIkZUYYMgVDNezxFAp1BXVgpav6+uBPnaYYXQwQVKslp
ljGmHKaNFInRMlobTS/4TpLMbJUCJVdFosPjOF9+eKZz5iJ22w1GM3mr4DRbjxsz
RNZx7nmUQ+SqbmtR0WYq/ESzZbBsG7xj+YE6fvVWUtm457jMyJH0BkrP53+8jxQ4
t9DBWOmagyT9Bfh4mndgvKm06gS7D3cmOqw37BGlHZ8KecnXtazWwvT6luXnvr/p
QnRZoQ+nYwxh1OSISIXWnAwwkm8k9gdLC/bPYzsJQU86X4H6VPqMC2P8pPtAm91y
QvzYcvE2otZ0KlHkbqKnBku7EkmegXxm7knhbNJHwou14TSg0TEvBw8bHQfuY4gS
9sMiIBE62My2tNQZ/dWf6HEzySmGuoTM4K2BhECD0reu7VDU4t7dU3IYEwA1KyzH
IasubndTPI75632MNXqVGzhuMo/gyP75olsfVIqsrnXReiAxbzP8/kLaB1rPPZq4
BK/+Hi8U3lpbz5sqb+VtdVYWE3MfSbWL8xg95QH2gWIm0PmmwygcCyomwzdis67M
Mj316SewGvKtwg809VZCcvgUDtTRMx46EnOfBLHRK2WhKuvi4u5jH1dpOo3Zuaz/
tYcyOvlvDbfq80OcpBYzB5CS/utCwEK1QrPyBc0u8hHakBv9CHmWtKM=
-----END CERTIFICATE-----
"""
SUPPORT_INTAKE_CERT_SHA256 = (
    "7A:C4:DE:AA:24:BF:06:55:1C:3D:2B:A4:1D:EB:07:13:"
    "9F:38:14:9D:37:BC:BE:46:AC:DB:56:25:76:34:D6:C6"
)
# Exit code when --encrypt was asked for but the plain .tgz had to be kept.
EXIT_ENCRYPT_FALLBACK = 4

def utc_now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)


def log(msg: str) -> None:
    print(f"[nano-upgrade-readiness] {msg}", file=sys.stderr, flush=True)


# --------------------------------------------------------------------------
# Pure helpers (unit tested)
# --------------------------------------------------------------------------

def _url_param_name(raw: str) -> str:
    """The decoded param name, case kept (camelCase splits in is_secret_name)."""
    name = raw
    for _ in range(3):  # undo up to triple percent-encoding
        dec = urllib.parse.unquote(name)
        if dec == name:
            break
        name = dec
    return name.strip()


def is_secret_url_param(raw_name: str) -> bool:
    name = _url_param_name(raw_name)
    low = name.lower()
    if low in _URL_SECRET_PARAMS:
        return True
    if not name or low in _URL_PARAM_EXEMPT or low.endswith(("_hash", "-hash", "_type", "_id")):
        return False
    return is_secret_name(name)


def _placeholder_value(val: str) -> bool:
    """Values that are not credentials: empty, wildcards, whole templates, regex
    syntax, already redacted."""
    v = urllib.parse.unquote(val).strip()
    return (not v or set(v) <= {"*", "?", "."} or v in (REDACTED, "REDACTED", "xxx", "XXX")
            or bool(_TEMPLATE_VALUE.match(v)) or bool(_REGEX_VALUE.search(v)))


def _scan_params(text: str, base: int, depth: int = 0):
    for m in _URL_PARAM.finditer(text):
        val = m.group("val")
        if is_secret_url_param(m.group("name")):
            if not _placeholder_value(val):
                yield base + m.start("val"), base + m.end("val"), _url_param_name(m.group("name")).lower()
        elif depth < 3 and val:
            # A non-secret value can hold an encoded URL with its own query
            # (`?url=https%3A%2F%2Fh%3Fapi_key%3DX`): scan inside it too.
            yield from _scan_params(val, base + m.start("val"), depth + 1)


def _url_secret_params(text: str):
    """Yield (start, end, decoded name) for each secret-named URL query param with a real value."""
    for q in _URL_QUERY.finditer(text):
        yield from _scan_params(q.group(0), q.start())


def redact_url_query_secrets(text):
    """Replace the value of every secret-named URL query parameter with [REDACTED]."""
    if not isinstance(text, str) or ("?" not in text and "#" not in text and "%" not in text):
        return text
    spans = list(_url_secret_params(text))
    for start, end, _ in reversed(spans):
        text = text[:start] + REDACTED + text[end:]
    return text


def strip_url_credentials(text):
    """Remove `user:pass@` (raw or percent-encoded) from every URL in a string and
    redact secret-named query parameters (`?api_key=`, `&sig=`, ...), keeping the
    rest of the URL readable."""
    if not isinstance(text, str):
        return text
    text = _URL_CREDS.sub(r"\1", text)
    text = _URL_CREDS_ENCODED.sub(r"\1", text)
    return redact_url_query_secrets(text)


def url_secret_findings(text: str) -> list:
    """Reasons (never values) for URL credentials still present in `text`."""
    out = []
    if _URL_CREDS.search(text) or _URL_CREDS_ENCODED.search(text):
        out.append("URL userinfo (user:password@)")
    names = sorted({n for _, _, n in _url_secret_params(text)})
    out.extend(f"URL query parameter {n!r} with a value" for n in names)
    return out


def redact_shapes(text, code: bool = False):
    """Redact secret-shaped substrings. Returns (text, [kinds redacted])."""
    if not isinstance(text, str):
        return text, []
    kinds = []
    for kind, rx in SECRET_SHAPES:
        new = rx.sub(REDACTED, text)
        if new != text:
            kinds.append(kind)
            text = new
    if not code:
        new = SECRET_ASSIGNMENT.sub(lambda m: m.group(1) + REDACTED, text)
        if new != text:
            kinds.append("password/secret/token assignment")
            text = new
    return text, kinds


def _name_parts(name: str):
    snake = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(name))
    return [p for p in re.split(r"[^a-z0-9]+", snake.lower()) if p]


def is_secret_name(name: str) -> bool:
    """True when a column or JSON key name denotes secret material.

    Matching is by name segment, so `author`, `bypass` and field names in query
    text are not affected, while `password_hash`, `key_hash`, `api_key`,
    `routing_key`, `auth_headers` and `client_secret` are. Any segment ending in
    `key` is secret unless the whole name is in SECRET_NAME_EXEMPT.
    """
    raw = str(name)
    parts = _name_parts(raw)
    if not parts:
        return False
    norm = "_".join(parts)
    if norm in SECRET_NAME_EXEMPT:
        return False
    if raw in SECRET_CONFIG_KEYS or norm in SECRET_CONFIG_KEYS:
        return True
    if raw in SECRET_CONFIG_SUBTREES:
        return True
    if any(p in _SECRET_TOKENS for p in parts):
        return True
    if any(p.endswith("key") and p not in _KEY_SEGMENT_EXEMPT for p in parts):
        return True
    if any((a, b) in _SECRET_PAIRS for a, b in zip(parts, parts[1:])):
        return True
    joined = "".join(parts)
    return any(s in joined for s in _SECRET_JOINED)


def parse_env_file(text: str) -> dict:
    """Parse a docker-compose style .env (KEY=VALUE, optional quotes/export).

    A quoted value may span several lines (a PEM key).
    """
    out = {}
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        i += 1
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
            continue
        val = val.strip()
        if val[:1] in ("\"", "'"):
            q = val[0]
            body = val[1:]
            if q in body:
                val = body[:body.index(q)]
            else:  # multi-line quoted value
                parts = [body]
                while i < len(lines):
                    nxt = lines[i]
                    i += 1
                    if q in nxt:
                        parts.append(nxt[:nxt.index(q)])
                        break
                    parts.append(nxt)
                val = "\n".join(parts)
        elif " #" in val:
            val = val.split(" #", 1)[0].rstrip()
        out[key] = val
    return out


def url_host(value: str):
    m = re.match(r"(?i)^[a-z][a-z0-9+.-]*://(?:[^/@]*@)?([^/:?#]+)", value or "")
    return m.group(1) if m else None


def safe_env(envmap: dict) -> dict:
    """The printable subset of .env: whitelisted keys, URL keys as host only."""
    out = {}
    for k in ENV_WHITELIST:
        if k in envmap:
            out[k] = strip_url_credentials(envmap[k])
    for k in ENV_HOST_ONLY:
        if envmap.get(k):
            out[k + " (host)"] = url_host(envmap[k])
    return out


def _not_a_secret(val: str) -> bool:
    v = val.strip()
    return bool(_UUID.match(v) or _DIGEST.match(v) or v.lower() in _TRIVIAL_VALUES)


def secret_values(envmaps) -> tuple:
    """Collect secret values (in memory only) from one or more KEY->VALUE maps.

    Returns (values, weak_keys): `values` maps each secret value scanned for in
    the output to the KEY NAME it came from; `weak_keys` names secret keys whose
    value is too short or a common word to scan for safely. UUID and digest
    shaped values are identifiers, not secrets, and are skipped.
    """
    values, weak = {}, set()
    for envmap in envmaps:
        for key, val in envmap.items():
            if not val or key in ENV_WHITELIST:
                continue
            cands = []
            m = _URL_CREDS.search(val)
            if m:
                userinfo = m.group(2)
                if ":" in userinfo:
                    cands.append(userinfo.split(":", 1)[1])
            if _SECRET_ENV_KEY.search(key.upper()):
                cands.append(val)
            elif (len(val) >= 20 and re.fullmatch(r"[A-Za-z0-9+/=_.-]+", val)
                  and re.search(r"[A-Za-z]", val) and re.search(r"[0-9]", val)
                  and not re.fullmatch(r"[0-9.:-]+", val)):
                cands.append(val)  # high-entropy token under an innocuous name
            for c in cands:
                if _UUID.match(c.strip()) or _DIGEST.match(c.strip()):
                    continue
                if len(c) < 8 or _not_a_secret(c):
                    weak.add(key)
                else:
                    values.setdefault(c, key)
    return values, weak


def _b64_aligned(b: bytes):
    """The base64 text of `b` at each of the three byte alignments.

    Only the characters fully determined by `b` are kept, so the secret is
    found inside a longer base64 blob (a basic-auth header, a JSON file).
    """
    n = len(b)
    for k in range(3):
        enc = base64.b64encode(b"\0" * k + b + b"\0\0").decode()
        start = (8 * k + 5) // 6
        end = (8 * (k + n)) // 6
        if end - start >= 8:
            yield enc[start:end]


def secret_variants(secret: str):
    """Forms a secret can take in output: plain, JSON-escaped, URL-encoded, hex, base64."""
    seen = set()
    b = secret.encode("utf-8", "replace")
    forms = [("plain", secret),
             ("json", json.dumps(secret)[1:-1]),
             ("json-unicode", json.dumps(secret, ensure_ascii=False)[1:-1]),
             ("urlencoded", urllib.parse.quote(secret, safe="")),
             ("hex", b.hex())]
    forms += [("base64", v) for v in _b64_aligned(b)]
    for form, v in forms:
        if v and v not in seen and len(v) >= 8:
            seen.add(v)
            yield form, v


def self_scan(blobs: dict, secrets) -> list:
    """Return [(member, reason)] for every secret found in the output blobs.

    `secrets` maps each secret value to the name of the key it came from (a
    plain set is accepted too). Each secret is checked in every form it can be
    written in (see secret_variants), and secret-shaped material (private
    keys, JWTs, SAS keys, AWS key ids) is checked by shape. Reasons name the
    key, never the value.
    """
    if not isinstance(secrets, dict):
        secrets = {s: f"secret #{i + 1}" for i, s in enumerate(sorted(s for s in secrets if s))}
    hits = []
    for member, data in blobs.items():
        text = data.decode("utf-8", "replace") if isinstance(data, bytes) else str(data)
        for secret, key in sorted(secrets.items(), key=lambda kv: kv[1]):
            for form, v in secret_variants(secret):
                if v in text:
                    hits.append((member, f"value of {key} ({form} form)"))
                    break
        for kind, rx in SECRET_SHAPES:
            if rx.search(text):
                hits.append((member, f"{kind} shaped value"))
        for reason in url_secret_findings(text):
            hits.append((member, reason))
    return hits


def detect_layout(install_dir, envmap: dict, exists=os.path.exists) -> dict:
    """Classify the install: open/enterprise, git checkout/bundle, or managed."""
    info = {"layout": "unknown", "evidence": []}
    if not install_dir:
        info["evidence"].append("no install directory found")
        return info
    d = install_dir.rstrip("/")
    j = lambda *p: os.path.join(d, *p)  # noqa: E731
    is_git = exists(j(".git"))
    ent_lock = exists(j("images.enterprise.lock")) or exists(j("images.enterprise.customer.lock"))
    open_compose = exists(j("docker-compose.opensource.yml"))
    edition = (envmap.get("NANO_EDITION") or "").strip().lower()
    if d == "/opt/nanosiem" or ("IMAGE_TAG" in envmap and "NANO_VERSION" not in envmap):
        info["layout"] = "managed"
        info["evidence"].append("/opt/nanosiem path or IMAGE_TAG in .env")
    elif is_git:
        info["layout"] = "enterprise-git-checkout" if edition == "enterprise" else "open-git-checkout"
        info["evidence"].append(".git present")
    elif ent_lock or edition == "enterprise":
        info["layout"] = "enterprise-bundle"
        info["evidence"].append("enterprise image lock or NANO_EDITION=enterprise")
    elif open_compose or exists(j("images.lock")):
        info["layout"] = "open-bundle"
        info["evidence"].append("docker-compose.opensource.yml / images.lock without .git")
    if open_compose:
        info["evidence"].append("docker-compose.opensource.yml present")
    return info


def detect_edition(envmap: dict, layout: str, image_refs) -> str:
    ed = (envmap.get("NANO_EDITION") or "").strip().lower()
    if ed:
        return ed
    if layout.startswith("enterprise") or layout == "managed":
        return "enterprise"
    for ref in image_refs:
        if re.search(r"/nano-(api|search|jobs|web)(:|@|$)", ref or ""):
            return "open"
    return "unknown"


def image_repository(ref: str) -> str:
    """`registry:5000/org/nano-api:tag@sha256:..` -> `registry:5000/org/nano-api`."""
    ref = (ref or "").split("@", 1)[0]
    slash = ref.rfind("/")
    colon = ref.rfind(":")
    return ref[:colon] if colon > slash else ref


def image_prefix(image_refs, envmap: dict):
    if envmap.get("NANO_IMAGE_PREFIX"):
        return envmap["NANO_IMAGE_PREFIX"]
    for ref in image_refs:
        m = re.match(r"^(.*)/(nano|nanosiem)-api$", image_repository(ref))
        if m:
            return f"{m.group(1)}/{m.group(2)}-"
    return None


def day_label(partition: str):
    p = str(partition).strip("'\"")
    if re.fullmatch(r"\d{8}", p):
        return f"{p[:4]}-{p[4:6]}-{p[6:]}"
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", p):
        return p
    return None


# Calibration for the OCSF legacy backfill (NAN-5556 rehearsal): 4.44M rows took
# 1.28 GiB in the 1.8 legacy table and 1.07 GiB in the new ocsf_logs (0.84x).
# The new table keeps the full `event` JSON (EPHEMERAL in 1.8), so the ratio
# depends on the sources; without a measured ratio we assume 1.25x the legacy
# on-disk size (about 1.5x the measured ratio).
BACKFILL_DEFAULT_MULTIPLIER = 1.25


def backfill_estimate(days, new_bytes_per_row=None) -> dict:
    """Free disk needed by the OCSF legacy backfill.

    Each UTC day is rebuilt into a staging table and published with ATTACH
    PARTITION FROM, which hardlinks the staged parts (no second copy). The
    legacy table stays until it is dropped after the copy, so the new copy of
    every day is extra space, plus headroom for the largest day being staged
    and merged. When new-format partitions already exist, their bytes per row
    size the copy; otherwise a stated conservative multiplier is used.
    """
    sizes = [int(d.get("bytes_on_disk") or 0) for d in days]
    rows = [int(d.get("rows") or 0) for d in days]
    legacy_total = sum(sizes)
    legacy_largest = max(sizes) if sizes else 0
    if new_bytes_per_row:
        new_total = int(sum(rows) * new_bytes_per_row)
        new_largest = int(max(rows) * new_bytes_per_row) if rows else 0
        basis = f"measured {new_bytes_per_row:.1f} bytes/row in the existing new-format ocsf_logs"
    else:
        new_total = int(legacy_total * BACKFILL_DEFAULT_MULTIPLIER)
        new_largest = int(legacy_largest * BACKFILL_DEFAULT_MULTIPLIER)
        basis = (f"{BACKFILL_DEFAULT_MULTIPLIER}x the legacy on-disk size (rehearsal measured 0.84x; the new "
                 "table keeps the full event JSON, so the ratio varies by source)")
    return {
        "legacy_bytes_on_disk": legacy_total,
        "legacy_rows": sum(rows),
        "largest_day_bytes": legacy_largest,
        "estimated_new_table_bytes": new_total,
        "estimated_largest_day_new_bytes": new_largest,
        "estimated_free_bytes_needed": new_total + new_largest,
        "basis": basis,
        "method": ("estimated size of every legacy day rewritten into the new ocsf_logs (" + basis + ") plus "
                   "the largest day again as staging and merge headroom. Staging is published with ATTACH "
                   "PARTITION FROM, which hardlinks parts. The legacy table stays until it is dropped after "
                   "the copy, so its space is not freed during the backfill."),
    }


def human_bytes(n) -> str:
    if n is None:
        return "n/a"
    n = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024 or unit == "TiB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TiB"


def _secret_header_entry(d: dict) -> bool:
    for nk in ("name", "key", "header"):
        nv = d.get(nk)
        if isinstance(nv, str) and (is_secret_name(nv) or nv.strip().lower() in _SECRET_HEADER_NAMES):
            return True
    return False


def scrub_value(value, scrub_keys: bool, redactions: list, path: str, code: bool = False):
    """Strip URL credentials and secret-shaped strings everywhere; in config-like
    JSON also drop secret-named keys and the `value` of secret-named headers."""
    if isinstance(value, str):
        new = strip_url_credentials(value)
        if new != value:
            redactions.append(f"{path}: URL credentials removed")
        new, kinds = redact_shapes(new, code=code)
        for k in kinds:
            redactions.append(f"{path}: {k} redacted")
        return new
    if isinstance(value, list):
        return [scrub_value(v, scrub_keys, redactions, f"{path}[]", code) for v in value]
    if isinstance(value, dict):
        drop_value = scrub_keys and _secret_header_entry(value)
        # A header entry {name|key: ..., value: ...} keeps its name field.
        header_like = scrub_keys and any(k in value for k in ("value", "val", "values")) and any(
            isinstance(value.get(nk), str) for nk in ("name", "key", "header"))
        out = {}
        for k, v in value.items():
            if header_like and k in ("name", "key", "header"):
                out[k] = scrub_value(v, scrub_keys, redactions, f"{path}.{k}", code)
                continue
            if scrub_keys and is_secret_name(k):
                redactions.append(f"{path}.{k}: removed")
                continue
            if drop_value and k in ("value", "val", "values"):
                redactions.append(f"{path}.{k}: removed (secret header)")
                continue
            out[k] = scrub_value(v, scrub_keys, redactions, f"{path}.{k}", code)
        return out
    return value


def scrub_row(table: str, row: dict, redactions: list) -> dict:
    out = {}
    for col, val in row.items():
        if is_secret_name(col):  # defense in depth; SQL already excludes them
            redactions.append(f"{table}.{col}: removed")
            continue
        out[col] = scrub_value(val, bool(CONFIG_JSON_COLUMN.search(col)), redactions, f"{table}.{col}",
                               code=col in CODE_COLUMNS)
    return out


def safe_filename(value) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value)).strip("._")
    return s[:120] or "item"


# --------------------------------------------------------------------------
# Process runner (fakeable)
# --------------------------------------------------------------------------

class Runner:
    def run(self, argv, stdin=None, env_extra=None, timeout=180):
        env = dict(os.environ)
        if env_extra:
            env.update(env_extra)
        try:
            p = subprocess.run(argv, input=stdin, capture_output=True, text=True,
                               env=env, timeout=timeout)
            return p.returncode, p.stdout, p.stderr
        except FileNotFoundError:
            return 127, "", f"{argv[0]}: not found"
        except subprocess.TimeoutExpired:
            return 124, "", "timed out"


# --------------------------------------------------------------------------
# Database access, read only
# --------------------------------------------------------------------------

class DbError(RuntimeError):
    pass


def _quote_ident(name: str) -> str:
    if not _IDENT.match(name):
        raise DbError(f"refusing unexpected identifier {name!r}")
    return '"' + name + '"'


def _sql_lit(s: str) -> str:
    return "'" + str(s).replace("'", "''") + "'"


class Pg:
    """psql inside the PostgreSQL container. Every session is BEGIN READ ONLY.

    Credentials: first the container's own POSTGRES_USER over the local socket
    (no password); then the .env user/password passed through the environment
    (`docker exec -e PGPASSWORD`), never on a command line.
    """

    _SOCKET = ('exec psql -X -q -v ON_ERROR_STOP=1 -A -t '
               '-U "${POSTGRES_USER:-postgres}" -d "${POSTGRES_DB:-${POSTGRES_USER:-postgres}}"')
    _TCP = ('exec psql -X -q -v ON_ERROR_STOP=1 -A -t -h 127.0.0.1 '
            '-U "$NANO_RO_PGUSER" -d "$NANO_RO_PGDB"')

    def __init__(self, runner, container: str, envmap: dict):
        self.r, self.c, self.env = runner, container, envmap
        self.mode = None
        self._cols = None

    def _exec(self, sql: str, mode: str):
        body = ("BEGIN TRANSACTION READ ONLY;\nSET LOCAL statement_timeout = '300s';\n"
                f"{sql}\nCOMMIT;\n")
        if mode == "socket":
            return self.r.run(["docker", "exec", "-i", self.c, "sh", "-c", self._SOCKET], stdin=body)
        extra = {"PGPASSWORD": self.env.get("POSTGRES_PASSWORD", ""),
                 "NANO_RO_PGUSER": self.env.get("POSTGRES_USER") or "nanosiem",
                 "NANO_RO_PGDB": self.env.get("POSTGRES_DB") or self.env.get("POSTGRES_USER") or "nanosiem"}
        return self.r.run(["docker", "exec", "-i", "-e", "PGPASSWORD", "-e", "NANO_RO_PGUSER",
                           "-e", "NANO_RO_PGDB", self.c, "sh", "-c", self._TCP],
                          stdin=body, env_extra=extra)

    def connect(self) -> str:
        errs = []
        modes = ["socket"] + (["tcp"] if self.env.get("POSTGRES_PASSWORD") else [])
        for mode in modes:
            rc, out, err = self._exec("SELECT 1;", mode)
            if rc == 0 and out.strip() == "1":
                self.mode = mode
                return mode
            errs.append(f"{mode}: {(err or out).strip()[:200]}")
        raise DbError("PostgreSQL not reachable read-only: " + "; ".join(errs))

    def query(self, sql: str):
        """Rows of a SELECT as a list of dicts (json_agg on the server)."""
        wrapped = f"SELECT coalesce(json_agg(q), '[]'::json) FROM ({sql}) q;"
        rc, out, err = self._exec(wrapped, self.mode or "socket")
        if rc != 0:
            raise DbError((err or out).strip()[:400])
        text = out.strip()
        return json.loads(text) if text else []

    def scalar(self, sql: str):
        rows = self.query(sql)
        if not rows:
            return None
        return next(iter(rows[0].values()))

    def columns(self) -> dict:
        """{table: [(column, data_type)]} for the current schema."""
        if self._cols is None:
            rows = self.query(
                "SELECT table_name AS t, column_name AS c, data_type AS d FROM information_schema.columns "
                "WHERE table_schema = current_schema() ORDER BY table_name, ordinal_position")
            cols = {}
            for r in rows:
                cols.setdefault(r["t"], []).append((r["c"], r["d"]))
            self._cols = cols
        return self._cols

    def rows(self, table: str, exclude, where=None, limit=None):
        sql = "SELECT to_jsonb(t)"
        for col in exclude:
            sql += f" - {_sql_lit(col)}"
        sql += f" AS item FROM {_quote_ident(table)} t"
        if where:
            sql += f" WHERE {where}"
        if limit is not None:
            sql += f" LIMIT {int(limit)}"
        return [r["item"] for r in self.query(sql)]


class Ch:
    """clickhouse-client inside the ClickHouse container, readonly=1.

    The password is handed to clickhouse-client through its CLICKHOUSE_PASSWORD
    environment variable from the container's own env (or from .env through
    `docker exec -e`), never on a command line.
    """

    CANDIDATES = (
        ("nanosiem", "CLICKHOUSE_NANOSIEM_PASSWORD"),
        ("nanosiem", "CLICKHOUSE_PASSWORD"),
        ("nanosiem_admin", "CLICKHOUSE_ADMIN_PASSWORD"),
    )

    def __init__(self, runner, container: str, envmap: dict, database: str):
        self.r, self.c, self.env, self.db = runner, container, envmap, database
        self.cmd = None
        self.user = None
        self.readonly = None

    @staticmethod
    def _script(user: str, var: str, set_readonly: bool) -> str:
        ro = " --readonly=1" if set_readonly else ""
        return (f'[ -n "${{{var}:-}}" ] || exit 97; CLICKHOUSE_USER={user} '
                f'CLICKHOUSE_PASSWORD="${var}" exec clickhouse-client{ro} '
                '--max_execution_time=300 --output_format_json_quote_64bit_integers=0')

    def _attempts(self):
        """Credential candidates. Each is tried with --readonly=1, then without
        the flag for a user whose profile is already read only (setting it again
        can be refused); connect() accepts only a session with readonly >= 1."""
        for user, var in self.CANDIDATES:
            for flag in (True, False):
                yield user, (["docker", "exec", "-i", self.c, "sh", "-c", self._script(user, var, flag)], None)
        if self.env.get("CLICKHOUSE_PASSWORD"):
            user = self.env.get("CLICKHOUSE_USER") or "nanosiem"
            if re.match(r"^[A-Za-z0-9_]+$", user):
                for flag in (True, False):
                    yield user, (["docker", "exec", "-i", "-e", "NANO_RO_CH_PASSWORD", self.c, "sh", "-c",
                                  self._script(user, "NANO_RO_CH_PASSWORD", flag)],
                                 {"NANO_RO_CH_PASSWORD": self.env["CLICKHOUSE_PASSWORD"]})

    def connect(self) -> str:
        errs = []
        for user, (argv, extra) in self._attempts():
            rc, out, err = self.r.run(argv, stdin="SELECT getSetting('readonly') FORMAT TSV", env_extra=extra)
            if rc == 0:
                try:
                    level = int(out.strip())
                except ValueError:
                    level = 0
                if level >= 1:
                    self.cmd, self.user, self.readonly = (argv, extra), user, level
                    return user
                errs.append(f"{user}: session is not read only (readonly={level}); not used")
            elif rc != 97:
                errs.append(f"{user}: {((err or out).strip().splitlines() or ['?'])[-1]}"[:200])
        raise DbError("ClickHouse not reachable read-only: " + "; ".join(errs[-3:]))

    def query(self, sql: str):
        argv, extra = self.cmd
        rc, out, err = self.r.run(argv, stdin=sql.rstrip().rstrip(";") + " FORMAT JSONEachRow",
                                  env_extra=extra)
        if rc != 0:
            raise DbError((err or out).strip()[:400])
        return [json.loads(line) for line in out.splitlines() if line.strip()]


# --------------------------------------------------------------------------
# Discovery
# --------------------------------------------------------------------------

class Collector:
    def __init__(self, args, runner=None):
        self.args = args
        self.r = runner or Runner()
        self.errors = []
        self.flags = []
        self.env = {}
        self.install_dir = None
        self.containers = []
        self.pg = None
        self.ch = None
        self.container_secret_envs = []

    # -- generic helpers --
    def flag(self, level: str, code: str, message: str):
        self.flags.append({"level": level, "code": code, "message": message})

    def redact_text(self, text: str) -> str:
        """URL credentials, secret shapes and every known secret value removed."""
        text, _ = redact_shapes(strip_url_credentials(str(text)))
        values, _ = self.secrets()
        for secret in sorted(values, key=len, reverse=True):
            for _form, v in secret_variants(secret):
                text = text.replace(v, REDACTED)
        return text

    def err(self, where: str, e):
        msg = self.redact_text(e)
        self.errors.append({"where": where, "error": msg[:500]})
        log(f"{where}: {msg[:200]}")

    def cmd(self, argv, timeout=60, env_extra=None):
        rc, out, err = self.r.run(argv, timeout=timeout, env_extra=env_extra)
        return out.strip() if rc == 0 else None

    # -- containers --
    def discover_containers(self):
        out = self.cmd(["docker", "ps", "-a", "--format", "{{json .}}"])
        if out is None:
            raise DbError("`docker ps` failed: is Docker running and is this user allowed to use it?")
        rows = []
        for line in out.splitlines():
            try:
                rows.append(json.loads(line))
            except ValueError:
                continue
        wanted = []
        for r in rows:
            name = r.get("Names", "")
            labels = r.get("Labels", "") or ""
            # Named nano-*/nanosiem-*, or a Compose service of a renamed project.
            if re.match(r"^(nano|nanosiem)[-_]", name) or re.search(
                    r"(^|,)com\.docker\.compose\.service=(nano-)?(postgres|clickhouse|api|search|jobs|web|vector)(,|$)",
                    labels):
                wanted.append(name)
        if not wanted:
            return
        fmt = ('{"name":{{json .Name}},"image":{{json .Config.Image}},"image_id":{{json .Image}},'
               '"state":{{json .State.Status}},"health":{{if .State.Health}}{{json .State.Health.Status}}'
               '{{else}}""{{end}},"labels":{{json .Config.Labels}}}')
        out = self.cmd(["docker", "inspect", "--format", fmt] + wanted)
        for line in (out or "").splitlines():
            try:
                c = json.loads(line)
            except ValueError:
                continue
            labels = c.pop("labels", None) or {}
            c["name"] = c["name"].lstrip("/")
            c["service"] = labels.get("com.docker.compose.service", "")
            c["project"] = labels.get("com.docker.compose.project", "")
            c["working_dir"] = labels.get("com.docker.compose.project.working_dir", "")
            c["config_files"] = labels.get("com.docker.compose.project.config_files", "")
            c["image"] = strip_url_credentials(c.get("image") or "")
            self.containers.append(c)
        ids = sorted({c["image_id"] for c in self.containers if c.get("image_id")})
        if ids:
            out = self.cmd(["docker", "image", "inspect", "--format",
                            '{"id":{{json .Id}},"digests":{{json .RepoDigests}},"created":{{json .Created}}}'] + ids)
            meta = {}
            for line in (out or "").splitlines():
                try:
                    m = json.loads(line)
                    meta[m["id"]] = m
                except (ValueError, KeyError):
                    continue
            for c in self.containers:
                m = meta.get(c.get("image_id"), {})
                c["repo_digests"] = m.get("digests") or []
                c["image_created"] = m.get("created")

    def find_container(self, override, service_names, name_candidates):
        if override:
            return override
        running = [c for c in self.containers if c.get("state") == "running"]
        for n in name_candidates:
            for c in running:
                if c["name"] == n:
                    return n
        for c in running:
            if c.get("service") in service_names:
                return c["name"]
        return None

    def container_env_secrets(self, name):
        """Read a container's env IN MEMORY ONLY, for the self-scan."""
        out = self.cmd(["docker", "inspect", "--format", "{{json .Config.Env}}", name])
        envmap = {}
        try:
            for item in json.loads(out or "[]") or []:
                k, _, v = item.partition("=")
                envmap[k] = v
        except ValueError:
            pass
        return envmap

    # -- install dir --
    def resolve_install_dir(self):
        cands = []
        if self.args.install_dir:
            cands.append(self.args.install_dir)
        for c in self.containers:
            if c.get("working_dir") and c.get("service") in ("postgres", "clickhouse", "api", "nano-api"):
                cands.append(c["working_dir"])
        here = os.path.dirname(os.path.abspath(__file__))
        if os.path.basename(here) == "scripts":
            cands.append(os.path.dirname(here))
        cands += [os.getcwd(), os.path.expanduser("~/nano"), "/opt/nanosiem", "/opt/nano"]
        for d in cands:
            try:
                ok = d and os.path.isdir(d) and (os.path.isfile(os.path.join(d, ".env")) or any(
                    n.startswith("docker-compose") for n in os.listdir(d)))
            except OSError:
                ok = False
            if ok:
                self.install_dir = os.path.realpath(d)
                return
        self.flag("warn", "install_dir_not_found", "No install directory with a .env was found; "
                  "pass --install-dir DIR.")

    def read_env(self):
        if not self.install_dir:
            return
        path = os.path.join(self.install_dir, ".env")
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                self.env = parse_env_file(fh.read())
        except OSError as e:
            self.flag("warn", "env_unreadable", f".env not readable ({e.strerror}); versions and "
                      "credentials from .env are unavailable. Run as the install owner.")

    def read_file(self, *parts):
        try:
            with open(os.path.join(self.install_dir, *parts), encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except (OSError, TypeError):
            return None

    # -- connect --
    def connect_dbs(self):
        pg_name = self.find_container(self.args.pg_container, ("postgres", "nano-postgres"),
                                      ("nano-postgres", "nanosiem-postgres"))
        ch_name = self.find_container(self.args.ch_container, ("clickhouse", "nano-clickhouse"),
                                      ("nano-clickhouse", "nanosiem-clickhouse"))
        if pg_name:
            self.container_secret_envs.append(self.container_env_secrets(pg_name))
            self.pg = Pg(self.r, pg_name, self.env)
            try:
                self.pg.connect()
            except DbError as e:
                self.err("postgres", e)
                self.pg = None
        else:
            self.err("postgres", "no running PostgreSQL container found (use --pg-container)")
        db = self.args.ch_database or self.env.get("CLICKHOUSE_DATABASE") or "nanosiem"
        if not _IDENT.match(db):
            db = "nanosiem"
        if ch_name:
            self.container_secret_envs.append(self.container_env_secrets(ch_name))
            self.ch = Ch(self.r, ch_name, self.env, db)
            try:
                self.ch.connect()
            except DbError as e:
                self.err("clickhouse", e)
                self.ch = None
        else:
            self.err("clickhouse", "no running ClickHouse container found (use --ch-container)")
        return pg_name, ch_name

    def secrets(self):
        return secret_values([self.env] + self.container_secret_envs)


# --------------------------------------------------------------------------
# Report sections
# --------------------------------------------------------------------------

def collect_host(col: Collector, ch_name, pg_name) -> dict:
    h = {"hostname": socket.gethostname(), "architecture": platform.machine(),
         "kernel": platform.release(), "python": platform.python_version(),
         "cpu_count": os.cpu_count()}
    try:
        with open("/proc/cpuinfo", encoding="utf-8", errors="replace") as fh:
            flags = set()
            for line in fh:
                if line.startswith(("flags", "Features")):
                    flags.update(line.split(":", 1)[1].split())
        h["cpu_flags"] = {f: f in flags for f in ("avx2", "sse4_2", "avx512f", "asimd")}
    except OSError:
        h["cpu_flags"] = None
    try:
        with open("/proc/meminfo", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("MemTotal:"):
                    h["ram_bytes"] = int(line.split()[1]) * 1024
    except OSError:
        h["ram_bytes"] = None
    try:
        with open("/etc/os-release", encoding="utf-8") as fh:
            osr = parse_env_file(fh.read())
        h["os"] = osr.get("PRETTY_NAME") or osr.get("NAME")
    except OSError:
        h["os"] = platform.platform()
    h["docker_version"] = col.cmd(["docker", "version", "--format", "{{.Server.Version}}"])
    h["compose_version"] = (col.cmd(["docker", "compose", "version", "--short"])
                            or col.cmd(["docker-compose", "version", "--short"]))
    h["docker_root_dir"] = col.cmd(["docker", "info", "--format", "{{.DockerRootDir}}"])
    disks = {}

    def statfs(label, path):
        if not path:
            return
        try:
            u = shutil.disk_usage(path)
            disks[label] = {"path": path, "free_bytes": u.free, "total_bytes": u.total}
        except OSError:
            out = col.cmd(["df", "-Pk", path])
            parsed = _parse_df(out)
            if parsed:
                parsed["path"] = path
                disks[label] = parsed

    statfs("install_dir", col.install_dir)
    statfs("docker_root", h["docker_root_dir"])
    for label, cname, path in (("clickhouse_data", ch_name, "/var/lib/clickhouse"),
                               ("postgres_data", pg_name, "/var/lib/postgresql/data")):
        if cname:
            parsed = _parse_df(col.cmd(["docker", "exec", cname, "df", "-Pk", path]))
            if parsed:
                parsed["path"] = f"{cname}:{path}"
                disks[label] = parsed
    h["disks"] = disks
    return h


def _parse_df(out):
    if not out:
        return None
    lines = out.strip().splitlines()
    if len(lines) < 2:
        return None
    f = lines[-1].split()
    try:
        return {"total_bytes": int(f[1]) * 1024, "free_bytes": int(f[3]) * 1024, "mount": f[-1]}
    except (IndexError, ValueError):
        return None


def collect_install(col: Collector) -> dict:
    env = col.env
    refs = [c.get("image", "") for c in col.containers]
    lay = detect_layout(col.install_dir, env)
    projects = sorted({c["project"] for c in col.containers if c.get("project")})
    info = {
        "install_dir": col.install_dir,
        "layout": lay["layout"],
        "layout_evidence": lay["evidence"],
        "edition": detect_edition(env, lay["layout"], refs),
        "schema_profile": env.get("NANO_SCHEMA_PROFILE") or None,
        "compose_project": (projects[0] if len(projects) == 1 else projects) or env.get("COMPOSE_PROJECT_NAME")
        or (os.path.basename(col.install_dir) if col.install_dir else None),
        "compose_files": sorted({f for c in col.containers for f in (c.get("config_files") or "").split(",") if f}),
        "env": safe_env(env),
        "env_keys_present": sorted(env.keys()),
        "image_prefix": image_prefix(refs, env),
    }
    if col.install_dir and os.path.isdir(os.path.join(col.install_dir, ".git")):
        info["git"] = collect_git(col)
    # Version markers in the install dir.
    cargo = col.read_file("Cargo.toml") or ""
    m = re.search(r'(?m)^version\s*=\s*"([^"]+)"', cargo)
    lock = col.read_file("images.lock") or ""
    rel = re.search(r"(?m)^#\s*Release:\s*(\S+)", lock)
    lock_digests = {}
    for line in lock.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].startswith("sha256:"):
            lock_digests[parts[0]] = parts[1]
    info["checkout_version"] = m.group(1) if m else None
    info["images_lock_release"] = rel.group(1) if rel else None
    containers = []
    matches = []
    for c in col.containers:
        row = {k: c.get(k) for k in ("name", "service", "project", "state", "health", "image",
                                     "image_id", "repo_digests", "image_created")}
        repo = image_repository(c.get("image") or "")
        if repo in lock_digests:
            ok = any(d.endswith(lock_digests[repo]) for d in c.get("repo_digests") or [])
            row["matches_images_lock"] = ok
            matches.append(ok)
        containers.append(row)
    info["containers"] = containers
    info["running_images_match_images_lock"] = all(matches) if matches else None
    return info


def collect_git(col: Collector) -> dict:
    d = col.install_dir
    base = ["git", "-c", f"safe.directory={d}", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
            "-C", d]
    ro = {"GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0"}
    g = {
        "commit": col.cmd(base + ["rev-parse", "HEAD"], env_extra=ro),
        "branch": col.cmd(base + ["rev-parse", "--abbrev-ref", "HEAD"], env_extra=ro),
        "describe": col.cmd(base + ["describe", "--tags", "--always"], env_extra=ro),
        "remote": strip_url_credentials(col.cmd(base + ["remote", "get-url", "origin"], env_extra=ro) or "") or None,
    }
    st = col.r.run(base + ["status", "--porcelain=v1", "--untracked-files=normal"], env_extra=ro)
    files = []
    if st[0] == 0:
        for line in st[1].splitlines():
            if len(line) > 3:
                files.append({"status": line[:2].strip(), "path": line[3:]})
    g["local_changes"] = files[:300]
    g["local_changes_count"] = len(files)
    return g


def collect_pg(col: Collector) -> dict:
    pg = col.pg
    out = {}
    cols = pg.columns()
    tables = set(cols)
    out["server_version"] = pg.scalar("SELECT current_setting('server_version') AS v")
    out["database_size_bytes"] = pg.scalar("SELECT pg_database_size(current_database()) AS s")
    if "_sqlx_migrations" in tables:
        r = pg.query("SELECT max(version) AS max_version, count(*) AS applied, "
                     "count(*) FILTER (WHERE NOT success) AS failed FROM _sqlx_migrations")[0]
        out["sqlx_migrations"] = r
    out["table_count"] = len(tables)

    def count(table, where=None):
        if table not in tables:
            return None
        sql = f"SELECT count(*) AS n FROM {_quote_ident(table)}"
        if where:
            sql += f" WHERE {where}"
        try:
            return pg.scalar(sql)
        except DbError as e:
            col.err(f"count {table}", e)
            return None

    def has(table, column):
        return any(c == column for c, _ in cols.get(table, []))

    c = {}
    c["parsers_log_sources"] = count("log_sources")
    if has("log_sources", "enabled"):
        c["parsers_log_sources_enabled"] = count("log_sources", "enabled IS TRUE")
    c["parsers_table"] = count("parsers")
    c["parser_versions"] = count("log_source_versions")
    c["source_configurations"] = count("source_configurations")
    c["routing_rules"] = count("routing_rules")
    c["feeds"] = count("feeds")
    if "detection_rules" in tables:
        c["detection_rules_total"] = count("detection_rules")
        where = "WHERE archived IS NOT TRUE" if has("detection_rules", "archived") else ""
        if has("detection_rules", "mode"):
            rows = pg.query(f"SELECT coalesce(mode, 'unset') AS mode, count(*) AS n "
                            f"FROM detection_rules {where} GROUP BY 1 ORDER BY 1")
            c["detection_rules_by_mode"] = {r["mode"]: r["n"] for r in rows}
        if has("detection_rules", "archived"):
            c["detection_rules_archived"] = count("detection_rules", "archived IS TRUE")
    if "ingest_tokens" in tables:
        c["ingest_tokens"] = count("ingest_tokens")
    else:
        c["ingest_tokens"] = None
        c["ingest_tokens_note"] = "no ingest_tokens table: this version uses one shared Vector token"
    c["users"] = count("users")
    c["api_keys"] = count("api_keys")
    c["dashboards"] = count("dashboards")
    c["saved_searches"] = count("saved_searches")
    c["case_saved_searches"] = count("case_saved_searches")
    if has("query_library", "is_builtin"):
        c["query_library_custom"] = count("query_library", "is_builtin IS NOT TRUE")
    c["lookups"] = count("lookup_tables_registry")
    c["cases"] = count("cases")
    c["alerts"] = count("alerts")
    c["report_definitions"] = count("report_definitions")
    out["content_counts"] = {k: v for k, v in c.items() if v is not None or k.startswith("ingest")}
    # Retention configured in the app.
    if "system_settings" in tables:
        want = [x for x in ("retention_enabled", "retention_days", "tier") if has("system_settings", x)]
        if want:
            try:
                out["system_settings"] = pg.query(
                    "SELECT " + ", ".join(_quote_ident(w) for w in want) + " FROM system_settings")
            except DbError as e:
                col.err("system_settings", e)
    # License presence (never the raw response).
    lic = {}
    if "license_status" in tables:
        want = [x for x in ("status", "valid", "tier", "expires_at", "offline", "last_checked_at")
                if has("license_status", x)]
        try:
            lic["license_status"] = pg.query(
                "SELECT " + ", ".join(_quote_ident(w) for w in want) + " FROM license_status") if want else []
        except DbError as e:
            col.err("license_status", e)
    for t in ("sovereign_license_state", "sovereign_license_installation"):
        if t in tables:
            lic[t + "_rows"] = count(t)
    out["license"] = lic
    return out


def collect_ch(col: Collector, legacy_hint: bool) -> dict:
    ch = col.ch
    db = ch.db
    out = {"database": db, "user": ch.user}
    out["server_version"] = ch.query("SELECT version() AS v")[0]["v"]
    tables = {r["name"]: r for r in ch.query(
        f"SELECT name, engine, partition_key, engine_full FROM system.tables "
        f"WHERE database = {_sql_lit(db)} AND NOT is_temporary")}
    if "_migrations" in tables:
        try:
            out["migrations"] = ch.query(
                f"SELECT count() AS applied, max(toUInt64OrZero(version)) AS max_version, "
                f"groupArrayIf(version, startsWith(version, '__')) AS markers FROM {db}._migrations")[0]
        except DbError as e:
            col.err("clickhouse _migrations", e)
    # Only the system.parts columns the app user is granted on every version:
    # active, bytes_on_disk, data_uncompressed_bytes, database, partition, rows, table.
    # bytes_on_disk is the compressed size on disk.
    parts = {}
    try:
        parts = {r["table"]: r for r in ch.query(
            f"SELECT table, count(partition) AS parts, sum(rows) AS rows, sum(bytes_on_disk) AS bytes_on_disk, "
            f"sum(data_uncompressed_bytes) AS uncompressed_bytes "
            f"FROM system.parts WHERE database = {_sql_lit(db)} AND active GROUP BY table")}
    except DbError as e:
        col.err("clickhouse system.parts", e)
    tbl_out = {}
    for name, t in sorted(tables.items()):
        if "MergeTree" not in (t.get("engine") or ""):
            continue
        row = {"engine": t["engine"], "partition_key": t.get("partition_key")}
        ttl = re.search(r"\bTTL\s+(.+?)(?:\s+SETTINGS\s|$)", t.get("engine_full") or "")
        if ttl:
            row["ttl"] = ttl.group(1).strip()
        row.update({k: v for k, v in parts.get(name, {}).items() if k != "table"})
        tbl_out[name] = row
    out["tables"] = tbl_out
    out["total_bytes_on_disk"] = sum(int(p.get("bytes_on_disk") or 0) for p in parts.values())
    ev = [t for t in EVENT_TABLES if t in tables]
    days = {}
    if ev:
        try:
            rows = ch.query(
                f"SELECT table, partition, sum(rows) AS rows, sum(bytes_on_disk) AS bytes_on_disk, "
                f"sum(data_uncompressed_bytes) AS uncompressed_bytes "
                f"FROM system.parts WHERE database = {_sql_lit(db)} AND active AND table IN "
                f"({', '.join(_sql_lit(t) for t in ev)}) GROUP BY table, partition ORDER BY table, partition")
        except DbError as e:
            col.err("clickhouse per-day volume", e)
            rows = []
        for r in rows:
            r["utc_day"] = day_label(r["partition"])
            days.setdefault(r.pop("table"), []).append(r)
        for t, lst in days.items():
            if any(r["utc_day"] is None for r in lst):
                col.flag("info", "partition_not_daily", f"{t} is not partitioned per UTC day; "
                         "the per-day table shows partitions.")
    out["event_tables_per_day"] = days
    # Which table is the OCSF 1.8 store is decided from the schema: after the
    # 2.x upgrade it is ocsf_logs_legacy_v179 (migration 180 renames it aside);
    # before, ocsf_logs is the 1.8 store while the ledger is below 180.
    ledger_max = (out.get("migrations") or {}).get("max_version")
    legacy, new_bpr, reason = None, None, None
    if "ocsf_logs_legacy_v179" in tables:
        legacy, reason = "ocsf_logs_legacy_v179", "ocsf_logs_legacy_v179 exists (upgraded, backfill pending)"
        new = out["tables"].get("ocsf_logs") or {}
        if int(new.get("rows") or 0) > 0 and int(new.get("bytes_on_disk") or 0) > 0:
            new_bpr = int(new["bytes_on_disk"]) / int(new["rows"])
    elif "ocsf_logs" in tables and ledger_max is not None and int(ledger_max) < 180:
        legacy, reason = "ocsf_logs", f"ClickHouse ledger {ledger_max} < 180: ocsf_logs is the OCSF 1.8 store"
    elif "ocsf_logs" in tables and ledger_max is None and legacy_hint:
        legacy, reason = "ocsf_logs", "no ClickHouse ledger readable; version suggests 0.1.x"
    out["ocsf_layout"] = {"legacy_table": legacy, "reason": reason or "no OCSF 1.8 store found"}
    if legacy:
        est = backfill_estimate(days.get(legacy, []), new_bpr)
        est["legacy_table"] = legacy
        out["ocsf_backfill_estimate"] = est
    return out


def version_summary(col, install, pg, ch) -> dict:
    env = col.env
    nv = env.get("NANO_VERSION") or env.get("IMAGE_TAG")
    guess, source = None, None
    # Digest-verified evidence ranks above what .env says.
    if install.get("images_lock_release") and install.get("running_images_match_images_lock"):
        guess, source = install["images_lock_release"], "images.lock (running digests match)"
    elif nv and nv not in ("latest", "main"):
        guess, source = nv, ".env"
    elif install.get("checkout_version"):
        guess, source = install["checkout_version"], "checkout Cargo.toml (running images not verified)"
    elif install.get("images_lock_release"):
        guess, source = install["images_lock_release"], "images.lock (running digests not verified)"
    return {
        "nano_version": guess.lstrip("v") if isinstance(guess, str) else guess,
        "nano_version_source": source,
        "env_version": nv,
        "checkout_version": install.get("checkout_version"),
        "images_lock_release": install.get("images_lock_release"),
        "running_images_match_images_lock": install.get("running_images_match_images_lock"),
        "pg_migration_max": ((pg or {}).get("sqlx_migrations") or {}).get("max_version"),
        "ch_migration_max": ((ch or {}).get("migrations") or {}).get("max_version"),
    }


def evaluate_flags(col, data):
    env = col.env
    host, inst = data.get("host") or {}, data.get("install") or {}
    nv = env.get("NANO_VERSION") or env.get("IMAGE_TAG")
    if nv in ("latest", "main"):
        col.flag("warn", "floating_version", f"{'NANO_VERSION' if 'NANO_VERSION' in env else 'IMAGE_TAG'}="
                 f"{nv}: do not re-run the old local install.sh or `docker compose pull`; it would pull "
                 "whatever is newest. Wait for the guided upgrade.")
    flags = host.get("cpu_flags")
    if flags is not None and host.get("architecture") in ("x86_64", "amd64") and not flags.get("avx2"):
        col.flag("warn", "no_avx2", "CPU has no AVX2; ClickHouse runs, but slower.")
    ram = host.get("ram_bytes")
    if ram and ram < 8 * 1024 ** 3:
        col.flag("warn", "low_ram", f"RAM {human_bytes(ram)} is below 8 GiB.")
    git = inst.get("git") or {}
    if git.get("local_changes_count"):
        col.flag("warn", "local_changes", f"{git['local_changes_count']} locally changed or untracked "
                 "file(s) in the checkout (listed under install.git.local_changes); the upgrade will not "
                 "carry them over.")
    disks = host.get("disks") or {}
    ch_free = (disks.get("clickhouse_data") or disks.get("docker_root") or {}).get("free_bytes")
    est = (data.get("clickhouse") or {}).get("ocsf_backfill_estimate")
    if est and ch_free is not None:
        need = est["estimated_free_bytes_needed"]
        est["clickhouse_free_bytes"] = ch_free
        est["enough_free_disk"] = ch_free >= need
        if ch_free < need:
            col.flag("warn", "backfill_disk", f"ClickHouse free disk {human_bytes(ch_free)} is below the "
                     f"estimated {human_bytes(need)} the OCSF legacy backfill needs.")
    pg = data.get("postgres") or {}
    size = pg.get("database_size_bytes")
    free = (disks.get("install_dir") or {}).get("free_bytes")
    if size is not None:
        data["postgres_backup_estimate"] = {"database_size_bytes": size, "install_dir_free_bytes": free,
                                            "note": "a compressed pg_dump is usually smaller than this"}
        if free is not None and free < size:
            col.flag("warn", "pg_backup_disk", f"free disk at the install dir {human_bytes(free)} is below "
                     f"the PostgreSQL size {human_bytes(size)}.")
    if inst.get("running_images_match_images_lock") is False:
        col.flag("info", "images_differ_from_lock", "Running images differ from the checkout's images.lock "
                 "(NANO_VERSION=latest pulled a newer image, or a manual pull).")
    if (inst.get("schema_profile") or "").lower() == "ocsf" and est and est["legacy_bytes_on_disk"]:
        col.flag("info", "ocsf_backfill", "OCSF event history will be copied day by day after the upgrade "
                 "(see clickhouse.ocsf_backfill_estimate).")
    version = str((data.get("version") or {}).get("nano_version") or inst.get("checkout_version") or nv or "")
    if version.startswith("0.") or nv in ("latest", "main"):
        col.flag("warn", "snapshot_before_upgrade", "Upgrading 0.1.x to 2.x cannot be rolled back in place. "
                 "Take a VM or disk snapshot (or, with the stack stopped, a copy of the Docker volumes) "
                 "right before the upgrade: restoring it is the rollback.")
    action = [p["label"] for p in (data.get("ingest") or {}).get("paths") or [] if p["verdict"] == VERDICT_ACTION]
    if action:
        col.flag("warn", "ingest_needs_action", "Ingest path(s) that need action before or at the upgrade: "
                 + ", ".join(action) + " (see Ingest paths).")
    if (inst.get("edition") or "open") == "open":
        col.flag("info", "convert_to_self_run", "This is the open edition. After the 2.x upgrade, "
                 "`scripts/nano convert --to enterprise` moves it to Self-run in place (same data); it needs the "
                 "license values from app.nano.rs and the enterprise package of the same release.")


# --------------------------------------------------------------------------
# Ingest paths (NAN-5559)
# --------------------------------------------------------------------------
# Which ingest paths this install actually uses, and what each one needs for
# the 2.x upgrade. Evidence, best first, every read best effort:
#   1. Vector's own counters. config/vector/92-metrics.toml runs a Prometheus
#      exporter on :9598 INSIDE the Vector container (not published on the
#      host): component_received_events_total per source component id
#      (vector_native, http_ingest, splunk_hec_ingest, otlp_ingest, ...).
#      Read with bash's /dev/tcp inside the container, so the image needs no
#      curl. The counters are cumulative since Vector last started.
#   2. The sockets of the Vector container's network namespace (/proc/net):
#      which ingest ports listen, and the peers connected right now.
#   3. nginx's access log (`docker logs`, last 7 days): requests to /ingest.
#   4. ClickHouse: events per source_type over the last 7 days. Context only:
#      0.1.x stores the type the sender declared, not the path it came in on.
# Nothing here writes or restarts anything.

VECTOR_METRICS_PORT = 9598
# Vector's minimum disk buffer (bytes); also the per-buffer default in 2.x.
SENDER_DISK_BUFFER_BYTES = 268435488
NGINX_LOG_SINCE = "168h"
NGINX_LOG_TAIL = "200000"
# Install-token values nano shipped as defaults or examples
# (config/known-public-secrets.txt, kind vector_install_token). 2.x refuses them.
KNOWN_PUBLIC_INSTALL_TOKENS = frozenset((
    "CHANGE_ME", "CHANGE_ME_GENERATED", "CHANGE_ME_GENERATE_WITH_OPENSSL_RAND_HEX_32",
    "nanosiem-default-token", "your-secret-token",
))
# Source types that are Vector's own, never a log sender.
_INTERNAL_SOURCE_TYPES = frozenset(("internal_metrics", "internal_logs", "host_metrics", "static_metrics"))
# The ingest paths every 0.1.x open install ships (component id, type, ports).
_KNOWN_SOURCE_IDS = frozenset(("vector_native", "http_ingest", "splunk_hec_ingest", "otlp_ingest"))

VERDICT_KEEPS = "keeps working"
VERDICT_ACTION = "needs action"
VERDICT_UNUSED = "unused"
VERDICT_UNKNOWN = "unknown"

VECTOR_NATIVE_BUFFER_SNIPPET = (
    "# In each upstream Vector's sink that sends to nano on port 6000:\n"
    "acknowledgements.enabled = true\n"
    "buffer.type = \"disk\"\n"
    f"buffer.max_size = {SENDER_DISK_BUFFER_BYTES}  # bytes; at least this, more for a longer window\n"
    "buffer.when_full = \"block\"\n"
)

# Fetches /metrics over bash's /dev/tcp inside the Vector container ($1 = port).
_METRICS_SCRIPT = (
    'exec 3<>"/dev/tcp/127.0.0.1/$1" || exit 1; '
    'printf "GET /metrics HTTP/1.0\\r\\nHost: localhost\\r\\nConnection: close\\r\\n\\r\\n" >&3; '
    'if command -v timeout >/dev/null 2>&1; then timeout 20 cat <&3; else cat <&3; fi'
)
_SOCKETS_SCRIPT = ("cat /proc/net/tcp /proc/net/tcp6 2>/dev/null; echo '#udp'; "
                   "cat /proc/net/udp /proc/net/udp6 2>/dev/null; true")
_METRIC_LINE = re.compile(r"^([A-Za-z_:][A-Za-z0-9_:]*)\{(.*)\}\s+(\S+)")
_LABEL = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)="((?:[^"\\]|\\.)*)"')


def metrics_port(toml_text) -> int:
    """The prometheus_exporter port in 92-metrics.toml (default 9598)."""
    for section in re.split(r"(?m)^\s*\[", toml_text or ""):
        if re.search(r'(?m)^\s*type\s*=\s*"prometheus_exporter"', section):
            m = re.search(r'(?m)^\s*address\s*=\s*"[^"]*:(\d+)"', section)
            if m:
                return int(m.group(1))
    return VECTOR_METRICS_PORT


def parse_vector_sources(text):
    """{component_id: {"type", "received_events"}} for every source in a
    Prometheus scrape. None when the text is not a scrape."""
    if not text:
        return None
    if text.startswith("HTTP/"):
        head, sep, body = text.replace("\r\n", "\n").partition("\n\n")
        if not sep or " 200" not in head.split("\n", 1)[0]:
            return None
        text = body
    sources, seen_metric = {}, False
    for line in text.splitlines():
        m = _METRIC_LINE.match(line.strip())
        if not m:
            continue
        seen_metric = True
        labels = dict(_LABEL.findall(m.group(2)))
        if labels.get("component_kind") != "source" or not labels.get("component_id"):
            continue
        cid = labels["component_id"]
        entry = sources.setdefault(cid, {"type": labels.get("component_type") or "", "received_events": 0})
        if m.group(1).endswith("component_received_events_total"):
            try:
                entry["received_events"] += int(float(m.group(3)))
            except ValueError:
                pass
    return sources if seen_metric else None


def _hex_ip(h: str):
    try:
        if len(h) == 8:
            return socket.inet_ntop(socket.AF_INET, bytes.fromhex(h)[::-1])
        if len(h) == 32:
            raw = b"".join(bytes.fromhex(h[i:i + 8])[::-1] for i in range(0, 32, 8))
            ip = socket.inet_ntop(socket.AF_INET6, raw)
            return ip[7:] if ip.startswith("::ffff:") and "." in ip else ip
    except (ValueError, OSError):
        return None
    return None


def parse_proc_net(text):
    """/proc/net/tcp{,6} then '#udp' then /proc/net/udp{,6} of one network
    namespace: {"tcp_listen": {port}, "udp_listen": {port}, "peers": {port: {ip}}}.
    Peers are ESTABLISHED connections INTO a listening port. None when empty."""
    if not text or not text.strip():
        return None
    tcp_listen, udp_listen, established = set(), set(), []
    udp = False
    for line in text.splitlines():
        if line.strip() == "#udp":
            udp = True
            continue
        parts = line.split()
        if len(parts) < 4 or not parts[0].endswith(":"):
            continue
        try:
            local_port = int(parts[1].rsplit(":", 1)[1], 16)
        except (IndexError, ValueError):
            continue
        state = parts[3].upper()
        if udp:
            if state == "07":
                udp_listen.add(local_port)
        elif state == "0A":
            tcp_listen.add(local_port)
        elif state == "01":
            established.append((local_port, _hex_ip(parts[2].rsplit(":", 1)[0])))
    peers = {}
    for port, ip in established:
        if port in tcp_listen and ip:
            peers.setdefault(port, set()).add(ip)
    return {"tcp_listen": tcp_listen, "udp_listen": udp_listen, "peers": peers}


_NGINX_INGEST = re.compile(r'"[A-Z]+ /ingest(?:[/? ]|")')


def count_ingest_requests(log_text):
    return sum(1 for line in (log_text or "").splitlines() if _NGINX_INGEST.search(line))


def classify_peers(ips, internal: dict, gateways):
    """Sorted peer descriptions; internal (another nano container) ones apart."""
    senders, inside = [], []
    for ip in sorted(ips or ()):
        if ip.startswith("127.") or ip == "::1":
            inside.append(f"{ip} (loopback, inside the Vector container)")
        elif ip in internal:
            inside.append(f"{ip} ({internal[ip]})")
        elif ip in gateways:
            senders.append(f"{ip} (Docker gateway: a sender on this host, or one relayed by docker-proxy)")
        else:
            senders.append(ip)
    return senders, inside


def install_token_state(env: dict) -> str:
    token = (env or {}).get("VECTOR_AUTH_TOKEN") or ""
    if not token.strip():
        return "missing"
    return "public" if token.strip() in KNOWN_PUBLIC_INSTALL_TOKENS else "set"


def evaluate_ingest(ev: dict) -> list:
    """Per-path verdicts from the evidence gathered by collect_ingest.

    ev keys: sources ({id: {type, received_events}} or None), sockets
    (parse_proc_net or None), nginx_ingest_requests (int or None), internal_ips
    ({ip: container}), gateways (set), token ("set" | "missing" | "public"),
    syslog_file (bool), ch_vector_native_events (int or None).
    """
    sources = ev.get("sources")
    sockets = ev.get("sockets")
    internal = ev.get("internal_ips") or {}
    gateways = ev.get("gateways") or set()
    token = ev.get("token") or "set"
    paths = []

    def of_type(*types, ids=()):
        if sources is None:
            return None
        return {cid: s for cid, s in sources.items() if s.get("type") in types or cid in ids}

    def events(found):
        return None if found is None else sum(int(s.get("received_events") or 0) for s in found.values())

    def peers_on(*ports):
        if sockets is None:
            return None
        ips = set()
        for p in ports:
            ips |= set(sockets["peers"].get(p, ()))
        return ips

    def listening(*ports):
        if sockets is None:
            return None
        return any(p in sockets["tcp_listen"] for p in ports)

    def add(pid, label, verdict, detail, steps=(), **extra):
        row = {"id": pid, "label": label, "verdict": verdict, "detail": detail, "steps": list(steps)}
        row.update(extra)
        paths.append(row)

    token_steps = []
    if token == "public":
        token_steps = ["VECTOR_AUTH_TOKEN is a publicly known default value, which 2.x refuses. Before the "
                       "window, set a random token (openssl rand -hex 32) in .env and on every sender, or plan "
                       "to give each sender its own ingest token (Settings > Ingest tokens) after the upgrade."]
    elif token == "missing":
        token_steps = ["No VECTOR_AUTH_TOKEN in .env: 0.1.x then accepted only with "
                       "VECTOR_ALLOW_UNAUTHENTICATED_INGEST=true. After the upgrade give each sender its own "
                       "ingest token (Settings > Ingest tokens)."]
    token_note = ("The install token (VECTOR_AUTH_TOKEN) stays valid: an upgraded install keeps it as a "
                  "legacy multiplex credential, so these senders need no change. Moving each sender to its "
                  "own ingest token (Settings > Ingest tokens) can wait until after the upgrade.")

    def token_verdict():
        return (VERDICT_ACTION, token_steps) if token_steps else (VERDICT_KEEPS, [])

    # nginx /ingest (80/443).
    hits = ev.get("nginx_ingest_requests")
    if hits is None:
        add("nginx_ingest", "nginx /ingest (80/443)", VERDICT_UNKNOWN,
            "nginx's log could not be read. If senders post to <BASE_URL>/ingest, they keep working: "
            + token_note, token_steps)
    elif hits > 0:
        verdict, steps = token_verdict()
        add("nginx_ingest", "nginx /ingest (80/443)", verdict,
            f"{hits} request(s) to /ingest in nginx's log (last 7 days). " + token_note, steps,
            requests=hits)
    else:
        add("nginx_ingest", "nginx /ingest (80/443)", VERDICT_UNUSED,
            "no request to /ingest in nginx's log (last 7 days).", requests=0)

    def token_lane(pid, label, port, found, kind):
        n = events(found)
        senders, inside = classify_peers(peers_on(port), internal, gateways)
        if found is None and sockets is None:
            add(pid, label, VERDICT_UNKNOWN, f"Vector's counters and sockets could not be read. {kind} "
                "senders using the install token keep working: " + token_note, token_steps)
            return
        used = bool(n) or bool(senders)
        if not used and found is None:
            add(pid, label, VERDICT_UNKNOWN, f"Vector's counters could not be read and no {kind} sender is "
                "connected now, so past use is unknown. Senders using the install token keep working: "
                + token_note, token_steps, peers=[], internal_peers=inside)
            return
        if not used:
            add(pid, label, VERDICT_UNUSED, f"no {kind} events since Vector started"
                + (" and no sender connected now." if sockets is not None else "."),
                events=n or 0, peers=[], internal_peers=inside)
            return
        verdict, steps = token_verdict()
        detail = f"{n if n is not None else 'unknown'} event(s) since Vector started"
        if senders:
            detail += f"; connected now: {', '.join(senders)}"
        if pid == "http_8080" and hits:
            detail += "; nginx /ingest forwards to this port too, so part of these may be nginx's"
        add(pid, label, verdict, detail + ". " + token_note, steps, events=n, peers=senders,
            internal_peers=inside)

    token_lane("http_8080", "HTTP :8080", 8080, of_type(ids=("http_ingest",)), "HTTP")
    token_lane("hec_8088", "HEC :8088", 8088, of_type("splunk_hec", ids=("splunk_hec_ingest",)), "HEC")

    # Vector native :6000.
    found = of_type("vector", ids=("vector_native",))
    n = events(found)
    ch_n = ev.get("ch_vector_native_events")
    senders, inside = classify_peers(peers_on(6000), internal, gateways)
    label = "Vector native :6000"
    if found is None and sockets is None and not ch_n:
        add("vector_native_6000", label, VERDICT_UNKNOWN,
            "Vector's counters and sockets could not be read. If any upstream Vector sends to port 6000, "
            "plan for its client certificate (see the runbook).", buffer_snippet=VECTOR_NATIVE_BUFFER_SNIPPET)
    elif n or senders or ch_n:
        peer_text = ", ".join(senders) if senders else "none connected right now"
        count = len(senders)
        detail = (f"Vector-to-Vector senders detected ({count} peer{'s' if count != 1 else ''}: {peer_text}). "
                  "After the upgrade, port 6000 requires mutual TLS. At cutover you will receive a client "
                  "certificate bundle per sender to add to each upstream Vector's sink, with the exact config "
                  "snippet. Set a disk buffer on those sinks now so they hold events during the switch:")
        evidence = []
        if n:
            evidence.append(f"{n} event(s) since Vector started")
        if ch_n:
            evidence.append(f"{ch_n} event(s) with source_type vector_native in the last 7 days")
        add("vector_native_6000", label, VERDICT_ACTION, detail, [
            "Now: add the disk buffer below to each upstream Vector's nano sink and restart it.",
            "At cutover: name each sender (install.sh asks, or NANO_VECTOR_NATIVE_SENDERS=edge-1,edge-2); "
            "it writes one bundle per sender to <install>/vector-client-bundles/<name>/ with its sink config. "
            "Or stage the bundles before the window (runbook: \"Before the window: ingest senders\").",
            "After the upgrade: copy each bundle to its sender, apply the sink config, restart that Vector.",
        ], events=n, evidence=evidence, peers=senders, internal_peers=inside,
            buffer_snippet=VECTOR_NATIVE_BUFFER_SNIPPET)
    elif found is None:
        add("vector_native_6000", label, VERDICT_UNKNOWN,
            "Vector's counters could not be read and no sender is connected now, so past use is unknown. If "
            "any upstream Vector sends to port 6000, plan its client certificate and set the disk buffer:",
            peers=[], internal_peers=inside, buffer_snippet=VECTOR_NATIVE_BUFFER_SNIPPET)
    else:
        add("vector_native_6000", label, VERDICT_UNUSED,
            "no Vector-native events since Vector started and no sender connected now.",
            events=n or 0, peers=[], internal_peers=inside)

    # OTLP :4317 / :4318.
    found = of_type("opentelemetry", ids=("otlp_ingest",))
    n = events(found)
    peers = peers_on(4317, 4318)
    senders, inside = classify_peers(peers, internal, gateways)
    label = "OTLP :4317/:4318"
    otlp_steps = [
        "2.x keeps raw OTLP unauthenticated but publishes 4317/4318 on 127.0.0.1 only. For senders on "
        "other hosts, pick one:",
        "  a) OTLP/HTTP through the authenticated edge: endpoint <BASE_URL>/otlp (http/protobuf), header "
        "Authorization: Bearer <ingest token bound to a log source> (Settings > Ingest tokens; the install "
        "token is not accepted there). gRPC (4317) senders switch to http/protobuf.",
        "  b) keep the raw ports open as on 0.1.x: NANO_OTLP_BIND_ADDRESS=0.0.0.0 in .env before the "
        "upgrade (unauthenticated; restrict it with a firewall).",
    ]
    if found is None and sockets is None:
        add("otlp", label, VERDICT_UNKNOWN, "Vector's counters and sockets could not be read.", otlp_steps)
    elif not n and not senders and found is None:
        add("otlp", label, VERDICT_UNKNOWN, "Vector's counters could not be read and no OTLP sender is "
            "connected now, so past use is unknown.", otlp_steps, peers=[], internal_peers=inside)
    elif not n and not senders:
        add("otlp", label, VERDICT_UNUSED, "no OTLP events since Vector started and no sender connected now"
            + (f" (nano's own containers connected: {', '.join(inside)})" if inside else "") + ".",
            events=n or 0, peers=[], internal_peers=inside)
    elif not senders and inside and sockets is not None:
        add("otlp", label, VERDICT_KEEPS, f"{n} event(s) since Vector started, only from nano's own "
            f"containers ({', '.join(inside)}), which reach Vector over the Docker network.",
            events=n, peers=[], internal_peers=inside)
    else:
        detail = f"{n if n is not None else 'unknown'} event(s) since Vector started"
        detail += f"; connected now: {', '.join(senders)}" if senders else "; no sender connected right now"
        add("otlp", label, VERDICT_ACTION, detail + ".", otlp_steps, events=n, peers=senders,
            internal_peers=inside)

    # Fluent Forward :24224 (published by 0.1.702's compose; nothing listens there).
    found = of_type("fluent")
    n = events(found)
    label = "Fluent Forward :24224"
    if found is None and sockets is None:
        add("fluent_24224", label, VERDICT_UNKNOWN, "Vector's counters and sockets could not be read.")
    elif n:
        add("fluent_24224", label, VERDICT_ACTION, f"{n} event(s) on a fluent source since Vector started.",
            ["2.x does not publish 24224 and has no Fluent Forward listener. Move these senders to "
             "HTTP /ingest, Splunk HEC or OTLP (all take an ingest token) before the upgrade."], events=n)
    elif listening(24224) or found:
        add("fluent_24224", label, VERDICT_UNUSED, "a listener exists, but no events since Vector started.",
            events=0)
    else:
        add("fluent_24224", label, VERDICT_UNUSED,
            "the port is published, but no Vector source listens on it (0.1.x ships none): nothing can be "
            "sending there.", events=0, listener=False)

    # Syslog: only when a syslog source or a live sources/syslog.toml exists.
    found = of_type("syslog") or {}
    n = events(found) if found else 0
    if found or ev.get("syslog_file"):
        label = "syslog"
        if n:
            add("syslog", label, VERDICT_ACTION,
                f"{n} event(s) on syslog source(s) {', '.join(sorted(found))} since Vector started.",
                ["0.1.x ships no syslog listener, so this one was added by hand. The upgrade replaces "
                 "docker-compose.opensource.yml: a port you published there is gone afterwards. Re-add it in a "
                 "compose overlay listed in NANO_COMPOSE_OVERLAYS, check the source's file is still loaded "
                 "(untracked files in the checkout are kept), and send a test message after the upgrade."],
                events=n, sources=sorted(found))
        elif found:
            add("syslog", label, VERDICT_UNUSED,
                f"syslog source(s) {', '.join(sorted(found))} exist, but no events since Vector started.",
                events=0, sources=sorted(found))
        else:
            add("syslog", label, VERDICT_UNUSED,
                "config/vector/sources/syslog.toml exists, but Vector runs no syslog source (it does not read "
                "config/vector/sources/), so nothing is listening.", events=0)
    return paths


def other_sources(sources) -> list:
    """Sources outside the shipped ingest paths (log sources created in nano,
    hand-added files), for the report only."""
    rows = []
    for cid, s in sorted((sources or {}).items()):
        if cid in _KNOWN_SOURCE_IDS or s.get("type") in _INTERNAL_SOURCE_TYPES:
            continue
        if s.get("type") in ("vector", "splunk_hec", "opentelemetry", "fluent", "syslog"):
            continue
        rows.append({"id": cid, "type": s.get("type"), "events": s.get("received_events")})
    return rows


def host_ip_addresses(col) -> set:
    """This host's interface addresses (best effort; empty when unknown)."""
    out = col.cmd(["ip", "-o", "addr", "show"]) or ""
    addrs = {m.group(1) for m in re.finditer(r"\binet6?\s+([0-9A-Fa-f:.]+)/", out)}
    if not addrs:
        addrs = set((col.cmd(["hostname", "-I"]) or "").split())
    return addrs


def public_host_check(col):
    """NANO_VECTOR_NATIVE_PUBLIC_HOST (the address sender configs get) as an IP
    this host does not have: often a snapshot/clone carrying another machine's
    address. A NAT or cloud public address is also not on an interface, so
    this is a prompt to check, not an error."""
    host = (col.env.get("NANO_VECTOR_NATIVE_PUBLIC_HOST") or "").strip().strip("[]")
    if not host:
        return None
    row = {"value": host}
    try:
        socket.inet_pton(socket.AF_INET6 if ":" in host else socket.AF_INET, host)
    except OSError:
        row["kind"] = "name"
        return row
    row["kind"] = "ip"
    addrs = host_ip_addresses(col)
    if addrs:
        row["on_this_host"] = host in addrs
        if not row["on_this_host"]:
            col.flag("warn", "vector_native_public_host", f"NANO_VECTOR_NATIVE_PUBLIC_HOST={host} in .env is "
                     "not an address of this host. Every Vector-native sink config is issued for it: if this "
                     "host was cloned or restored from a snapshot, set it (and NANO_VECTOR_NATIVE_SANS) to the "
                     "name or address senders use before staging bundles. A NAT or cloud public address is fine.")
    return row


def collect_ingest(col: Collector) -> dict:
    out = {"evidence": {}}
    evd = out["evidence"]
    vec = col.find_container(None, ("vector",), ("nano-vector", "nanosiem-vector"))
    sources = sockets = None
    if vec:
        evd["vector_container"] = vec
        started = col.cmd(["docker", "inspect", "--format", "{{.State.StartedAt}}", vec])
        evd["vector_started_at"] = started
        port = metrics_port(col.read_file("config", "vector", "92-metrics.toml"))
        rc, o, e = col.r.run(["docker", "exec", vec, "bash", "-c", _METRICS_SCRIPT, "_", str(port)], timeout=60)
        sources = parse_vector_sources(o) if rc == 0 else None
        if sources is not None:
            evd["vector_metrics"] = f"read from :{port} in {vec}"
        else:
            why = ((e or o or "").strip().splitlines() or [f"exit {rc}"])[-1]
            evd["vector_metrics"] = f"not readable on :{port} in {vec}: " + col.redact_text(why)[:200]
        rc, o, _ = col.r.run(["docker", "exec", vec, "sh", "-c", _SOCKETS_SCRIPT], timeout=60)
        sockets = parse_proc_net(o) if rc == 0 else None
        evd["vector_sockets"] = "read from /proc/net in the Vector container" if sockets else "not readable"
    else:
        evd["vector_metrics"] = evd["vector_sockets"] = "no running Vector container"
    hits = None
    nginx = col.find_container(None, ("nginx", "nano-nginx"), ("nano-nginx", "nanosiem-nginx"))
    if nginx:
        rc, o, e = col.r.run(["docker", "logs", "--since", NGINX_LOG_SINCE, "--tail", NGINX_LOG_TAIL, nginx],
                             timeout=120)
        if rc == 0:
            hits = count_ingest_requests(o) + count_ingest_requests(e)
        evd["nginx_log"] = (f"{nginx}: last 7 days (at most {NGINX_LOG_TAIL} lines)" if hits is not None
                            else f"{nginx}: not readable")
    else:
        evd["nginx_log"] = "no running nginx container"
    internal, gateways = {}, set()
    names = [c["name"] for c in col.containers if c.get("state") == "running"]
    if names:
        fmt = ('{{.Name}}|{{range .NetworkSettings.Networks}}{{.IPAddress}},{{.GlobalIPv6Address}},'
               '{{.Gateway}},{{.IPv6Gateway}};{{end}}')
        for line in (col.cmd(["docker", "inspect", "--format", fmt] + names) or "").splitlines():
            name, _, nets = line.partition("|")
            for net in nets.split(";"):
                parts = net.split(",")
                if len(parts) != 4:
                    continue
                for ip in parts[:2]:
                    if ip:
                        internal[ip] = name.lstrip("/")
                gateways.update(p for p in parts[2:] if p)
    ch_vn, ch_types = None, None
    if col.ch:
        try:
            tables = {r["name"] for r in col.ch.query(
                f"SELECT name FROM system.tables WHERE database = {_sql_lit(col.ch.db)} "
                "AND name IN ('ocsf_logs', 'logs')")}
            ch_types = {}
            for t in sorted(tables):
                try:
                    for r in col.ch.query(
                            f"SELECT source_type, count() AS events FROM {_quote_ident(col.ch.db)}.{_quote_ident(t)} "
                            "WHERE timestamp >= now() - INTERVAL 7 DAY GROUP BY source_type "
                            "ORDER BY events DESC LIMIT 50"):
                        ch_types.setdefault(t, {})[r["source_type"]] = int(r["events"])
                except DbError as e:
                    col.err(f"clickhouse source types ({t})", e)
            ch_vn = sum(v.get("vector_native", 0) for v in ch_types.values())
            evd["clickhouse"] = "events per source_type, last 7 days"
        except DbError as e:
            col.err("clickhouse source types", e)
    syslog_file = bool(col.install_dir) and os.path.isfile(
        os.path.join(col.install_dir, "config", "vector", "sources", "syslog.toml"))
    out["paths"] = evaluate_ingest({
        "sources": sources, "sockets": sockets, "nginx_ingest_requests": hits,
        "internal_ips": internal, "gateways": gateways, "token": install_token_state(col.env),
        "syslog_file": syslog_file, "ch_vector_native_events": ch_vn,
    })
    out["vector_native_public_host"] = public_host_check(col)
    out["other_sources"] = other_sources(sources)
    out["clickhouse_source_types_7d"] = ch_types
    out["listening_ports"] = sorted(sockets["tcp_listen"]) if sockets else None
    return out


def render_ingest(ing) -> list:
    L = []
    if not ing:
        return L
    L.append("")
    L.append("Ingest paths (what the upgrade means for your senders)")
    evd = ing.get("evidence") or {}
    started = evd.get("vector_started_at")
    if started:
        L.append(f"  Vector counters cover events since Vector started: {started}. A sender that was")
        L.append("  quiet since then (and is not connected now) is not seen: treat its path as used.")
    for p in ing.get("paths") or []:
        L.append(f"  {p['label']:24} {p['verdict']}")
        L.append(f"    {p['detail']}")
        if p.get("verdict") == VERDICT_ACTION and p.get("buffer_snippet"):
            for line in p["buffer_snippet"].rstrip("\n").splitlines():
                L.append(f"      {line}")
        for s in p.get("steps") or []:
            L.append(f"    - {s}" if not s.startswith("  ") else f"      {s.strip()}")
    others = ing.get("other_sources") or []
    if others:
        L.append("  Other Vector sources (log sources created in nano, or added by hand):")
        for o in others:
            L.append(f"    {o['id']:32} type {o['type']:16} events {o['events']}")
    L.append("  Evidence: " + "; ".join(f"{k} {v}" for k, v in sorted(evd.items()) if k != "vector_started_at"))
    return L

# --------------------------------------------------------------------------
# Report rendering
# --------------------------------------------------------------------------

def render_text(data) -> str:
    L = []
    w = L.append
    w("nano upgrade readiness report")
    w("=" * 30)
    w(f"generated (UTC): {data['generated_at']}    format: {data['format']}")
    v = data.get("version") or {}
    inst = data.get("install") or {}
    w("")
    w("Summary")
    w(f"  nano version      : {v.get('nano_version')}  ({v.get('nano_version_source')})")
    w(f"  .env version      : {v.get('env_version')}")
    w(f"  layout / edition  : {inst.get('layout')} / {inst.get('edition')}")
    w(f"  schema profile    : {inst.get('schema_profile')}")
    w(f"  install dir       : {inst.get('install_dir')}")
    w(f"  compose project   : {inst.get('compose_project')}")
    w(f"  image prefix      : {inst.get('image_prefix')}")
    w(f"  PG / CH ledgers   : {v.get('pg_migration_max')} / {v.get('ch_migration_max')}")
    git = inst.get("git")
    if git:
        w(f"  git               : {git.get('describe')} {git.get('branch')} {git.get('commit')} "
          f"remote={git.get('remote')}")
    w("")
    w("Flags")
    if not data["flags"]:
        w("  none")
    for f in data["flags"]:
        w(f"  [{f['level'].upper():5}] {f['code']}: {f['message']}")
    for e in data["errors"]:
        w(f"  [ERROR] {e['where']}: {e['error']}")
    h = data.get("host") or {}
    w("")
    w("Host")
    w(f"  {h.get('os')}  kernel {h.get('kernel')}  arch {h.get('architecture')}")
    w(f"  CPUs {h.get('cpu_count')}  flags {h.get('cpu_flags')}  RAM {human_bytes(h.get('ram_bytes'))}")
    w(f"  docker {h.get('docker_version')}  compose {h.get('compose_version')}  python {h.get('python')}")
    for k, d in (h.get("disks") or {}).items():
        w(f"  disk {k:16}: free {human_bytes(d.get('free_bytes'))} of {human_bytes(d.get('total_bytes'))} "
          f"({d.get('path')})")
    w("")
    w("Containers")
    for c in inst.get("containers") or []:
        dig = (c.get("repo_digests") or [""])[0]
        w(f"  {c.get('name'):28} {c.get('state'):8} {c.get('image')}  {dig[-71:] if dig else ''}")
    ch = data.get("clickhouse") or {}
    if ch:
        w("")
        w(f"ClickHouse {ch.get('server_version')}  database {ch.get('database')}  "
          f"total on disk {human_bytes(ch.get('total_bytes_on_disk'))}")
        for name, t in sorted((ch.get("tables") or {}).items(), key=lambda x: -int(x[1].get("bytes_on_disk") or 0))[:15]:
            w(f"  {name:40} rows {t.get('rows') or 0:>14}  {human_bytes(t.get('bytes_on_disk') or 0):>10}"
              f"  TTL {t.get('ttl') or '-'}")
        for t, days in (ch.get("event_tables_per_day") or {}).items():
            w(f"  per UTC day: {t}")
            for d in days:
                w(f"    {d.get('utc_day') or d.get('partition'):12} rows {d.get('rows'):>14}  "
                  f"{human_bytes(d.get('bytes_on_disk')):>10}")
        est = ch.get("ocsf_backfill_estimate")
        if est:
            w(f"  OCSF backfill ({est['legacy_table']}): need about {human_bytes(est['estimated_free_bytes_needed'])}"
              f" free (new copy {human_bytes(est['estimated_new_table_bytes'])} + largest day "
              f"{human_bytes(est['estimated_largest_day_new_bytes'])}; legacy on disk "
              f"{human_bytes(est['legacy_bytes_on_disk'])}); free now {human_bytes(est.get('clickhouse_free_bytes'))}")
            w(f"    {est['method']}")
    pg = data.get("postgres") or {}
    if pg:
        w("")
        w(f"PostgreSQL {pg.get('server_version')}  size {human_bytes(pg.get('database_size_bytes'))}  "
          f"migrations {pg.get('sqlx_migrations')}")
        for k, val in (pg.get("content_counts") or {}).items():
            w(f"  {k:32} {val}")
        w(f"  license: {pg.get('license')}")
    L.extend(render_ingest(data.get("ingest")))
    w("")
    w("Conversion readiness (open to enterprise Self-run)")
    cr = data.get("conversion_readiness") or {}
    for k, val in cr.items():
        w(f"  {k:24} {val}")
    w("")
    w("The JSON block below holds everything above, for nano support.")
    return "\n".join(L) + "\n"


# --------------------------------------------------------------------------
# Modes
# --------------------------------------------------------------------------

def cert_sha256(pem: str) -> str:
    """SHA-256 fingerprint of a PEM certificate's DER, as AA:BB:..; no openssl needed."""
    der = ssl.PEM_cert_to_DER_cert(pem)
    return ":".join(f"{b:02X}" for b in hashlib.sha256(der).digest())


class EncryptError(RuntimeError):
    pass


def _unlink_quiet(path: str) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


def encrypt_export(path: str, runner=None) -> str:
    """Encrypt `path` to the pinned support intake certificate.

    Writes `<path>.cms` (DER CMS EnvelopedData, AES-256-CBC so OpenSSL 1.1.x
    works), checks it is non-empty and parses, and only then removes the
    plaintext. Returns the .cms path. Raises EncryptError, leaving the
    plaintext untouched and no .cms behind, on any failure.
    """
    runner = runner or Runner()
    pem = SUPPORT_INTAKE_CERT_PEM
    try:
        got = cert_sha256(pem)
    except (ValueError, TypeError) as e:
        raise EncryptError(f"the embedded support certificate does not parse ({e})")
    want = SUPPORT_INTAKE_CERT_SHA256.replace(" ", "").upper()
    if got != want:
        raise EncryptError("the embedded support certificate does NOT match its pinned fingerprint "
                           f"(expected {want}, got {got}); refusing to encrypt to it. "
                           "This copy of the script is corrupted: download it again and report this to nano support")
    openssl = shutil.which("openssl")
    if not openssl:
        raise EncryptError("openssl was not found on PATH")
    cms = path + ".cms"
    partial = cms + ".partial"
    tmpdir = tempfile.mkdtemp(prefix="nano-intake-")  # mode 0700
    ok = False
    try:
        certfile = os.path.join(tmpdir, "support-intake.cert.pem")
        fd = os.open(certfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(pem)
        # Pre-create the output 0600 so openssl's write never widens it; O_EXCL
        # and O_NOFOLLOW so a planted file or symlink there is never written through.
        _unlink_quiet(partial)
        os.close(os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                         0o600))
        rc, _, err = runner.run([openssl, "cms", "-encrypt", "-binary", "-aes-256-cbc",
                                 "-outform", "DER", "-in", path, "-out", partial, certfile])
        if rc != 0:
            raise EncryptError(f"openssl cms -encrypt failed (exit {rc}): {(err or '').strip()[-300:]}")
        if not os.path.exists(partial) or os.path.getsize(partial) == 0:
            raise EncryptError("openssl wrote an empty encrypted file")
        rc, _, err = runner.run([openssl, "cms", "-cmsout", "-inform", "DER", "-in", partial, "-noout"])
        if rc != 0:
            raise EncryptError(f"the encrypted file does not parse as CMS (exit {rc}): "
                               f"{(err or '').strip()[-300:]}")
        os.replace(partial, cms)
        ok = True
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
        if not ok:
            _unlink_quiet(partial)
    # Only now, with the .cms fully written and verified, drop the plaintext.
    try:
        os.unlink(path)
    except OSError as e:
        log(f"WARN: could not remove the plain archive {path} ({e}); delete it yourself")
    return cms


def output_dir(col: Collector) -> str:
    inst = col.install_dir
    if not inst and not col.args.output:
        raise SystemExit("no install directory was detected, so the output cannot be kept out of it: "
                         "pass --output DIR (and --install-dir DIR)")
    out = os.path.realpath(os.path.expanduser(col.args.output or os.getcwd()))
    if inst and (out == inst or out.startswith(inst + os.sep)):
        if col.args.output:
            raise SystemExit(f"--output {out} is inside the install directory; choose another directory")
        out = os.path.realpath(os.path.expanduser("~"))
        if out == inst or out.startswith(inst + os.sep):
            raise SystemExit("cannot pick an output directory outside the install dir; pass --output DIR")
        log(f"the current directory is inside the install dir; writing to {out} instead")
    os.makedirs(out, exist_ok=True)
    return out


def file_stem(prefix: str) -> str:
    host = re.sub(r"[^A-Za-z0-9_-]", "-", socket.gethostname().split(".")[0])[:63] or "host"
    return f"{prefix}-{host}-{utc_now().strftime('%Y%m%dT%H%M%SZ')}"


def write_checked(path: str, payload: bytes, blobs: dict, secrets) -> None:
    hits = self_scan(blobs, secrets)
    if hits:
        for member, reason in hits:
            log(f"SELF-SCAN FAILED: {member}: {reason}")
        log("nothing was written. Send nano support the KEY names above (never the values).")
        raise SystemExit(3)
    tmp = path + ".partial"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(payload)
    os.replace(tmp, path)


def gather(col: Collector) -> tuple:
    try:
        col.discover_containers()
    except DbError as e:
        col.err("docker", e)
    col.resolve_install_dir()
    col.read_env()
    pg_name, ch_name = col.connect_dbs()
    return pg_name, ch_name


def run_report(col: Collector) -> int:
    pg_name, ch_name = gather(col)
    data = {"format": REPORT_FORMAT, "tool_version": TOOL_VERSION,
            "generated_at": utc_now().isoformat().replace("+00:00", "Z"), "flags": [], "errors": []}
    for key, fn in (("install", lambda: collect_install(col)),
                    ("host", lambda: collect_host(col, ch_name, pg_name)),
                    ("postgres", lambda: collect_pg(col) if col.pg else None)):
        try:
            data[key] = fn()
        except Exception as e:  # keep going: a partial report is still useful
            col.err(key, e)
            data[key] = None
    inst = data.get("install") or {}
    data["version"] = version_summary(col, inst, data.get("postgres"), None)
    legacy_hint = str(data["version"].get("nano_version") or "").startswith("0.")
    try:
        data["clickhouse"] = collect_ch(col, legacy_hint) if col.ch else None
    except Exception as e:
        col.err("clickhouse", e)
        data["clickhouse"] = None
    data["version"]["ch_migration_max"] = ((data.get("clickhouse") or {}).get("migrations") or {}).get("max_version")
    if data.get("clickhouse"):
        data["clickhouse"]["readonly_setting"] = col.ch.readonly
    try:
        data["ingest"] = collect_ingest(col)
    except Exception as e:
        col.err("ingest", e)
        data["ingest"] = None
    lic = (data.get("postgres") or {}).get("license") or {}
    lic_rows = lic.get("license_status") or []
    data["conversion_readiness"] = {
        "edition": inst.get("edition"),
        "license_present": bool(any(r.get("status") not in (None, "", "none", "missing") for r in lic_rows)
                                or any(lic.get(k) for k in lic if k.endswith("_rows"))),
        "license_tier": (lic_rows[0].get("tier") if lic_rows else None),
        "license_mode_env": col.env.get("NANO_LICENSE_MODE"),
        "image_prefix": inst.get("image_prefix"),
    }
    evaluate_flags(col, data)
    _, weak = col.secrets()
    if weak:
        col.flag("warn", "weak_secret", "secret value(s) too short or common to verify in the output: "
                 + ", ".join(sorted(weak)) + " (consider rotating them)")
    data["flags"], data["errors"] = col.flags, col.errors
    text = render_text(data)
    body = json.dumps(data, indent=2, sort_keys=True, default=str)
    payload = (text + "\n----- BEGIN NANO READINESS JSON -----\n" + body
               + "\n----- END NANO READINESS JSON -----\n").encode()
    out = output_dir(col)
    path = os.path.join(out, file_stem("nano-upgrade-readiness") + ".txt")
    secrets, _ = col.secrets()
    write_checked(path, payload, {os.path.basename(path): payload}, secrets)
    sys.stdout.write(text)
    log(f"report written: {path}")
    log("send this one file to nano support")
    return 2 if (col.pg is None and col.ch is None) else 0


def build_export(pg, ch, include_lookup_rows: bool, meta: dict, errors: list,
                 max_lookup_rows: int = 100000, redact=None) -> tuple:
    """Return (members {path: bytes}, manifest dict). `pg` needs columns()/rows()."""
    _redact = redact or (lambda t: redact_shapes(strip_url_credentials(t))[0])
    cols = pg.columns()
    members, counts, tables_out, removed, redactions = {}, {}, {}, {}, []
    kinds = list(EXPORT_KINDS)
    fm = tuple(t for t in sorted(cols) if FIELD_MAPPING_TABLE.search(t))
    if fm:
        kinds.append(("field_mappings", fm, None))
    lookups = []
    for kind, cands, filt in kinds:
        present = [t for t in cands if t in cols]
        counts.setdefault(kind, 0)
        for table in present:
            tcols = cols[table]
            drop = [c for c, typ in tcols if is_secret_name(c) or typ == "bytea"]
            keep = [c for c, _ in tcols if c not in drop]
            where = None
            if filt and any(c == filt[0] for c, _ in tcols):
                where = filt[1]
            try:
                rows = pg.rows(table, drop, where)
            except DbError as e:
                errors.append({"where": f"export {table}", "error": _redact(str(e))[:300]})
                continue
            tables_out[table] = keep
            if drop:
                removed[table] = drop
            for i, row in enumerate(rows):
                row = scrub_row(table, row, redactions)
                ident = row.get("id", row.get("name", row.get("key", i)))
                fname = safe_filename(ident) if len(present) == 1 else f"{table}-{safe_filename(ident)}"
                path = f"{kind}/{fname}.json"
                n = 2
                while path in members:
                    path = f"{kind}/{fname}-{n}.json"
                    n += 1
                item = {"table": table, "row": row}
                if kind == "lookups":
                    lookups.append((item, path))
                else:
                    members[path] = json.dumps(item, indent=2, sort_keys=True, default=str).encode()
                counts[kind] += 1
    # Lookups: definition plus column headers; rows only with --include-lookup-rows.
    for item, path in lookups:
        row = item["row"]
        tname = row.get("table_name") or ""
        info = {"table_name": tname, "storage": None, "columns": [], "rows_included": False}
        if _IDENT.match(tname or "") and tname in cols:
            info["storage"] = "postgres"
            lc = cols[tname]
            ldrop = [c for c, typ in lc if is_secret_name(c) or typ == "bytea"]
            info["columns"] = [{"name": c, "type": t} for c, t in lc if c not in ldrop]
            if ldrop:
                info["removed_columns"] = ldrop
            if include_lookup_rows:
                try:
                    got = pg.rows(tname, ldrop, None, max_lookup_rows + 1)
                    info["rows_truncated"] = len(got) > max_lookup_rows
                    info["rows"] = [scrub_row(tname, r, redactions) for r in got[:max_lookup_rows]]
                    info["rows_included"] = True
                except DbError as e:
                    errors.append({"where": f"export lookup {tname}", "error": _redact(str(e))[:300]})
        elif _IDENT.match(tname or "") and ch is not None:
            try:
                lc = ch.query(f"SELECT name, type FROM system.columns WHERE database = {_sql_lit(ch.db)} "
                              f"AND table = {_sql_lit(tname)} ORDER BY position")
                if lc:
                    info["storage"] = "clickhouse"
                    ldrop = [c["name"] for c in lc if is_secret_name(c["name"])]
                    info["columns"] = [c for c in lc if c["name"] not in ldrop]
                    if ldrop:
                        info["removed_columns"] = ldrop
                    if include_lookup_rows:
                        sel = ", ".join("`" + c["name"].replace("`", "") + "`" for c in info["columns"]) or "*"
                        got = ch.query(f"SELECT {sel} FROM {ch.db}.`{tname}` LIMIT {int(max_lookup_rows) + 1}")
                        info["rows_truncated"] = len(got) > max_lookup_rows
                        info["rows"] = [scrub_row(tname, r, redactions) for r in got[:max_lookup_rows]]
                        info["rows_included"] = True
            except DbError as e:
                errors.append({"where": f"export lookup {tname}", "error": _redact(str(e))[:300]})
        item["lookup"] = info
        members[path] = json.dumps(item, indent=2, sort_keys=True, default=str).encode()
    manifest = dict(meta)
    manifest.update({
        "format": EXPORT_FORMAT,
        "exported_at": utc_now().isoformat().replace("+00:00", "Z"),
        "counts": counts,
        "tables": tables_out,
        "removed_columns": removed,
        "redactions": sorted(set(redactions)),
        "include_lookup_rows": include_lookup_rows,
        "errors": errors,
        "notes": [
            "Each <kind>/<id>.json is {\"table\": <postgres table>, \"row\": {column: value}} with the "
            "columns as named in PostgreSQL. Secret columns (and bytea) are removed, not masked; "
            "secret keys inside *config*/*headers*/*metadata* JSON columns are removed; URL "
            "credentials are stripped everywhere.",
            "No event data, logs or ClickHouse ingest samples are included.",
        ],
    })
    members["manifest.json"] = json.dumps(manifest, indent=2, sort_keys=True, default=str).encode()
    return members, manifest


def run_export(col: Collector) -> int:
    gather(col)
    if col.pg is None:
        log("PostgreSQL is not reachable; nothing to export")
        for e in col.errors:
            log(f"  {e['where']}: {e['error']}")
        return 2
    inst = collect_install(col)
    pgv = None
    try:
        pgv = col.pg.query("SELECT max(version) AS max_version FROM _sqlx_migrations")[0]
    except (DbError, IndexError):
        pass
    ver = version_summary(col, inst, {"sqlx_migrations": pgv} if pgv else None, None)
    meta = {"nano_version": ver.get("nano_version"), "nano_version_source": ver.get("nano_version_source"),
            "env_version": ver.get("env_version"), "pg_migration_max": ver.get("pg_migration_max"),
            "schema_profile": inst.get("schema_profile"), "edition": inst.get("edition"),
            "layout": inst.get("layout"), "tool_version": TOOL_VERSION}
    errors = []
    members, manifest = build_export(col.pg, col.ch, col.args.include_lookup_rows, meta, errors,
                                     getattr(col.args, "max_lookup_rows", 100000), col.redact_text)
    buf = io.BytesIO()
    now = int(time.time())
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name in ["manifest.json"] + sorted(k for k in members if k != "manifest.json"):
            data = members[name]
            ti = tarfile.TarInfo(name)
            ti.size, ti.mtime, ti.mode = len(data), now, 0o600
            tf.addfile(ti, io.BytesIO(data))
    out = output_dir(col)
    path = os.path.join(out, file_stem("nano-content-export") + ".tgz")
    secrets, weak = col.secrets()
    write_checked(path, buf.getvalue(), members, secrets)
    for kind, n in sorted(manifest["counts"].items()):
        print(f"  {kind:20} {n}")
    if weak:
        log("warning: some secret values are too short or common to verify: " + ", ".join(sorted(weak)))
    for e in errors + col.errors:
        log(f"warning: {e['where']}: {col.redact_text(e['error'])}")
    if not getattr(col.args, "encrypt", False):
        log(f"export written: {path}")
        return 0
    try:
        cms = encrypt_export(path, col.r)
    except (EncryptError, OSError) as e:
        log(f"WARN: --encrypt was requested but the export was NOT encrypted: {e}")
        log(f"WARN: the plain (unencrypted) archive was kept: {path}")
        log("WARN: send it to nano support over a secure channel only (never plain email or a public link)")
        return EXIT_ENCRYPT_FALLBACK
    log(f"encrypted export written: {cms}")
    log("only nano support can open this file; send it to nano support")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="nano-upgrade-readiness",
        description="Read-only nano upgrade readiness report and content export (writes ONE file).")
    ap.add_argument("mode", nargs="?", default="report", choices=("report", "export"))
    ap.add_argument("--install-dir", help="nano install directory (default: auto-detect)")
    ap.add_argument("--output", help="directory for the output file (default: current directory; "
                    "never the install directory)")
    ap.add_argument("--include-lookup-rows", action="store_true",
                    help="export: include lookup table rows (default: definitions and columns only)")
    ap.add_argument("--max-lookup-rows", type=int, default=100000,
                    help="export: at most this many rows per lookup table (default 100000)")
    ap.add_argument("--encrypt", action="store_true",
                    help="export: encrypt the archive to nano support's pinned certificate (needs openssl); "
                    "writes a .tgz.cms only nano support can open. If it cannot encrypt, it keeps the "
                    "plain .tgz, prints WARN and exits 4")
    ap.add_argument("--pg-container", help="PostgreSQL container name (default: auto-detect)")
    ap.add_argument("--ch-container", help="ClickHouse container name (default: auto-detect)")
    ap.add_argument("--ch-database", help="ClickHouse database (default: CLICKHOUSE_DATABASE or nanosiem)")
    args = ap.parse_args(argv)
    if sys.version_info < (3, 8):
        print("Python 3.8 or newer is required", file=sys.stderr)
        return 1
    if args.encrypt and args.mode != "export":
        log("--encrypt applies to export only; the report holds no content and is not encrypted")
    col = Collector(args)
    return run_report(col) if args.mode == "report" else run_export(col)


if __name__ == "__main__":
    sys.exit(main())
