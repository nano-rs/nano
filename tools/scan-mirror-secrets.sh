#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later

#
# scan-mirror-secrets.sh <tree>
#
# Fail if <tree> contains anything that looks like a live credential, a real
# AWS account id (NAN-2361), or a hosted identifier (NAN-3861).
#
# NAN-2228: a working Cloudflare AI Gateway token sat in
# `scripts/start-microservices-dev.sh` for ~80 days, published to the public
# mirror. Nothing caught it. The strip gate already proves the stripped tree
# COMPILES and that its OpenAPI spec is VALID — but never that it is free of
# secrets, even though that tree is by definition exactly what goes public.
#
# Run against the STRIPPED tree, not the source tree: the stripped tree is what
# is actually published, and it is the only thing whose contents matter here.
#
# Deliberately NO directory exclusions beyond build output. Excluding a path
# because "it never ships" is the exact failure that produced NAN-2228: the
# token was safe until NAN-758 changed what ships, and nothing re-checked. This
# scans whatever it is pointed at, so it stays correct when the strip rules
# change.
#
# Consequence: running it against the SOURCE tree flags synthetic AWS key ids in
# `design-ref/` sample CloudTrail data, and both key ids and account ids in the
# `benchmarks/security-lake-chdb/` evidence tree. The design-ref and benchmark
# key ids are synthetic mockups; the benchmark ACCOUNT id is real. All three
# paths are stripped (sync-to-nano-mirror.sh) and absent from the published
# mirror, so the authoritative run — the stripped tree — is clean. Do not add
# any of them to ALLOW.
#
# Usage:
#   tools/scan-mirror-secrets.sh /tmp/nano-mirror
#
# Exit 0 = clean, 1 = credential-shaped strings found (job should fail).

set -uo pipefail

TREE="${1:?usage: scan-mirror-secrets.sh <tree>}"
[ -d "$TREE" ] || { echo "not a directory: $TREE" >&2; exit 2; }

# Provider-prefixed token shapes. Deliberately anchored on vendor prefixes plus
# a length floor rather than generic entropy heuristics — a noisy gate gets
# switched off, and a gate that is switched off catches nothing.
PATTERNS='cfut_[A-Za-z0-9]{30,}'
PATTERNS+='|sk-[A-Za-z0-9]{32,}'
PATTERNS+='|sk_live_[A-Za-z0-9]{20,}'
PATTERNS+='|rk_live_[A-Za-z0-9]{20,}'
PATTERNS+='|ghp_[A-Za-z0-9]{36,}'
PATTERNS+='|gho_[A-Za-z0-9]{36,}'
PATTERNS+='|github_pat_[A-Za-z0-9_]{60,}'
PATTERNS+='|glpat-[A-Za-z0-9_-]{20,}'
PATTERNS+='|xox[baprs]-[A-Za-z0-9-]{20,}'
PATTERNS+='|AIza[0-9A-Za-z_-]{35}'
PATTERNS+='|AKIA[0-9A-Z]{16}'
PATTERNS+='|dop_v1_[a-f0-9]{60,}'
PATTERNS+='|pul-[a-f0-9]{40}'
PATTERNS+='|-----BEGIN [A-Z ]*PRIVATE KEY-----[[:space:]]*[A-Za-z0-9+/]{40,}'

# Known-benign literals. Keep this list SHORT and justified — every entry is a
# hole. Anything added here must be provably not a credential.
#
#   AKIAIOSFODNN7EXAMPLE — AWS's own published documentation example key,
#                          used as a test fixture in nanosiem-core/src/crypto.rs.
ALLOW='AKIAIOSFODNN7EXAMPLE'

# Real AWS account ids. Not a credential, but an identifier that pins the
# published tree to a live account: it names S3 buckets, and every ARN built
# from it is a valid target for enumeration or a confused-deputy attempt.
#
# NAN-2361 nearly shipped one: the security-lake benchmark evidence baked a
# live account id into ~120 files, and nothing here would have said a word.
# `sync-to-nano-mirror.sh` now strips that subtree, but the strip list is a
# per-incident fix — this is the rule that catches the CLASS.
#
# Anchored on the positions an account id actually occupies, NOT on a bare
# `\b[0-9]{12}\b`. Measured on this repo, the bare form matches 30+ distinct
# values that are not account ids at all — UUID tails (…-446655440000),
# zero-padded fixture ids (000000000002), byte constants (107374182400 =
# 100GiB). A gate that noisy gets switched off, and a gate that is switched off
# catches nothing.
ACCOUNT_PATTERNS='arn:aws[a-zA-Z0-9-]*:[a-z0-9-]*:[a-z0-9-]*:[0-9]{12}:'
ACCOUNT_PATTERNS+='|[0-9]{12}\.dkr\.ecr\.'
# Spelled out per-character rather than with a case-insensitive grep: the token
# PATTERNS above are case-SENSITIVE by design (`AKIA` must not match `akia`),
# and both alternations share one grep invocation.
ACCOUNT_PATTERNS+='|[Aa][Cc][Cc][Oo][Uu][Nn][Tt][_-]?([IiUu][Dd])?"?[[:space:]]*[:=][[:space:]]*"?[0-9]{12}([^0-9]|$)'
# Account-id-suffixed bucket / resource names, the shape NAN-2361 used
# (nanosiem-nan-2361-chdb-<acct>-us-east-1).
ACCOUNT_PATTERNS+='|-[0-9]{12}-(us|eu|ap|sa|ca|me|af|il|cn)-[a-z]+-[0-9]'
# Bare path segment in an AWS service URL. SQS queue URLs, execute-api
# endpoints and Lambda function URLs carry the account id as a plain path
# component — no `arn:`, no region suffix, no assignment — so none of the
# shapes above see it. This was a measured miss: an SQS queue URL in the
# NAN-2361 benchmark tree (`sqs.us-east-1.amazonaws.com/<acct>/<queue>`).
ACCOUNT_PATTERNS+='|amazonaws\.com/[0-9]{12}([^0-9]|$)'
# Prose form: "AWS account `123456789012`, region us-east-1" in a README.
# The `[:=]` shape above requires an assignment; prose separates the word from
# the id with spaces and (in markdown) a backtick. The optional ID/NO/# word
# covers "account id 4458…". Bounded to two non-alphanumeric separator chars so
# the match stays anchored on the word `account` and cannot bridge across an
# intervening word into an unrelated 12-digit number.
ACCOUNT_PATTERNS+='|[Aa][Cc][Cc][Oo][Uu][Nn][Tt]([[:space:]]+([Ii][Dd]|[Nn][Oo]\.?|#))?[[:space:]]*[^0-9A-Za-z]{0,2}[0-9]{12}([^0-9]|$)'

# Reserved / obviously-fake ids that the repo already uses as examples. Held
# separate from ALLOW on purpose: both allowlists are LINE-scoped (grep -v
# drops the whole matching line), so folding these into ALLOW would let a real
# token hide on any line that also mentions a placeholder account.
#
#   000000000000, 123456789012 — AWS's documentation-reserved placeholders.
#   210987654321 — descending-sequence fixture in the credential /
#                  source-config assume-role tests.
#   234567890123 — ascending-sequence fixture in the nPL parser tests
#                  (`account=234567890123`) and the synthetic CloudTrail corpus.
ACCOUNT_ALLOW='000000000000|123456789012|210987654321|234567890123'

# Hosted identifiers (NAN-3861): the hosted Cloudflare account id and the
# internal lean tenant ids. Neither is a credential, but the account id pins
# the published tree to the live hosted account (R2 endpoints, Worker and
# Container API paths, registry refs), and the tenant ids name real tenants.
#
# Matched by SHA-256 so this script, which is itself published, never carries
# the values. The account id is 128 random bits, so its digest reveals nothing;
# the tenant ids are 8-hex prefixes, so their digests hide nothing from a
# determined reader — they are hashed only so the scanner does not flag itself.
#
#   HOSTED_ACCOUNT_SHA256: any 32-hex window of a hex run (any case), so it
#     also catches `<acct>.r2.cloudflarestorage.com`, `<acct>_<bucket>`
#     warehouses and ids inside longer hex strings.
#   HOSTED_TENANT_SHA256: a hex run of exactly 8 (a UUID's first group,
#     `cell-…-<prefix>`, a bare prefix in prose) or the leading 8 digits of an
#     `0x…` integer literal (`Uuid::from_u128(0x…_…)`).
#
# gzip members are decompressed and scanned too: NAN-3861 found the account id
# inside a gzipped test corpus that every plain-text grep missed.
#
#   HOSTED_WORKERS_SUBDOMAIN_SHA256: the account's workers.dev subdomain, the
#     label right before `.workers.dev` (`<worker>.<subdomain>.workers.dev`).
#     It names the hosted account as surely as the account id does. Like the
#     tenant ids it is short, so the digest only keeps the scanner from
#     flagging itself.
#
# Extra digests for the self-test only: NANO_SCAN_EXTRA_ACCOUNT_SHA256 /
# NANO_SCAN_EXTRA_TENANT_SHA256 / NANO_SCAN_EXTRA_WORKERS_SHA256 (space-separated).
HOSTED_ACCOUNT_SHA256='75205cc50094432f740d7c1c75cb7318a77c9ad0706deec488082beea8506331'
HOSTED_TENANT_SHA256='9ef7797594ba696bf8a95584c53ebd4fd91655c495c8f5b214b6b34aa093f180'
HOSTED_TENANT_SHA256+=' 7fb7b4d6b3ad09798415b3fc57882629142ee12f1abb871f14b676cd0fd6eccb'
HOSTED_WORKERS_SUBDOMAIN_SHA256='2a7e304a6bac1f6f84367e3514364abadd68745837b7f9e1b6b4d44707bfbdbe'
# Files that may keep a tenant id, each because it cannot change:
#   migrations/postgres/346_*.sql — an applied sqlx migration; editing even its
#   comment changes the checksum every existing database verifies at boot.
HOSTED_TENANT_ALLOW_PATHS='migrations/postgres/346_lean_finding_outbox_completion.sql'

hosted_scan() {
    python3 -I - "$TREE" "$HOSTED_ACCOUNT_SHA256 ${NANO_SCAN_EXTRA_ACCOUNT_SHA256:-}" \
        "$HOSTED_TENANT_SHA256 ${NANO_SCAN_EXTRA_TENANT_SHA256:-}" "$HOSTED_TENANT_ALLOW_PATHS" \
        "$HOSTED_WORKERS_SUBDOMAIN_SHA256 ${NANO_SCAN_EXTRA_WORKERS_SHA256:-}" <<'PY'
import gzip, hashlib, os, re, sys

tree, accounts, tenants, allow, workers = sys.argv[1], *(set(a.split()) for a in sys.argv[2:6])
for digest in accounts | tenants | workers:
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        sys.exit(f"scan-mirror-secrets: malformed digest {digest!r}")
SKIP_DIRS = {".git", "node_modules", "target", "dist"}
HEX = re.compile(rb"[0-9A-Fa-f]+")
INT = re.compile(rb"(?<![0-9A-Za-z_])0[xX]([0-9A-Fa-f_]+)")
WORKERS = re.compile(rb"([0-9A-Za-z-]+)\.workers\.dev(?![0-9A-Za-z-])", re.I)
MAX_GUNZIP = 256 << 20

def sha(b):
    return hashlib.sha256(b.lower()).hexdigest()

def hit(line, tenant_ok):
    for m in WORKERS.finditer(line):
        if sha(m.group(1)) in workers:
            return True
    for m in HEX.finditer(line):
        run = m.group(0)
        if len(run) >= 32 and any(sha(run[i:i + 32]) in accounts for i in range(len(run) - 31)):
            return True
        if not tenant_ok and len(run) == 8 and sha(run) in tenants:
            return True
    if not tenant_ok:
        for m in INT.finditer(line):
            digits = m.group(1).replace(b"_", b"")
            if len(digits) >= 8 and sha(digits[:8]) in tenants:
                return True
    return False

def scan(label, data, tenant_ok):
    for number, line in enumerate(data.split(b"\n"), 1):
        if hit(line, tenant_ok):
            print(f"{label}:{number}: [match withheld]")

for root, dirs, files in os.walk(tree):
    dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
    for name in files:
        path = os.path.join(root, name)
        if os.path.islink(path) or not os.path.isfile(path):
            continue
        rel = os.path.relpath(path, tree)
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError:
            continue
        tenant_ok = rel in allow
        if data[:2] == b"\x1f\x8b":
            try:
                with gzip.open(path, "rb") as g:
                    inner = g.read(MAX_GUNZIP + 1)
            except (OSError, EOFError):
                continue
            if len(inner) > MAX_GUNZIP:
                print(f"{path}(gunzip):0: [too large to scan]")
            else:
                scan(f"{path}(gunzip)", inner, tenant_ok)
        elif b"\0" not in data[:8192]:
            scan(path, data, tenant_ok)
PY
}

echo "Scanning $TREE for credential-shaped strings..."

scan() {
    grep -rInE "$1" "$TREE" \
        --exclude-dir=.git \
        --exclude-dir=node_modules \
        --exclude-dir=target \
        --exclude-dir=dist \
      2>/dev/null | grep -vE "$2" || true
}

hits=$(scan "$PATTERNS" "$ALLOW")
account_hits=$(scan "$ACCOUNT_PATTERNS" "$ACCOUNT_ALLOW")
[ -n "$account_hits" ] && hits="${hits:+$hits$'\n'}$account_hits"
hosted_hits=$(hosted_scan) || { echo "hosted identifier scan failed" >&2; exit 2; }
[ -n "$hosted_hits" ] && hits="${hits:+$hits$'\n'}$hosted_hits"

if [ -z "$hits" ]; then
    echo "OK — no credential-shaped strings found."
    exit 0
fi

echo ""
echo "FAIL — credential-shaped strings found in the tree that would be published:"
echo ""
# Never print matched lines. Prefix-specific masking is easy to miss when
# adding a new provider pattern; file/line coordinates suffice for triage.
printf '%s\n' "$hits" | awk -F: '{print $1 ":" $2 ": [match withheld]"}'

echo ""
echo "Remove the credential, then ROTATE it — assume anything that reached this"
echo "point is compromised. If a match is a genuine false positive, add it to"
echo "ALLOW in tools/scan-mirror-secrets.sh with a comment justifying it."
echo ""
echo "For an AWS account id there is nothing to rotate: either strip the path in"
echo "sync-to-nano-mirror.sh, or replace the id with 123456789012. Do NOT add a"
echo "real account id to ACCOUNT_ALLOW."
echo ""
echo "For the hosted Cloudflare account, its workers.dev subdomain or a lean tenant id: use a"
echo "placeholder (e.g. 0123456789abcdef0123456789abcdef, aaaaaaaa-aaaa-4aaa-8aaa-"
echo "aaaaaaaaaaaa) or read the real value from config."
exit 1
