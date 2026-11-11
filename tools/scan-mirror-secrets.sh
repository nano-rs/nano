#!/usr/bin/env bash
#
# scan-mirror-secrets.sh <tree>
#
# Fail if <tree> contains anything that looks like a live credential.
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
# `design-ref/` sample CloudTrail data. Those are mockups, `design-ref` is
# stripped (sync-to-nano-mirror.sh) and absent from the published mirror, so the
# authoritative run — the stripped tree — is clean. Do not add them to ALLOW.
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
PATTERNS+='|nsiem-docs-[A-Za-z0-9]{20,}'   # docs RAG worker tokens (NAN-5025)
PATTERNS+='|-----BEGIN [A-Z ]*PRIVATE KEY-----[[:space:]]*[A-Za-z0-9+/]{40,}'

# Known-benign literals. Keep this list SHORT and justified — every entry is a
# hole. Anything added here must be provably not a credential.
#
#   AKIAIOSFODNN7EXAMPLE — AWS's own published documentation example key,
#                          used as a test fixture in nanosiem-core/src/crypto.rs.
ALLOW='AKIAIOSFODNN7EXAMPLE'

echo "Scanning $TREE for credential-shaped strings..."

hits=$(grep -rInE "$PATTERNS" "$TREE" \
        --exclude-dir=.git \
        --exclude-dir=node_modules \
        --exclude-dir=target \
        --exclude-dir=dist \
      2>/dev/null | grep -vE "$ALLOW" || true)

# PEM private keys span lines, which the line-oriented PATTERNS above cannot
# see: the BEGIN header and the base64 body sit on different lines. This
# file-level check flags any file holding a private-key header that is
#   - a PEM block (the header starts its line: what openssl and ssh-keygen write),
#   - followed on the same line by an escaped newline and a key body (a key
#     pasted into a JSON/TOML/code string), or
#   - followed on the next line by a key body.
# A "body" is 40+ base64 characters, so short placeholders such as
# "-----BEGIN PRIVATE KEY-----\nMIIE..." in tests and UI hints do not trip it.
# Only PATHS are reported, never content.
pem_files=""
pem_candidates=$(grep -rlIE -e '-----BEGIN ([A-Z0-9]+ )*PRIVATE KEY-----' "$TREE" \
        --exclude-dir=.git \
        --exclude-dir=node_modules \
        --exclude-dir=target \
        --exclude-dir=dist \
      2>/dev/null || true)
if [ -n "$pem_candidates" ]; then
    pem_files=$(printf '%s\n' "$pem_candidates" | while IFS= read -r f; do
        # No {n,} intervals: mawk (Debian's default awk) may not support them.
        awk '
          BEGIN {
            hdr = "-----BEGIN ([A-Z0-9]+ )*PRIVATE KEY-----"
            b64 = ""; for (i = 0; i < 40; i++) b64 = b64 "[A-Za-z0-9+/=]"
            body = "^[ \t]*" b64
            escaped = "^(\\\\r)?\\\\n" b64
          }
          pending && $0 ~ body { found = 1; exit }
          { pending = 0 }
          $0 ~ hdr {
            if ($0 ~ ("^[ \t]*" hdr)) { found = 1; exit }
            rest = $0; sub(".*" hdr, "", rest)
            if (rest ~ escaped) { found = 1; exit }
            pending = 1
          }
          END { exit found ? 0 : 1 }
        ' "$f" && printf '%s\n' "$f"
    done || true)
fi

artifact_files=$(NANO_MIRROR_TREE="$TREE" python3 -I - <<'PY'
import json
import os
from pathlib import Path

tree = Path(os.environ["NANO_MIRROR_TREE"])
skip = {".git", "node_modules", "target", "dist"}
suffixes = (".license.json", ".issuance.json", ".body.json")
found = set()

for base, directories, files in os.walk(tree):
    directories[:] = [name for name in directories if name not in skip]
    for name in files:
        path = Path(base, name)
        if name.endswith(suffixes):
            found.add(path)
            continue
        try:
            if path.stat().st_size > 256 * 1024:
                continue
            value = json.loads(path.read_bytes())
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if not isinstance(value, dict):
            continue
        claims = value.get("claims")
        signature = value.get("signature")
        if (
            isinstance(claims, dict)
            and isinstance(value.get("key_id"), str)
            and isinstance(value.get("key_version"), int)
            and isinstance(signature, list)
            and len(signature) == 64
            and all(isinstance(byte, int) and 0 <= byte <= 255 for byte in signature)
            and {"schema_version", "issuer", "order_id", "purchaser_id", "expires_at", "entitlement"} <= claims.keys()
            and isinstance(claims.get("entitlement"), dict)
        ):
            found.add(path)

for path in sorted(found):
    print(path)
PY
)

if [ -z "$hits" ] && [ -z "$pem_files" ] && [ -z "$artifact_files" ]; then
    echo "OK — no credential-shaped strings found."
    exit 0
fi

if [ -n "$artifact_files" ]; then
    echo ""
    echo "FAIL — C05 license artifacts found in files that would be published:"
    echo ""
    printf '%s\n' "$artifact_files"
fi
if [ -n "$pem_files" ]; then
    echo ""
    echo "FAIL — private keys (PEM) found in files that would be published:"
    echo ""
    printf '%s\n' "$pem_files"
fi
if [ -z "$hits" ]; then
    echo ""
    echo "Remove the artifact or key, then ROTATE/REVOKE it — assume anything that reached this point is compromised."
    exit 1
fi

echo ""
echo "FAIL — credential-shaped strings found in the tree that would be published:"
echo ""
# Mask the matched value so the gate does not itself print the secret into
# public CI logs.
printf '%s\n' "$hits" | sed -E \
    -e 's/(cfut_[A-Za-z0-9]{6})[A-Za-z0-9]*/\1…REDACTED/g' \
    -e 's/(sk-[A-Za-z0-9]{4})[A-Za-z0-9]*/\1…REDACTED/g' \
    -e 's/(sk_live_[A-Za-z0-9]{4})[A-Za-z0-9]*/\1…REDACTED/g' \
    -e 's/(ghp_[A-Za-z0-9]{4})[A-Za-z0-9]*/\1…REDACTED/g' \
    -e 's/(github_pat_[A-Za-z0-9_]{6})[A-Za-z0-9_]*/\1…REDACTED/g' \
    -e 's/(glpat-[A-Za-z0-9_-]{4})[A-Za-z0-9_-]*/\1…REDACTED/g' \
    -e 's/(xox[baprs]-[A-Za-z0-9-]{4})[A-Za-z0-9-]*/\1…REDACTED/g' \
    -e 's/(AIza[0-9A-Za-z_-]{4})[0-9A-Za-z_-]*/\1…REDACTED/g' \
    -e 's/(AKIA[0-9A-Z]{4})[0-9A-Z]*/\1…REDACTED/g' \
    -e 's/(dop_v1_[a-f0-9]{6})[a-f0-9]*/\1…REDACTED/g' \
    -e 's/(pul-[a-f0-9]{6})[a-f0-9]*/\1…REDACTED/g' \
    -e 's/(nsiem-docs-)[A-Za-z0-9]*/\1…REDACTED/g' \
    -e 's/(PRIVATE KEY-----[[:space:]]*)[A-Za-z0-9+\/]+/\1…REDACTED/g'
echo ""
echo "Remove the credential, then ROTATE it — assume anything that reached this"
echo "point is compromised. If a match is a genuine false positive, add it to"
echo "ALLOW in tools/scan-mirror-secrets.sh with a comment justifying it."
exit 1
