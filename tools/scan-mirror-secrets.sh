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

if [ -z "$hits" ]; then
    echo "OK — no credential-shaped strings found."
    exit 0
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
    -e 's/(pul-[a-f0-9]{6})[a-f0-9]*/\1…REDACTED/g'
echo ""
echo "Remove the credential, then ROTATE it — assume anything that reached this"
echo "point is compromised. If a match is a genuine false positive, add it to"
echo "ALLOW in tools/scan-mirror-secrets.sh with a comment justifying it."
exit 1
