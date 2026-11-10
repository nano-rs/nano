#!/usr/bin/env bash
# Create or refresh .env for the development / manual compose stacks with
# per-checkout generated secrets (security review 2026-11-08).
#
#   scripts/dev-env.sh [ENV_FILE]      (default: ./.env)
#
# - No ENV_FILE yet: copies .env.example and replaces every
#   CHANGE_ME_GENERATED placeholder with a random value.
# - Existing ENV_FILE: fills missing generated secrets and replaces values nano
#   once shipped as public defaults or examples (config/known-public-secrets.txt)
#   exactly like install.sh does on upgrade. A public NANOSIEM_ENCRYPTION_KEY is
#   moved to a key ring that keeps the old key decrypt-only, so stored
#   credentials still open. A public VECTOR_AUTH_TOKEN is rotated too (nano
#   refuses it since v2.0.6, NAN-5013).
#
# Production installs do not use this: install.sh generates every secret.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${1:-$ROOT/.env}"
# shellcheck source=scripts/lib/generated-secrets.sh
. "$ROOT/scripts/lib/generated-secrets.sh"

if [[ ! -e "$ENV_FILE" ]]; then
    umask 077
    # A fresh file holds no ciphertext yet, so placeholders become plain
    # generated values (no key-ring migration needed).
    grep -v '=CHANGE_ME_GENERATED$' "$ROOT/.env.example" > "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    echo "Created $ENV_FILE from .env.example"
fi

nano_backfill_generated_secrets "$ENV_FILE" generate

[[ -z "$NANO_BACKFILLED_SECRET_KEYS" ]] || echo "Generated: $NANO_BACKFILLED_SECRET_KEYS"
[[ -z "$NANO_ROTATED_SECRET_KEYS" ]] || echo "Replaced publicly known values: $NANO_ROTATED_SECRET_KEYS"
if [[ ",${NANO_ROTATED_SECRET_KEYS// /}," == *,NANOSIEM_ENCRYPTION_KEY,* ]]; then
    echo "NANOSIEM_ENCRYPTION_KEY is now a key ring; the old key stays decrypt-only (legacy-0) until"
    echo "'nanosiem-jobs credential-keys status' shows nothing pending, then: credential-keys retire legacy-0"
fi
if [[ ",${NANO_ROTATED_SECRET_KEYS// /}," == *,VECTOR_AUTH_TOKEN,* ]]; then
    echo "VECTOR_AUTH_TOKEN was a publicly known default (refused since v2.0.6); senders using it need a named ingest token."
fi
