#!/usr/bin/env bash
# NAN-4968: tests for tools/scan-mirror-secrets.sh's PEM private-key check
# (plus NAN-5025 docs RAG token shape).
# Generates REAL keys at run time (never committed) into throwaway trees under
# paths the mirror strip keeps (config/), and asserts the scanner fails, reports
# the path, and never prints key material. Also asserts the short placeholders
# the codebase uses in tests and UI hints stay allowed.
#
#   bash tools/tests/scan-mirror-secrets.test.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCAN="$ROOT/tools/scan-mirror-secrets.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
command -v openssl >/dev/null || { echo "openssl required" >&2; exit 2; }

pass=0 failed=0
ok() { echo "  ok    $*"; pass=$((pass + 1)); }
no() { echo "  FAIL  $*"; failed=$((failed + 1)); }

# Fresh tree with the benign placeholder shapes the real tree contains.
new_tree() {
    local t="$WORK/$1"
    mkdir -p "$t/config" "$t/src"
    cat > "$t/src/placeholders.rs" <<'RS'
const HINT: &str = "-----BEGIN PRIVATE KEY-----\nMIIE...";
let sa = r#"{"private_key": "-----BEGIN PRIVATE KEY-----\nSECRET\n-----END PRIVATE KEY-----\n"}"#;
let fmt = format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n", body);
RS
    printf '%s' "$t"
}

# expect <name> <tree> <want-exit> [path-that-must-be-reported] [key-file-whose-body-must-not-leak]
expect() {
    local name="$1" tree="$2" want="$3" path="${4:-}" keyfile="${5:-}" out rc=0
    out="$(bash "$SCAN" "$tree" 2>&1)" || rc=$?
    if [[ "$rc" != "$want" ]]; then no "$name: exit $rc, want $want"; printf '%s\n' "$out" | sed 's/^/        /'; return; fi
    if [[ -n "$path" && "$out" != *"$path"* ]]; then no "$name: path $path not reported"; return; fi
    if [[ -n "$keyfile" ]]; then
        local line
        while IFS= read -r line; do
            [[ "$line" == -----* || -z "$line" ]] && continue
            if [[ "$out" == *"$line"* ]]; then no "$name: key material printed"; return; fi
        done < "$keyfile"
    fi
    ok "$name"
}

echo "scan-mirror-secrets PEM tests"

t=$(new_tree clean)
expect "placeholders only -> clean" "$t" 0

t=$(new_tree pem-file)
openssl genpkey -algorithm ED25519 -out "$t/config/leaked.pem" 2>/dev/null
expect "openssl ED25519 PEM file under config/ -> fail" "$t" 1 "config/leaked.pem" "$t/config/leaked.pem"

t=$(new_tree pem-rsa)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$t/config/tls.key" 2>/dev/null
expect "openssl RSA PEM file -> fail" "$t" 1 "config/tls.key" "$t/config/tls.key"

t=$(new_tree pem-indented)
openssl genpkey -algorithm ED25519 2>/dev/null | sed 's/^/    /' > "$t/config/values.yaml"
expect "indented PEM block in YAML -> fail" "$t" 1 "config/values.yaml"

t=$(new_tree pem-json)
key="$(openssl genpkey -algorithm ED25519 2>/dev/null | awk '{printf "%s\\n", $0}')"
printf '{"type": "service_account", "private_key": "%s"}\n' "$key" > "$t/config/sa.json"
expect "JSON-escaped key in a service-account file -> fail" "$t" 1 "config/sa.json"

t=$(new_tree pem-toml)
{ printf 'key = """-----BEGIN PRIVATE KEY-----\n'; openssl genpkey -algorithm ED25519 2>/dev/null | sed '1d'; printf '"""\n'; } > "$t/config/app.toml"
expect "key body on the line after a mid-line header -> fail" "$t" 1 "config/app.toml"

t=$(new_tree c05-license-name)
: > "$t/config/customer.license.json"
expect "*.license.json bearer artifact -> fail" "$t" 1 "config/customer.license.json"

t=$(new_tree c05-record-name)
: > "$t/config/customer.issuance.json"
expect "*.issuance.json ceremony record -> fail" "$t" 1 "config/customer.issuance.json"

t=$(new_tree c05-body-name)
: > "$t/config/customer.body.json"
expect "*.body.json retained signing body -> fail" "$t" 1 "config/customer.body.json"

t=$(new_tree c05-renamed)
python3 - "$t/config/renamed.json" <<'PY'
import json
import sys

with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump({
        "claims": {
            "schema_version": 1,
            "issuer": "nano",
            "order_id": "order-one",
            "purchaser_id": "customer-one",
            "expires_at": 1_800_000_000,
            "entitlement": {"schema_version": 1, "license_id": "eval-one"},
        },
        "key_id": "license-signing-v1",
        "key_version": 1,
        "signature": [0] * 64,
    }, handle)
PY
expect "renamed C05 signature structure -> fail" "$t" 1 "config/renamed.json"

# NAN-5025: docs RAG worker bearer tokens (nsiem-docs-<hex>) in a mirrored
# script. Generated at run time; the scanner must fail and must not echo it.
t=$(new_tree docs-rag-token)
mkdir -p "$t/scripts"
tok="nsiem-docs-$(openssl rand -hex 16)"
printf 'export DOCS_RAG_TOKEN="${DOCS_RAG_TOKEN:-%s}"\n' "$tok" > "$t/scripts/start-dev.sh"
printf '%s\n' "$tok" > "$WORK/docs-rag-token.txt"
expect "docs RAG token default in a script -> fail, value masked" "$t" 1 "scripts/start-dev.sh" "$WORK/docs-rag-token.txt"

t=$(new_tree docs-rag-env-only)
mkdir -p "$t/scripts"
printf 'export DOCS_RAG_TOKEN="${DOCS_RAG_TOKEN:-}"\n' > "$t/scripts/start-dev.sh"
expect "docs RAG token read from env only -> clean" "$t" 0

echo "$pass passed, $failed failed"
[[ "$failed" == 0 ]]
