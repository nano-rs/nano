#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Create or list Rackspace Spot VM pools for a benchmark cloudspace, straight
# against the ngpc API. Some Spot clients send a null spec.vmCloudSpaceRef and
# get HTTP 422 back; this sets the reference explicitly.
#
#   SPOT_ORG_NAMESPACE=org-...                        (your Spot org namespace)
#   SPOT_REFRESH_TOKEN_FILE=~/.secrets/spot-refresh  (0600, one line: a Spot API refresh token)
#   or SPOT_ID_TOKEN_FILE=...                          (0600, an already-exchanged Spot id token)
#   spot_pool.sh create <cloudspace> <server-class> <bid-usd> <role> [userdata-file]
#   spot_pool.sh list   <cloudspace>
#
# The refresh token is exchanged for a short-lived id token in memory. Neither
# is printed, logged, written to disk or passed in argv (curl reads them from
# stdin). Output is pool names, classes, bids, status and IP addresses only.
# Delete pools and cloudspaces with the Spot UI or MCP (deleteVMCloudspace).
set -euo pipefail

ORG_NS="${SPOT_ORG_NAMESPACE:?set SPOT_ORG_NAMESPACE to your Spot org namespace (org-...)}"
API="${SPOT_API:-https://spot.rackspace.com}/apis/ngpc.rxt.io/v1/namespaces/$ORG_NS"
OAUTH="https://login.spot.rackspace.com/oauth/token"
CLIENT_ID="mwG3lUMV8KyeMqHe4fJ5Bb3nM1vBvRNa"   # Spot's public OAuth client id

die() { echo "spot_pool: $*" >&2; exit 1; }
mode_of() { stat -f %Lp "$1" 2>/dev/null || stat -c %a "$1"; }
if [[ -n "${SPOT_ID_TOKEN_FILE:-}" ]]; then
  [[ -r "$SPOT_ID_TOKEN_FILE" && "$(mode_of "$SPOT_ID_TOKEN_FILE")" == 600 ]] || die "$SPOT_ID_TOKEN_FILE must exist with mode 0600"
else
  [[ -r "${SPOT_REFRESH_TOKEN_FILE:-}" ]] || die "set SPOT_ID_TOKEN_FILE or SPOT_REFRESH_TOKEN_FILE (0600 files)"
  [[ "$(mode_of "$SPOT_REFRESH_TOKEN_FILE")" == 600 ]] || die "$SPOT_REFRESH_TOKEN_FILE must be mode 0600"
fi

id_token() {
  if [[ -n "${SPOT_ID_TOKEN_FILE:-}" ]]; then tr -d '\n' < "$SPOT_ID_TOKEN_FILE"; return; fi
  { printf 'grant_type=refresh_token&client_id=%s&refresh_token=' "$CLIENT_ID"; tr -d '\n' < "$SPOT_REFRESH_TOKEN_FILE"; } \
    | curl -fsS "$OAUTH" --data-binary @- -H 'Content-Type: application/x-www-form-urlencoded' \
    | python3 -c 'import json,sys; t=json.load(sys.stdin).get("id_token"); sys.exit(1) if not t else print(t)' \
    || die "token exchange failed"
}

# curl with the bearer header on stdin (-K -), never in argv.
api() { # <method> <path> [body-file]
  local tok; tok="$(id_token)"
  printf 'header = "Authorization: Bearer %s"\n' "$tok" \
    | curl -sS -K - -X "$1" -H 'Content-Type: application/json' ${3:+--data @"$3"} -w '\n%{http_code}' "$API/$2"
}

case "${1:-}" in
  create)
    [[ $# -ge 5 ]] || die "usage: create <cloudspace> <server-class> <bid> <role> [userdata-file]"
    cs="$2" cls="$3" bid="$4" role="$5" ud="${6:-}"
    [[ "$cs" == bench-* ]] || die "refusing: only bench-* cloudspaces"
    name="$(python3 -c 'import uuid; print(uuid.uuid4())')"
    body="$(mktemp)"; trap 'rm -f "$body"' EXIT
    python3 - "$name" "$cs" "$cls" "$bid" "$role" "$ORG_NS" "$ud" > "$body" <<'PY'
import base64, json, sys
name, cs, cls, bid, role, ns, ud = sys.argv[1:]
spec = {"vmCloudSpace": cs, "vmCloudSpaceRef": {"kind": "VMCloudSpace", "name": cs, "namespace": ns},
        "serverClass": cls, "bidPrice": bid, "desired": 1, "poolType": "spot", "vmImage": "ubuntu24.04"}
if ud:
    spec["vmUserData"] = base64.b64encode(open(ud, "rb").read()).decode()
print(json.dumps({"apiVersion": "ngpc.rxt.io/v1", "kind": "VMPool",
                  "metadata": {"name": name, "namespace": ns, "labels": {"nano.rs/purpose": "bench", "nano.rs/role": role}},
                  "spec": spec}))
PY
    out="$(api POST vmpools "$body")"; code="${out##*$'\n'}"
    [[ "$code" == 201 ]] || die "create $role ($cls) -> HTTP $code"
    echo "$role $name $cls bid=$bid created $(date -u +%FT%TZ)"
    ;;
  list)
    [[ $# -ge 2 ]] || die "usage: list <cloudspace>"
    out="$(api GET "vmcloudspaces/$2")"; code="${out##*$'\n'}"
    [[ "$code" == 200 ]] || die "list -> HTTP $code"
    printf '%s' "${out%$'\n'*}" | python3 -c '
import json, sys
s = json.load(sys.stdin).get("status", {})
print(s.get("phase"), s.get("reason", ""))
for v in (s.get("assignedServers") or {}).values():
    print(v.get("serverClassName"), v.get("ipAddress"), v.get("nodePoolName", ""))'
    ;;
  *) die "usage: create|list (see header)" ;;
esac
