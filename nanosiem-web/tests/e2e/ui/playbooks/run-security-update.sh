#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Security-update UI playbook runner (NAN-5085).
#
# One command: bring up a THROWAWAY e2e stack from a checkout (scripts/e2e.sh,
# compose project nanoe2e-<id>, its own free 127.0.0.1 ports), publish that
# checkout's web build into the stack's nginx edge, run
# security-update.mjs against the edge as four users, write the report, and
# tear the stack down. It never touches the nanoch-* dev stack.
#
#   run-security-update.sh [--checkout DIR] [--edition enterprise|open]
#                          [--label NAME] [--out DIR] [--keep]
#                          [--stack-env FILE]   reuse a live e2e stack (no up/down)
#                          [--compare BASELINE_REPORT.json]
#
#   --checkout  the tree whose backend AND web UI are tested (default: this
#               checkout). Point it at a worktree of the branch under test, e.g.
#               `git worktree add --detach ../sec-ui origin/security/<version>`.
#   --compare   after the run, diff against an earlier report (regressions =
#               passed there, fail here).
#
# Wrap with the codex Docker gate when other lanes share the machine:
#   CODEX/docker-slot.sh sec-ui -- nanosiem-web/tests/e2e/ui/playbooks/run-security-update.sh ...
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SELF_ROOT="$(cd "$HERE/../../../../.." && pwd)"
CHECKOUT="$SELF_ROOT"; EDITION=""; LABEL=""; OUT=""; KEEP=0; STACK_ENV=""; COMPARE=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --checkout) CHECKOUT="$(cd "${2:?}" && pwd)"; shift 2 ;;
        --edition) EDITION="${2:?}"; shift 2 ;;
        --label) LABEL="${2:?}"; shift 2 ;;
        --out) OUT="${2:?}"; shift 2 ;;
        --keep) KEEP=1; shift ;;
        --stack-env) STACK_ENV="${2:?}"; shift 2 ;;
        --compare) COMPARE="${2:?}"; shift 2 ;;
        -h|--help) sed -n '3,25p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done
if [[ -z "$EDITION" ]]; then
    if [[ -d "$CHECKOUT/nanosiem-enterprise" ]]; then EDITION=enterprise; else EDITION=open; fi
fi
[[ "$EDITION" =~ ^(enterprise|open)$ ]] || { echo "--edition must be enterprise or open" >&2; exit 2; }
SHA="$(git -C "$CHECKOUT" rev-parse --short=9 HEAD)"
LABEL="${LABEL:-$(git -C "$CHECKOUT" rev-parse --abbrev-ref HEAD | tr '/' '-')-$SHA}"
OUT="${OUT:-$SELF_ROOT/target/e2e/security-update/$LABEL-$EDITION-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$OUT"
log() { printf '\033[1;34m==>\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31mERR\033[0m %s\n' "$*" >&2; exit 1; }

# Disk guard (codex rule: stop under 100 GiB free).
avail_gib="$(df -Pk / | awk 'NR==2 {print int($4/1048576)}')"
(( avail_gib >= 100 )) || die "only ${avail_gib} GiB free on /: refusing to build (need >= 100)"

E2E="$CHECKOUT/scripts/e2e.sh"
RUN_ID=""; OWN=0
cleanup() {
    local rc=$?
    if (( OWN )) && [[ -n "$RUN_ID" ]]; then
        if (( KEEP )); then
            log "stack kept (--keep): $E2E down --run $RUN_ID --purge"
        else
            log "tearing down e2e run $RUN_ID"
            "$E2E" down --run "$RUN_ID" --purge >/dev/null 2>&1 || true
        fi
    fi
    exit "$rc"
}
trap cleanup EXIT

if [[ -z "$STACK_ENV" ]]; then
    log "bringing up a throwaway $EDITION stack from $CHECKOUT ($SHA)"
    # New installs get the OCSF profile (install.sh); test what customers run.
    export NANO_SCHEMA_PROFILE="${NANO_SCHEMA_PROFILE:-ocsf}"
    STACK_ENV="$(cd "$CHECKOUT" && "$E2E" up --edition "$EDITION" 2> "$OUT/stack-up.log" | tail -n1)" \
        || { tail -n 40 "$OUT/stack-up.log" >&2; die "e2e stack bring-up failed (log: $OUT/stack-up.log)"; }
    OWN=1
fi
[[ -f "$STACK_ENV" ]] || die "no stack.env at '$STACK_ENV'"
env_get() { grep -E "^$1=" "$STACK_ENV" | tail -n1 | cut -d= -f2-; }
RUN_ID="$(env_get E2E_RUN_ID)"; RUN_DIR="$(env_get E2E_RUN_DIR)"
EDGE="$(env_get NANOSIEM_EDGE_URL)"
[[ -n "$EDGE" && -f "$RUN_DIR/edge/nginx.conf" ]] || die "stack $RUN_ID has no nginx edge"
case "$EDGE" in *:3000|*:3002|*:5173|*:8123) die "refusing edge URL $EDGE (dev-stack port)";; esac

# The checkout's own web UI, built for the edition and served by the edge
# (the shipped nginx.opensource.conf, so /api routing is the customer's).
WEB_KEY="$(git -C "$CHECKOUT" rev-parse HEAD:nanosiem-web)$(git -C "$CHECKOUT" diff HEAD -- nanosiem-web | git hash-object --stdin | cut -c1-8)"
DIST="$CHECKOUT/target/e2e/web/secui-$EDITION-${WEB_KEY:0:16}"
if [[ ! -f "$DIST/index.html" ]]; then
    log "building nanosiem-web (VITE_EDITION=$EDITION) from $CHECKOUT"
    (
        cd "$CHECKOUT/nanosiem-web"
        [[ -d node_modules ]] || npm ci --no-audit --no-fund
        VITE_EDITION="$EDITION" npx --no-install vite build --outDir "$DIST.tmp" --emptyOutDir
    ) > "$OUT/web-build.log" 2>&1 || { tail -n 30 "$OUT/web-build.log" >&2; die "web build failed"; }
    rm -rf "$DIST"; mv "$DIST.tmp" "$DIST"
fi
find "$RUN_DIR/edge/web" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
cp -R "$DIST/." "$RUN_DIR/edge/web/"

log "running the security-update playbook against $EDGE (report: $OUT)"
[[ -d "$SELF_ROOT/nanosiem-web/node_modules/puppeteer-core" ]] \
    || (cd "$SELF_ROOT/nanosiem-web" && npm ci --no-audit --no-fund >/dev/null)
rc=0
(
    set -a
    # shellcheck disable=SC1090
    . "$STACK_ENV"
    set +a
    export BASE_URL="$EDGE" PLAYBOOK_OUT="$OUT" PLAYBOOK_EDITION="$EDITION" PLAYBOOK_LABEL="$LABEL" PLAYBOOK_SHA="$SHA"
    node "$HERE/security-update.mjs"
) || rc=$?
if [[ -n "$COMPARE" ]]; then
    node "$HERE/diff-reports.mjs" "$COMPARE" "$OUT/report.json" > "$OUT/diff.md" || true
    log "diff vs baseline: $OUT/diff.md"
fi
log "report: $OUT/report.md"
exit "$rc"
