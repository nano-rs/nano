#!/usr/bin/env bash
# shellcheck disable=SC2016,SC2001,SC2329,SC1091
# Test harness: stubs are invoked indirectly by the sourced install.sh functions, the bash -c bodies are separate scripts, and under_test.sh is generated at run time.
#
# Unit tests for install.sh's supply-chain check (`verify_image_digests`).
#
# install.sh is a curl|bash script with no main guard, so the functions under
# test are extracted into a temp file and sourced with `docker` and the logging
# helpers stubbed. No daemon, no network, no images — this runs in milliseconds
# and is safe in any environment.
#
# What it pins down:
#   1. a matching first-party digest verifies
#   2. a mismatched digest is fatal
#   3. an image the compose deploys but images.lock omits is FATAL, not skipped
#      (NAN-2361 — the loops iterate the lock, so an uncovered image used to be
#      invisible while the installer still printed a clean verification)
#   4. an unpulled profile-gated third-party image is still skipped, not fatal
#   5. NANO_SKIP_IMAGE_VERIFY=1 still bypasses everything
#
# Run from the repo root:  bash scripts/test-install-image-verification.sh

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$REPO_ROOT" || exit 2
# NANO_INSTALL_SH lets the same cases run against another revision of the script
# (e.g. `git show HEAD:install.sh > /tmp/old.sh`) to prove a case really fails
# before the fix.
INSTALL_SH="${NANO_INSTALL_SH:-install.sh}"
[[ -f "$INSTALL_SH" ]] || { echo "$INSTALL_SH not found — run from the repo root." >&2; exit 2; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/nano-install-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# Extract just the functions under test plus the one helper they call.
{
    sed -n '/^repo_digest_of() {/,/^}/p'      "$INSTALL_SH"
    sed -n '/^verify_one_digest() {/,/^}/p'   "$INSTALL_SH"
    sed -n '/^verify_image_digests() {/,/^}/p' "$INSTALL_SH"
} > "$WORK/under_test.sh"
for fn in repo_digest_of verify_one_digest verify_image_digests; do
    grep -q "^${fn}() {" "$WORK/under_test.sh" \
        || { echo "could not extract ${fn}() from $INSTALL_SH" >&2; exit 2; }
done

PASS=0; FAIL=0
green() { printf '  \033[32mok\033[0m   %s\n' "$*"; }
red()   { printf '  \033[31mFAIL\033[0m %s\n' "$*"; }

# One test = one subshell with its own stubs and fixtures, so a `fail` (which
# exits) is contained and observable as a non-zero status.
run_case() {
    local name="$1" want_status="$2" want_grep="$3"; shift 3
    local out status
    out="$( "$@" 2>&1 )"; status=$?
    local bad=""
    [[ "$status" == "$want_status" ]] || bad="expected exit $want_status, got $status"
    if [[ -n "$want_grep" ]] && ! grep -qF "$want_grep" <<< "$out"; then
        bad="${bad:+$bad; }expected output to contain: $want_grep"
    fi
    if [[ -z "$bad" ]]; then
        PASS=$((PASS + 1)); green "$name"
    else
        FAIL=$((FAIL + 1)); red "$name — $bad"
        sed 's/^/        /' <<< "$out" | head -12
    fi
}

# $1 = lock body, $2 = `compose config --images` output, $3 = digest the fake
# daemon reports for every image (empty = image absent locally).
harness() {
    local lock="$1" images="$2" reported="$3"
    (
        set -uo pipefail
        cd "$WORK" || exit 2
        printf '%s\n' "$lock" > images.lock
        printf '%s\n' "$images" > active_images.txt
        export NANO_REPORTED_DIGEST="$reported"
        # Read by the sourced verify_image_digests(), which shellcheck cannot see.
        # shellcheck disable=SC2034
        COMPOSE_FILE="docker-compose.opensource.yml"
        # shellcheck disable=SC2034
        NANO_VERSION="latest"

        warn() { printf '! %s\n' "$*" >&2; }
        ok()   { printf 'ok %s\n' "$*"; }
        log()  { printf '==> %s\n' "$*"; }
        fail() { printf 'FAIL %s\n' "$*" >&2; exit 1; }

        # Fake daemon: `docker compose … config --images` replays the fixture;
        # `docker image inspect` reports the fixture digest for the requested repo.
        docker() {
            case "$1 ${2:-}" in
                "compose -f") cat active_images.txt; return 0 ;;
            esac
            if [[ "$1" == "image" && "$2" == "inspect" ]]; then
                [[ -n "$NANO_REPORTED_DIGEST" ]] || return 1
                local repo="${3%@*}"; repo="${repo%:*}"
                printf '%s@%s\n' "$repo" "$NANO_REPORTED_DIGEST"
                return 0
            fi
            return 1
        }
        export -f docker 2>/dev/null || true

        # shellcheck disable=SC1090
        source "$WORK/under_test.sh"
        verify_image_digests
    )
}

D1=sha256:1111111111111111111111111111111111111111111111111111111111111111
D2=sha256:2222222222222222222222222222222222222222222222222222222222222222

echo "install.sh — verify_image_digests()"

run_case "matching first-party digest verifies" 0 "Verified 1 first-party" \
    harness "ghcr.io/nano-rs/nano-api $D1" "ghcr.io/nano-rs/nano-api:latest" "$D1"

run_case "mismatched digest is fatal" 1 "Image digest verification failed" \
    harness "ghcr.io/nano-rs/nano-api $D1" "ghcr.io/nano-rs/nano-api:latest" "$D2"

run_case "deployed image absent from images.lock is FATAL, not skipped" 1 \
    "images.lock does not cover every first-party image" \
    harness "ghcr.io/nano-rs/nano-api $D1" \
            "ghcr.io/nano-rs/nano-api:latest
ghcr.io/nano-rs/nano-lake-query:latest" "$D1"

run_case "the uncovered image is named in the failure" 1 "ghcr.io/nano-rs/nano-lake-query" \
    harness "ghcr.io/nano-rs/nano-api $D1" \
            "ghcr.io/nano-rs/nano-api:latest
ghcr.io/nano-rs/nano-lake-query:latest" "$D1"

run_case "unpulled profile-gated third-party image is skipped, not fatal" 0 \
    "not pulled (optional/profile-gated image, not deployed)" \
    harness "tenzir/tenzir:v6.19.1 $D1" "nginx:alpine" ""

run_case "NANO_SKIP_IMAGE_VERIFY=1 bypasses the whole check" 0 "skipping image digest verification" \
    env NANO_SKIP_IMAGE_VERIFY=1 bash -c '
        cd "$1"; shift
        warn() { printf "! %s\n" "$*" >&2; }; ok() { printf "ok %s\n" "$*"; }
        log() { printf "==> %s\n" "$*"; }; fail() { printf "FAIL %s\n" "$*" >&2; exit 1; }
        COMPOSE_FILE=x NANO_VERSION=latest
        source "$1/under_test.sh"; verify_image_digests' _ "$WORK" "$WORK"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" == "0" ]]
