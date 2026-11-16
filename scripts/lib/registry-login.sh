#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# NAN-5509: the license-API registry login install.sh does before its pull
# (scripts/lib/image-pull.sh, NAN-5505), for `scripts/nano upgrade`. install.sh
# never leaves its credential behind, so without this every upgrade of a
# Self-run install stopped at "not logged in": the customer had to fetch a
# credential by hand.
#
#   registry-login.sh --env-file <install>/.env --docker-config <dir> [--even-if-local]
#                                                          (image refs on stdin)
#
# NAN-5524: --docker-config is the caller's PRIVATE docker config directory
# (mktemp, 0700, owned by the caller, removed by it after its last pull). The
# login is written there only, never into the user's own docker config; the
# caller pulls with DOCKER_CONFIG=<dir> when this prints `logged-in`.
#
# --even-if-local checks the login even when every image is already local
# (a later `docker pull` of a present digest still asks the registry).
#
# Reads LICENSE_URL, LICENSE_TOKEN (or DEPLOYMENT_TOKEN), NANO_DEPLOYMENT_ID,
# NANO_LICENSE_MODE, AIRGAP_MODE and HTTPS_PROXY from the .env itself, so the
# token never passes through argv or the environment. The refs on stdin are
# the private images this host pulls, one per line (repo@sha256:... or
# repo:tag). Messages go to stderr; the last stdout line is the outcome:
#   logged-in <registry>   a credential from the license API is now in <dir>/config.json
#   unchanged              nothing to do (images local, an existing login works,
#                          or the license is not online)
# Exit 1 (after naming the cause on stderr) when the credential could not be
# fetched or used.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=scripts/lib/image-pull.sh
. "$here/image-pull.sh"

env_file="" even_if_local=0 docker_config=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --env-file) env_file="${2:-}"; shift 2 ;;
        --docker-config) docker_config="${2:-}"; shift 2 ;;
        --even-if-local) even_if_local=1; shift ;;
        *) printf 'registry-login.sh: unknown argument %s\n' "$1" >&2; exit 2 ;;
    esac
done
[[ -n "$env_file" && -f "$env_file" ]] || { printf 'registry-login.sh: --env-file <.env> is required\n' >&2; exit 2; }
[[ -n "$docker_config" && -d "$docker_config" && ! -L "$docker_config" && -O "$docker_config" ]] \
    || { printf 'registry-login.sh: --docker-config <private directory owned by this user> is required\n' >&2; exit 2; }
# The caller's directory: logged in to by the library, removed by the caller.
# shellcheck disable=SC2034
NANO_REGISTRY_DOCKER_CONFIG="$docker_config"
# shellcheck disable=SC2034
NANO_REGISTRY_DOCKER_CONFIG_OWNED=0

log()  { printf '==> %s\n' "$*" >&2; }
ok()   { printf 'ok: %s\n' "$*" >&2; }
warn() { printf '%s\n' "$*" >&2; }

# Same parsing as install.sh's env_value: last assignment wins, quotes and CR dropped.
env_get() {
    awk -v k="$1" '
        index($0, k "=") == 1 {
            sub(/^[^=]*=/, "")
            gsub(/[\r"'"'"']/, "")
            value = $0
        }
        END { print value }
    ' "$env_file"
}

images=$(cat)
mode=$(env_get NANO_LICENSE_MODE)
if [[ "$mode" != offline && "$mode" != airgap ]]; then
    case "$(env_get AIRGAP_MODE | tr '[:upper:]' '[:lower:]')" in
        1|true|yes|on) mode=airgap ;;
    esac
fi
# Read by nano_registry_login_if_needed (image-pull.sh); not exported.
# shellcheck disable=SC2034
NANO_REGISTRY_LICENSE_MODE="$mode"
# shellcheck disable=SC2034
NANO_REGISTRY_LICENSE_URL="$(env_get LICENSE_URL)"
NANO_REGISTRY_LICENSE_TOKEN="$(env_get LICENSE_TOKEN)"
[[ -n "$NANO_REGISTRY_LICENSE_TOKEN" ]] || NANO_REGISTRY_LICENSE_TOKEN="$(env_get DEPLOYMENT_TOKEN)"
# shellcheck disable=SC2034
NANO_REGISTRY_DEPLOYMENT_ID="$(env_get NANO_DEPLOYMENT_ID)"
# shellcheck disable=SC2034
NANO_REGISTRY_PROXY="$(env_get HTTPS_PROXY)"
# An online license without a recorded URL checks in at the default.
[[ -n "$NANO_REGISTRY_LICENSE_URL" || -z "$NANO_REGISTRY_LICENSE_TOKEN" ]] \
    || NANO_REGISTRY_LICENSE_URL="https://api.nano.rs/api/license/status"

rc=0
first=$(nano_private_images "$images" | awk 'NR == 1')
if [[ -z "$first" ]]; then
    :
elif (( even_if_local )); then
    if nano_registry_probe "$first"; then
        ok "This host's docker login already reads $(nano_image_registry "$first"); using it"
    elif [[ "$mode" != offline && "$mode" != airgap && -n "$NANO_REGISTRY_LICENSE_TOKEN" && -n "$NANO_REGISTRY_DEPLOYMENT_ID" ]]; then
        nano_registry_fetch_and_login "$first" || rc=$?
    fi
else
    nano_registry_login_if_needed "$images" || rc=$?
fi
NANO_REGISTRY_LICENSE_TOKEN=""
(( rc == 0 )) || exit 1
if [[ -n "$NANO_REGISTRY_LOGGED_IN_AT" ]]; then
    printf 'logged-in %s\n' "$(nano_image_registry "$first")"
else
    printf 'unchanged\n'
fi
