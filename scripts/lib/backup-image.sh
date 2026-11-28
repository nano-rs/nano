#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# NAN-5937: make the nano-backup image local before automatic backups are
# turned on (`scripts/nano backup-schedule --configure`).
#
#   backup-image.sh --install-dir DIR
#
# The image is `${NANO_IMAGE_PREFIX}-backup:${NANO_VERSION}` from .env, pinned
# by the release's images lock when one describes this release. A missing
# image is pulled exactly as install.sh pulls (scripts/lib/image-pull.sh): an
# enterprise install with an online license first gets a one-hour pull
# credential from the license API into a private, temporary docker config
# (removed on exit; the user's own docker config is never touched). The
# license token is read from .env here and never passes through argv.
# Exit 0 when the image is local afterwards, 1 (with the reason) otherwise.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=scripts/lib/image-pull.sh
. "$here/image-pull.sh"

install_dir=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --install-dir) install_dir="${2:-}"; shift 2 ;;
        *) printf 'backup-image.sh: unknown argument %s\n' "$1" >&2; exit 2 ;;
    esac
done
env_file="$install_dir/.env"
[[ -n "$install_dir" && -f "$env_file" ]] || { printf 'backup-image.sh: --install-dir with a .env is required\n' >&2; exit 2; }

log()  { printf '==> %s\n' "$*" >&2; }
ok()   { printf 'ok: %s\n' "$*" >&2; }
warn() { printf '%s\n' "$*" >&2; }

# Same parsing as install.sh's env_value: last assignment wins, quotes and CR dropped.
env_get() {
    awk -v k="$1" '
        index($0, k "=") == 1 { sub(/^[^=]*=/, ""); gsub(/[\r"'"'"']/, ""); value = $0 }
        END { print value }
    ' "$env_file"
}

prefix=$(env_get NANO_IMAGE_PREFIX); prefix=${prefix:-ghcr.io/nano-rs/nano}
version=$(env_get NANO_VERSION)
[[ "$prefix" =~ ^[A-Za-z0-9./_:-]+$ && "$version" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$ ]] \
    || { warn "NANO_IMAGE_PREFIX or NANO_VERSION in .env is missing or invalid; cannot name the nano-backup image."; exit 1; }
ref="$prefix-backup:$version"

# The lock that pins this release's first-party digests (as install.sh picks
# it: the one whose `# Release:` header is this version and lists the image).
NANO_PULL_LOCK=""
for lock in images.lock images.enterprise.customer.lock deploy/release/images.enterprise.lock images.enterprise.lock; do
    path="$install_dir/$lock"
    [[ -f "$path" ]] || continue
    release=$(sed -n 's/^# Release: v\{0,1\}//p' "$path" | awk 'NR == 1 {print $1}')
    [[ "$release" == "${version#v}" ]] || continue
    if awk -v r="$prefix-backup" '$1 == r { found = 1 } END { exit !found }' "$path"; then
        NANO_PULL_LOCK="$path"; break
    fi
done
export NANO_PULL_LOCK

if [[ -z "$(nano_missing_images "$ref")" ]]; then
    ok "nano-backup image is on this host ($ref)"
    exit 0
fi
log "The nano-backup image is not on this host yet; pulling $ref"

trap 'nano_registry_cleanup' EXIT
if [[ "$(env_get NANO_EDITION)" == enterprise ]]; then
    mode=$(env_get NANO_LICENSE_MODE)
    if [[ "$mode" != offline && "$mode" != airgap ]]; then
        case "$(env_get AIRGAP_MODE | tr '[:upper:]' '[:lower:]')" in 1|true|yes|on) mode=airgap ;; esac
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
    [[ -n "$NANO_REGISTRY_LICENSE_URL" || -z "$NANO_REGISTRY_LICENSE_TOKEN" ]] \
        || NANO_REGISTRY_LICENSE_URL="https://api.nano.rs/api/license/status"
    if ! nano_registry_login_if_needed "$ref"; then
        warn "Could not get a registry pull credential from the license API for the nano-backup image."
        exit 1
    fi
    NANO_REGISTRY_LICENSE_TOKEN=""
fi
nano_pull_images "$ref" || exit 1
ok "pulled the nano-backup image ($ref)"
