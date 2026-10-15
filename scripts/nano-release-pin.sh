#!/usr/bin/env bash
# Print the open-core release pinned by images.lock (`# Release: vX.Y.Z` ->
# `X.Y.Z`), the value docker-compose.opensource.yml needs in NANO_VERSION.
#
# install.sh writes NANO_VERSION into .env itself. This is for the paths that
# drive the compose file without an installer-written .env: local development
# (docker-compose.localdev.yml, scripts/bootstrap-local-lake.sh) and CI
# (scripts/check-opensource-pins.sh). Same parse as install.sh
# resolve_lean_version; never `latest`, never a hard-coded prefix.
#
#   NANO_VERSION=$(./scripts/nano-release-pin.sh) docker compose -f docker-compose.opensource.yml ...
set -euo pipefail
lock="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/images.lock}"
release=$(sed -nE 's/^# Release: v?([0-9][0-9A-Za-z.+-]*).*$/\1/p' "$lock" 2>/dev/null | head -1)
if [[ -z "$release" ]]; then
    echo "nano-release-pin: no '# Release: vX.Y.Z' line in $lock" >&2
    exit 1
fi
printf '%s\n' "$release"
