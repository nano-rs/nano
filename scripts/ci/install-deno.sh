#!/usr/bin/env bash
# NAN-3485: the one place the Deno version and its checksums live. The root
# Dockerfile (api and jobs stages, enterprise edition only) and CI
# (pg-integration-tests.yml) both run this script, so they cannot drift.
#
# Installs the official release zip for linux x86_64 or aarch64 after checking
# its SHA-256. The sums are the upstream `<asset>.sha256sum` files from the
# GitHub release, cross-checked against the GitHub API asset digest and a
# local download (2026-10-10).
#
# Usage: install-deno.sh [dest_dir]   (default /usr/local/bin)
# The architecture comes from TARGETARCH (amd64/arm64, as BuildKit sets it)
# or, when that is unset, from `uname -m`.
set -euo pipefail

DENO_VERSION=2.9.7
DENO_SHA256_X86_64=c6527f24f4b16031d3ae4fa9f658d5f11534c8d84ce7dc8502420280919c3490
DENO_SHA256_AARCH64=c832298b1ad4422481334855f6003e0f54145762c5a134f20a489511d2f65bbf

dest=${1:-/usr/local/bin}

case "${TARGETARCH:-$(uname -m)}" in
  amd64 | x86_64) arch=x86_64; sha256=$DENO_SHA256_X86_64 ;;
  arm64 | aarch64) arch=aarch64; sha256=$DENO_SHA256_AARCH64 ;;
  *) echo "install-deno: unsupported architecture '${TARGETARCH:-$(uname -m)}'" >&2; exit 1 ;;
esac

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL --retry 5 --retry-all-errors -o "$tmp/deno.zip" \
  "https://github.com/denoland/deno/releases/download/v${DENO_VERSION}/deno-${arch}-unknown-linux-gnu.zip"
echo "${sha256}  $tmp/deno.zip" | sha256sum -c -
unzip -q -o "$tmp/deno.zip" deno -d "$tmp"
install -m 0755 "$tmp/deno" "$dest/deno"

installed=$("$dest/deno" --version | head -n1)
case "$installed" in
  "deno ${DENO_VERSION} "*) echo "install-deno: $installed" ;;
  *) echo "install-deno: expected deno ${DENO_VERSION}, got '$installed'" >&2; exit 1 ;;
esac
