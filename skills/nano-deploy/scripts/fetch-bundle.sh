#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Download and verify the nano enterprise compose bundle with ONLY the license
# (enrollment) values, without a portal login. Never prints the token.
#
#   bash scripts/fetch-bundle.sh --enrollment ./nano-deploy-work/enrollment.env \
#       [--version 2.0.7] [--out ./nano-deploy-work/bundle] [--registry-cred ./nano-deploy-work/registry.cred]
#
# 1. Downloads nano-compose-enterprise-<V>.tar.gz, .sha256 and .sha256.sig through
#    GET <license API>/api/license/self-run/bundle (Authorization: Bearer
#    LICENSE_TOKEN, X-Nano-Deployment-Id). The token goes to curl on stdin
#    (-K -), never in argv, and only to the license API: each file is answered
#    with a 302 that is read, not followed, and the signed URL is fetched
#    without it.
# 2. Verifies, before anything is extracted: the pinned release-signing-v1 key's
#    fingerprint, the signature on the .sha256 (openssl pkeyutl -rawin, OpenSSL
#    3+), that the signed .sha256 is exactly one line naming this bundle, and
#    that line byte for byte against the bundle's own hash. Not `sha256sum -c`:
#    that checks whichever file the .sha256 names.
# 3. With --registry-cred, writes a one-hour registry pull credential (the
#    password only) to that file, mode 0600, for `docker login --password-stdin`.
#
# If a download or a check fails, or it is interrupted (Ctrl-C, TERM) before
# printing VERIFIED, it exits non-zero and removes the three downloaded files and
# the key file it wrote. Bad arguments or license values exit 2 before anything
# is downloaded. A registry-credential failure after VERIFIED exits non-zero but
# keeps the verified bundle. Prints paths, version and VERIFIED, never secrets.
set -euo pipefail
umask 077

# release-signing-v1, pinned (deploy/release/release-signing-v1.pem; SPKI DER sha256 below). Never taken from the
# download or the archive.
KEY_PEM='-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAQYUuvZPcBwXLcQgxCcZi+9S2CewrhdPy9ylKDkVjfIE=
-----END PUBLIC KEY-----'
KEY_FINGERPRINT=a073033180edff24ddcafa20b2b2be3fbdb450da76110141f9ed8363cb135017

usage() {
    [[ -n "${1:-}" ]] && echo "fetch-bundle: $1" >&2
    echo "usage: fetch-bundle.sh --enrollment FILE [--version X.Y.Z] [--out DIR] [--registry-cred FILE]" >&2
    exit 2
}
enrollment="" version="" out="./nano-deploy-work/bundle" cred=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --enrollment|--version|--out|--registry-cred)
            [[ $# -ge 2 && -n "$2" && "$2" != --* ]] || usage "$1 needs a value"
            case "$1" in
                --enrollment) enrollment="$2" ;;
                --version) version="$2" ;;
                --out) out="$2" ;;
                --registry-cred) cred="$2" ;;
            esac
            shift 2 ;;
        -h|--help) usage ;;
        --) shift ;;
        *) usage "unknown option: $1" ;;
    esac
done
die() { echo "fetch-bundle: $*" >&2; exit 1; }

# ── license values (same rules as apply-enrollment.sh) ──────────────────────
[[ -n "$enrollment" && -f "$enrollment" ]] || { echo "enrollment file not found: ${enrollment:-<unset>}" >&2; exit 2; }
LICENSE_URL="" LICENSE_TOKEN="" NANO_DEPLOYMENT_ID=""
while IFS= read -r line || [[ -n "$line" ]]; do
    line=${line%$'\r'}
    [[ -z "$line" || "$line" == \#* ]] && continue
    key=${line%%=*}; val=${line#*=}
    val=${val#\"}; val=${val%\"}; val=${val#\'}; val=${val%\'}
    case "$key" in
        LICENSE_URL) LICENSE_URL=$val ;;
        LICENSE_TOKEN) LICENSE_TOKEN=$val ;;
        NANO_DEPLOYMENT_ID) NANO_DEPLOYMENT_ID=$val ;;
        *) echo "refusing unexpected key in enrollment file: $key" >&2; exit 2 ;;
    esac
done < "$enrollment"
[[ -n "$LICENSE_URL" && -n "$LICENSE_TOKEN" && -n "$NANO_DEPLOYMENT_ID" ]] \
    || { echo "enrollment file needs LICENSE_URL, LICENSE_TOKEN and NANO_DEPLOYMENT_ID" >&2; exit 2; }
[[ "$LICENSE_TOKEN" =~ ^[A-Za-z0-9_-]+$ && ${#LICENSE_TOKEN} -ge 32 && ${#LICENSE_TOKEN} -le 512 ]] || { echo "LICENSE_TOKEN is not an enrollment token (value not shown)" >&2; exit 2; }
[[ "$NANO_DEPLOYMENT_ID" =~ ^[A-Za-z0-9_-]{1,128}$ ]] || { echo "NANO_DEPLOYMENT_ID is malformed" >&2; exit 2; }
# The token goes only to the license API: https, or a loopback address for tests.
if [[ "$LICENSE_URL" =~ ^(https://[A-Za-z0-9.-]+(:[0-9]+)?)/ || "$LICENSE_URL" =~ ^(http://(127\.0\.0\.1|localhost)(:[0-9]+)?)/ ]]; then
    API=${BASH_REMATCH[1]}
else
    echo "LICENSE_URL must be an https:// URL" >&2; exit 2
fi
[[ -z "$version" || "$version" =~ ^v?[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,6}$ ]] || { echo "--version must look like 2.0.7" >&2; exit 2; }
version=${version#v}

# ── tools ───────────────────────────────────────────────────────────────────
OPENSSL=${OPENSSL:-}
if [[ -z "$OPENSSL" ]]; then
    for bin in openssl /opt/homebrew/opt/openssl@3/bin/openssl /usr/local/opt/openssl@3/bin/openssl; do
        if "$bin" version 2>/dev/null | grep -Eq '^OpenSSL ([3-9]|[1-9][0-9])\.'; then OPENSSL=$bin; break; fi
    done
fi
[[ -n "$OPENSSL" ]] || die "needs OpenSSL 3.0 or later for the signature check (macOS: brew install openssl@3)"
command -v curl >/dev/null || die "needs curl"
command -v python3 >/dev/null || die "needs python3"
if command -v sha256sum >/dev/null; then sha256() { sha256sum "$1" | cut -d ' ' -f 1; }
else sha256() { shasum -a 256 "$1" | cut -d ' ' -f 1; }; fi

# The token reaches curl on stdin, never in argv.
api() { local path=$1; shift
    printf 'header = "Authorization: Bearer %s"\n' "$LICENSE_TOKEN" \
        | curl -fsS --proto '=https,http' -K - -H "X-Nano-Deployment-Id: $NANO_DEPLOYMENT_ID" "$@" "$API/api/license/self-run/$path"; }
json_field() { python3 -I -c 'import json,sys; v=json.load(sys.stdin).get(sys.argv[1]); sys.exit(1) if not isinstance(v,str) or not v else print(v)' "$1"; }

if [[ -z "$version" ]]; then
    version=$(api "bundle?edition=enterprise" | json_field version) \
        || die "the license API refused the bundle request (check the license values, that the deployment is paid or in trial, and that this machine reaches $API)"
fi
[[ "$version" =~ ^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,6}$ ]] || die "the license API returned an unexpected version"

bundle="nano-compose-enterprise-$version.tar.gz"
mkdir -p "$out"
cd "$out"
cleanup() { rm -f -- "$bundle" "$bundle.sha256" "$bundle.sha256.sig" release-signing-v1.pem; }
fail() { cleanup; die "$*"; }
# Until VERIFIED, an interrupt leaves nothing half-downloaded or unverified behind.
trap 'cleanup; echo "fetch-bundle: interrupted; nothing was kept" >&2; exit 130' INT TERM

fetch() { local kind=$1 name=$2 url
    url=$(api "bundle?version=$version&edition=enterprise&file=$kind" -o /dev/null -w '%{redirect_url}') \
        || fail "the license API refused $kind for $version (check the license values, that the deployment is paid or in trial, and that the release exists)"
    [[ "$url" == https://* || "$url" =~ ^http://(127\.0\.0\.1|localhost)[:/] ]] || fail "the license API returned no download link for $kind"
    curl -fsSL --proto '=https,http' -o "$name" "$url" || fail "downloading $name failed; run again (the links last 15 minutes)"
}
fetch compose_bundle "$bundle"
fetch compose_checksum "$bundle.sha256"
fetch compose_signature "$bundle.sha256.sig"

# ── verify before anything is extracted ─────────────────────────────────────
printf '%s\n' "$KEY_PEM" > release-signing-v1.pem
[[ "$("$OPENSSL" pkey -pubin -in release-signing-v1.pem -outform DER | { sha256sum 2>/dev/null || shasum -a 256; } | cut -d ' ' -f 1)" == "$KEY_FINGERPRINT" ]] \
    || fail "the pinned release signing key does not have fingerprint $KEY_FINGERPRINT"
"$OPENSSL" pkeyutl -verify -pubin -inkey release-signing-v1.pem -rawin -in "$bundle.sha256" -sigfile "$bundle.sha256.sig" >/dev/null 2>&1 \
    || fail "the signature on $bundle.sha256 did not verify; nothing was kept"
[[ "$(sed -n '$=' "$bundle.sha256")" == 1 && "$(cut -d ' ' -f 3- "$bundle.sha256")" == "$bundle" ]] \
    || fail "the signed $bundle.sha256 does not name exactly $bundle; nothing was kept"
printf '%s  %s\n' "$(sha256 "$bundle")" "$bundle" | cmp -s - "$bundle.sha256" \
    || fail "$bundle does not match its signed checksum; nothing was kept"

trap - INT TERM
echo "VERIFIED $bundle (release $version, signature release-signing-v1 $KEY_FINGERPRINT)"
echo "bundle:   $(pwd)/$bundle"
echo "sha256:   $(cut -d ' ' -f 1 "$bundle.sha256")"

# ── optional: one-hour registry credential, password only, 0600 ─────────────
if [[ -n "$cred" ]]; then
    reply=$(api "registry-token?deploymentId=$NANO_DEPLOYMENT_ID") || die "the license API refused the registry credential"
    registry=$(printf '%s' "$reply" | json_field registry) || die "the registry credential reply was malformed"
    username=$(printf '%s' "$reply" | json_field username) || die "the registry credential reply was malformed"
    expires=$(printf '%s' "$reply" | json_field expiresAt) || die "the registry credential reply was malformed"
    cd - >/dev/null
    tmp=$(mktemp "$(dirname "$cred")/.registry-cred.XXXXXX")
    printf '%s' "$reply" | json_field password > "$tmp" || { rm -f "$tmp"; die "the registry credential reply was malformed"; }
    chmod 600 "$tmp" && mv "$tmp" "$cred"
    unset reply
    echo "registry: $registry user $username, credential in $cred (0600, expires $expires)"
fi
