#!/usr/bin/env bash
#
# nano — one-line installer for the open-source edition.
#
# Designed to be piped from curl:
#
#   curl -fsSL https://get.nano.rs | bash
#
# What it does:
#   1. Validates prerequisites (docker, docker compose v2, git, openssl, curl)
#   2. Clones (or pulls) nano-rs/nano into $NANO_INSTALL_DIR (default ~/nano)
#   3. Prompts for admin email / password / public BASE_URL and the storage
#      schema profile (UDM or OCSF) (reads /dev/tty even when stdin is piped
#      from curl)
#   4. Generates strong random secrets and writes .env
#   5. Pulls images from ghcr.io/nano-rs
#   6. Verifies the pulled first-party image digests against images.lock
#   7. Brings the stack up
#   8. Waits for the API to report healthy
#   9. POSTs to /api/setup/initialize to create the first admin account
#  10. Prints the login URL
#
# Non-interactive use: set the prompt values as env vars before running.
#   NANO_ADMIN_EMAIL, NANO_ADMIN_NAME, NANO_ADMIN_PASSWORD, NANO_BASE_URL
#   NANO_HTTPS_PROXY (http://host:port), NANO_PROXY_USERNAME / NANO_PROXY_PASSWORD
#   (raw; the installer percent-encodes them) and NANO_NO_PROXY — outbound proxy for
#   nano's own calls; asked once, kept in .env as HTTPS_PROXY/HTTP_PROXY/NO_PROXY.
#   Enterprise licence (NAN-5172), asked once on a TTY and kept in .env:
#   LICENSE_URL, LICENSE_TOKEN (or the older DEPLOYMENT_TOKEN) and
#   NANO_DEPLOYMENT_ID from the deployment's page in app.nano.rs, or
#   NANO_LICENSE_MODE=offline with an optional NANO_LICENSE_FILE (imported
#   after install), or AIRGAP_MODE=true. An unattended first install without
#   any of these fails closed. A new LICENSE_TOKEN given to a re-run replaces
#   the recorded one. NANO_ADMIN_EMAIL / NANO_ADMIN_NAME are kept in .env (the
#   password never is), so a prepare-then-install second run needs neither.
#   Single-node in one command:
#     NANO_IMAGES_LOCK=images.enterprise.customer.lock LICENSE_URL=… \
#       LICENSE_TOKEN=… NANO_DEPLOYMENT_ID=… ./install.sh
#   NANO_ALLOW_PRIVATE_AI_ENDPOINTS (true | false, default false) — allow AI
#   providers on private addresses (a local LLM); asked once, kept in .env.
#   NANO_SCHEMA_PROFILE (ocsf | udm | ocsf+tenzir, default ocsf) — chosen at
#   first install and immutable afterward; see the prompt below. New installs
#   are OCSF-first (NAN-4903); an existing install keeps the profile recorded in
#   its .env (a .env without one predates the choice and is pinned to udm).
#
# Override defaults: NANO_INSTALL_DIR, NANO_REPO_URL, NANO_BRANCH, NANO_VERSION.
# NANO_VERSION defaults to the release recorded in the edition's images lock
# ("# Release: vX.Y.Z"). It must be a v2+ release (X.Y.Z, major >= 2): no
# floating tag is published, so "latest" is refused, and 0.x/1.x images belong
# to other product lines. Re-running the installer moves the install to the
# checkout's release (an upgrade).
# Edition (open | enterprise) comes from, and must agree across: the source
# tree's .nano-edition marker (the public repo and the open bundle say open,
# the enterprise compose bundle says enterprise), NANO_EDITION in an existing
# install's .env, and the NANO_EDITION environment variable. Any disagreement
# fails closed; an install never changes edition on a re-run. Enterprise uses
# images.enterprise.lock (enterprise bundle only; needs a registry login),
# open core uses images.lock (ghcr.io).
# NANO_INSTALL_DIR may also be an extracted release bundle (a directory with a
# .nano-bundle marker) instead of a git checkout.
# NANO_CHECK_ONLY=1 validates the inputs, prints the resolved edition, release
# and image source, and exits before writing .env, pulling or starting anything.
# Set NANO_SKIP_IMAGE_VERIFY=1 to skip the image digest supply-chain check.
# Unauthenticated ingest ports (Vector native :6000, raw OTLP :4317/:4318,
# Fluent :24224, bundled Tenzir :9095) bind 127.0.0.1. Opt in to exposing them
# with NANO_VECTOR_NATIVE_BIND_ADDRESS / NANO_OTLP_BIND_ADDRESS /
# NANO_FLUENT_BIND_ADDRESS / NANO_TENZIR_BIND_ADDRESS (persisted to .env).

main() {
set -euo pipefail
# The checkout and generated runtime configuration are bind-mounted into
# containers that intentionally run as non-root.  Keep those non-secret paths
# traversable/readable even when the caller (notably root) starts with umask
# 077.  Secret files are created atomically with explicit 0600/0640 modes
# below and in generated-secrets.sh / render-inventory.py.
umask 022

# NANO_INSTALLER_SCRIPT_PATH is captured at top level, beside the final `main`
# call: inside a function a streamed script reports BASH_SOURCE[0] as "main",
# which would resolve against a same-named file in the caller's directory.
INSTALLER_SOURCE_DIR=""
if [[ -n "${NANO_INSTALLER_SCRIPT_PATH:-}" && -f "$NANO_INSTALLER_SCRIPT_PATH" ]]; then
    INSTALLER_SOURCE_DIR=$(cd "$(dirname "$NANO_INSTALLER_SCRIPT_PATH")" && pwd -P)
fi
if [[ -z "${NANO_INSTALL_DIR:-}" ]]; then
    if [[ -n "$INSTALLER_SOURCE_DIR" \
        && ( -f "$INSTALLER_SOURCE_DIR/.nano-bundle" \
            || -f "$INSTALLER_SOURCE_DIR/.nano-edition" \
            || -e "$INSTALLER_SOURCE_DIR/.git" ) ]]; then
        # A directly executed checkout or extracted bundle is already the
        # install source. In particular, `/opt/nano/install.sh` must not ignore
        # its enterprise bundle and clone the public repository into ~/nano.
        NANO_INSTALL_DIR="$INSTALLER_SOURCE_DIR"
    else
        # curl | bash has no source file, so retain the one-line install default.
        NANO_INSTALL_DIR="$HOME/nano"
    fi
fi
NANO_REPO_URL="${NANO_REPO_URL:-https://github.com/nano-rs/nano.git}"
NANO_BRANCH="${NANO_BRANCH:-main}"
NANO_VERSION="${NANO_VERSION:-}"
NANO_VERSION="${NANO_VERSION#v}"
ENV_EDITION="${NANO_EDITION:-}"
COMPOSE_FILE="docker-compose.opensource.yml"
ROLE_ARG=""
INVENTORY_ARG=""
TOPOLOGY_MIGRATION_SHA=""
ENV_TEMP_FILE=""
cleanup_env_temp() {
    [[ -z "$ENV_TEMP_FILE" ]] || rm -f -- "$ENV_TEMP_FILE"
}
trap cleanup_env_temp EXIT
while [[ $# -gt 0 ]]; do
    case "$1" in
        --role)
            [[ $# -ge 2 ]] || { printf '%s\n' "--role requires a comma-separated role list" >&2; exit 2; }
            ROLE_ARG="$2"; shift 2 ;;
        --inventory)
            [[ $# -ge 2 ]] || { printf '%s\n' "--inventory requires an inventory.yaml path" >&2; exit 2; }
            INVENTORY_ARG="$2"; shift 2 ;;
        --accept-topology-migration)
            [[ $# -ge 2 ]] || { printf '%s\n' "--accept-topology-migration requires the currently recorded identity SHA-256" >&2; exit 2; }
            TOPOLOGY_MIGRATION_SHA="$2"; shift 2 ;;
        -h|--help)
            cat <<'EOF'
Usage: install.sh [--role app,ingest,clickhouse,keeper,postgres --inventory inventory.yaml]
                  [--accept-topology-migration CURRENT_IDENTITY_SHA256]

Without role/inventory arguments, installs the unchanged single-node stack.
Enterprise bundles may select one or more roles from a shared host inventory.
The migration acknowledgement is valid only for a role-split install after its
data-movement runbook has completed; the exact recorded identity is required.
EOF
            exit 0 ;;
        *) printf 'Unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done
if [[ -n "$ROLE_ARG" && -z "$INVENTORY_ARG" ]] || [[ -z "$ROLE_ARG" && -n "$INVENTORY_ARG" ]]; then
    printf '%s\n' "--role and --inventory must be provided together" >&2
    exit 2
fi
if [[ -n "$TOPOLOGY_MIGRATION_SHA" && -z "$INVENTORY_ARG" ]]; then
    printf '%s\n' "--accept-topology-migration is valid only with --role/--inventory" >&2
    exit 2
fi
if [[ -n "$TOPOLOGY_MIGRATION_SHA" && ! "$TOPOLOGY_MIGRATION_SHA" =~ ^[0-9a-f]{64}$ ]]; then
    printf '%s\n' "--accept-topology-migration requires a lowercase 64-character SHA-256" >&2
    exit 2
fi
ROLE_ARG=$(printf '%s' "$ROLE_ARG" | tr -d '[:space:]')
# NAN-5172: licence inputs from the invoking environment, captured before
# anything else can reuse these names. The role-split renderer later exports
# NANO_DEPLOYMENT_ID as cluster.deployment_id (volume/project identity); the
# app.nano.rs-issued id given here is the licence id and never that.
LICENSE_URL_INPUT="${LICENSE_URL:-}"
LICENSE_TOKEN_INPUT="${LICENSE_TOKEN:-${DEPLOYMENT_TOKEN:-}}"
LICENSE_DEPLOYMENT_ID_INPUT="${NANO_DEPLOYMENT_ID:-}"
LICENSE_MODE_INPUT="${NANO_LICENSE_MODE:-}"
LICENSE_FILE_INPUT="${NANO_LICENSE_FILE:-}"
# Lowest major this installer may deploy. Mirrors LINE_FLOOR_MAJOR in
# scripts/ci/release-version.sh (not shipped in the public tree).
RELEASE_FLOOR_MAJOR=2

# 0 iff $1 is an X.Y.Z release on this product line (major >= RELEASE_FLOOR_MAJOR).
is_line_release() {
    [[ "$1" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] \
        && (( BASH_REMATCH[1] >= RELEASE_FLOOR_MAJOR ))
}

# Fail before anything is cloned, written, pulled or started.
if [[ -n "$NANO_VERSION" ]] && ! is_line_release "$NANO_VERSION"; then
    printf 'NANO_VERSION=%s is not a v%s+ release (X.Y.Z). No floating tag such as latest is published, and 0.x/1.x images belong to other product lines. Unset NANO_VERSION to use the checkout'"'"'s release.\n' \
        "$NANO_VERSION" "$RELEASE_FLOOR_MAJOR" >&2
    exit 1
fi
case "$ENV_EDITION" in
    "" | open | enterprise) ;;
    *) printf 'NANO_EDITION must be open or enterprise (got %s)\n' "$ENV_EDITION" >&2; exit 1 ;;
esac
# All traffic goes through the nginx reverse proxy on port 80. The internal
# nano-api / nano-search ports are not exposed to the host by default.
HOST_PORT="${NANO_HOST_PORT:-80}"
API_BASE="http://localhost:${HOST_PORT}"
# Extra curl flags for installer -> edge calls (see the TLS overlay below).
API_CURL_ARGS=()

# NAN-5124: an installer -> edge call succeeds only on a 2xx. `curl -f` fails
# only on 4xx/5xx, so a redirect (the TLS overlay's :80 -> https 301) used to
# read as success and the installer printed "Admin user created" with no admin.
# Usage: api_call <body-file|/dev/null> <curl args...>; prints the HTTP status.
api_call() {
    local out="$1" code
    shift
    code=$(curl -sS --max-redirs 0 -o "$out" -w '%{http_code}' \
        ${API_CURL_ARGS[@]+"${API_CURL_ARGS[@]}"} "$@" </dev/null 2>/dev/null) || code="${code:-000}"
    printf '%s' "${code:-000}"
    [[ "$code" == 2[0-9][0-9] ]]
}

c_reset='\033[0m'
c_bold='\033[1m'
c_red='\033[31m'
c_green='\033[32m'
c_yellow='\033[33m'
c_blue='\033[34m'

log()    { printf "%b==>%b %s\n" "$c_blue$c_bold" "$c_reset" "$*"; }
ok()     { printf "%b✓%b %s\n"   "$c_green$c_bold" "$c_reset" "$*"; }
warn()   { printf "%b!%b %s\n"   "$c_yellow$c_bold" "$c_reset" "$*"; }
fail()   { printf "%b✗ %s%b\n"   "$c_red$c_bold" "$*" "$c_reset" >&2; exit 1; }

resolve_env_target() {
    local current="$1" link directory hops=0
    [[ "$current" = /* ]] || current="$PWD/$current"
    while [[ -L "$current" ]]; do
        hops=$((hops + 1))
        (( hops <= 40 )) || return 1
        link=$(readlink "$current") || return 1
        if [[ "$link" = /* ]]; then
            current="$link"
        else
            current="$(dirname "$current")/$link"
        fi
    done
    directory=$(cd "$(dirname "$current")" 2>/dev/null && pwd -P) || return 1
    printf '%s/%s\n' "$directory" "$(basename "$current")"
}

validate_env_file() {
    local path="$1" target owner mode
    target=$(resolve_env_target "$path") \
        || fail "Cannot resolve $path. Correct the symbolic link before retrying; no secrets were read."
    [[ -f "$target" ]] \
        || fail "$path must resolve to a regular file owned by the installer user; no secrets were read."
    if owner=$(stat -f '%u' "$target" 2>/dev/null); then
        mode=$(stat -f '%Lp' "$target")
    else
        owner=$(stat -c '%u' "$target" 2>/dev/null) || fail "Cannot inspect owner of $path; no secrets were read."
        mode=$(stat -c '%a' "$target" 2>/dev/null) || fail "Cannot inspect mode of $path; no secrets were read."
    fi
    [[ "$owner" == "$(id -u)" ]] \
        || fail "$path is owned by uid $owner, not the current uid $(id -u). Correct ownership before retrying; no secrets were read."
    [[ "$mode" == "600" ]] \
        || fail "$path has mode $mode; run 'chmod 600 $path' before retrying. No secrets were read."
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "$1 is required but not installed. $2"
}

prompt_tty() {
    # $1 = prompt, $2 = default value (optional), $3 = "secret" to suppress echo
    local prompt="$1" default="${2:-}" secret="${3:-}" answer=""
    local display_prompt="$prompt"
    [[ -n "$default" ]] && display_prompt="$prompt [$default]"

    if ! have_controlling_tty; then
        # `/dev/tty` commonly exists in noninteractive services but open(2)
        # returns ENXIO because the process has no controlling terminal.
        fail "No TTY available for interactive prompts. Set NANO_ADMIN_EMAIL, NANO_ADMIN_NAME, NANO_ADMIN_PASSWORD, NANO_BASE_URL via env and re-run."
    fi

    if [[ -n "$secret" ]]; then
        printf "%s: " "$display_prompt" > /dev/tty
        IFS= read -rs answer < /dev/tty || true
        printf "\n" > /dev/tty
    else
        printf "%s: " "$display_prompt" > /dev/tty
        IFS= read -r answer < /dev/tty || true
    fi
    [[ -z "$answer" && -n "$default" ]] && answer="$default"
    printf "%s" "$answer"
}

have_controlling_tty() {
    (exec 9<>/dev/tty) 2>/dev/null
}

# Yes/no answer -> true/false; empty output for anything else.
normalize_bool() {
    case "$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')" in
        y|yes|true|1|on)   printf 'true' ;;
        n|no|false|0|off)  printf 'false' ;;
    esac
}

# Outbound proxy URL: http(s)://[user[:pass]@]host:port[/]. No quotes,
# whitespace or newlines can reach .env.
valid_proxy_url() {
    [[ "${1:-}" =~ ^https?://([A-Za-z0-9._~%-]+(:[A-Za-z0-9._~%-]+)?@)?([A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\]):[0-9]{1,5}/?$ ]]
}

# A proxy URL for output: any user[:pass]@ is replaced by ***@ so credentials
# never reach the terminal or a captured install log.
redact_proxy_url() {
    printf '%s' "${1:-}" | sed -E 's#^([A-Za-z][A-Za-z0-9+.-]*://)[^/@]*@#\1***@#'
}

# The same shape without credentials: what the interactive prompt accepts.
valid_proxy_hostport() {
    [[ "${1:-}" =~ ^https?://([A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\]):[0-9]{1,5}/?$ ]]
}

strip_proxy_userinfo() {
    printf '%s' "${1:-}" | sed -E 's#^([A-Za-z][A-Za-z0-9+.-]*://)[^/@]*@#\1#'
}

# Percent-encode every byte outside RFC 3986 unreserved (A-Z a-z 0-9 - . _ ~).
pct_encode() {
    local LC_ALL=C value="${1:-}" out="" char hex i
    for ((i = 0; i < ${#value}; i++)); do
        char="${value:i:1}"
        case "$char" in
            [A-Za-z0-9._~-]) out+="$char" ;;
            *) printf -v hex '%%%02X' "'$char"; out+="$hex" ;;
        esac
    done
    printf '%s' "$out"
}

# ask_yes_no <question> <Y|N default> -> true/false; re-asks on anything else.
ask_yes_no() {
    local answer hint="[y/N]"
    [[ "$2" == "Y" ]] && hint="[Y/n]"
    while :; do
        answer=$(prompt_tty "$1 $hint")
        [[ -z "$answer" ]] && answer="$2"
        answer=$(normalize_bool "$answer")
        [[ -n "$answer" ]] && { printf '%s' "$answer"; return 0; }
        warn "Answer y or n."
    done
}

# Extra NO_PROXY entries: comma-separated host / domain / IP / CIDR tokens.
valid_no_proxy() {
    [[ "${1:-}" =~ ^[A-Za-z0-9.*:/_-]+(,[A-Za-z0-9.*:/_-]+)*$ ]]
}

# Corporate egress proxy for nano's own outbound calls (licence check-in,
# feeds, content, OIDC/identity sync, S3 tiering). Asked once, only while
# .env has neither HTTPS_PROXY nor a recorded answer; a re-run or upgrade
# never asks again. Unattended installs pass NANO_HTTPS_PROXY (and
# NANO_NO_PROXY). No TTY and no input means no proxy. A proxy already
# exported in the installer's shell is offered as the default.
configure_outbound_proxy() {
    local answer url extra auth="" user="" pass="" confirm default_answer="N"
    local shell_proxy="${HTTPS_PROXY:-${https_proxy:-}}"
    if [[ -n "$(env_value HTTPS_PROXY)" || -n "$(env_value NANO_OUTBOUND_PROXY_ASKED)" ]]; then
        return 0
    fi
    url="" extra=""
    if [[ -n "${NANO_HTTPS_PROXY:-}" ]]; then
        url="$NANO_HTTPS_PROXY" extra="${NANO_NO_PROXY:-}"
        user="${NANO_PROXY_USERNAME:-}" pass="${NANO_PROXY_PASSWORD:-}"
    elif have_controlling_tty; then
        # Offer an exported proxy as the default, without any credentials it
        # carries (they would be shown in the prompt).
        shell_proxy=$(strip_proxy_userinfo "$shell_proxy")
        valid_proxy_hostport "$shell_proxy" || shell_proxy=""
        [[ -n "$shell_proxy" ]] && default_answer="Y"
        answer=$(ask_yes_no "Does this server reach the internet through an HTTP(S) proxy?" "$default_answer")
        if [[ "$answer" == "true" ]]; then
            while :; do
                url=$(prompt_tty "Proxy URL (http://host:port)" "$shell_proxy")
                valid_proxy_hostport "$url" && break
                warn "Enter the proxy as http://host:port or https://host:port (no credentials, quotes or spaces)."
            done
            auth=$(ask_yes_no "Does the proxy require a username and password?" "N")
            if [[ "$auth" == "true" ]]; then
                while :; do
                    user=$(prompt_tty "Proxy username (DOMAIN\\user is fine)")
                    [[ -n "$user" ]] && break
                    warn "Enter the proxy username."
                done
                while :; do
                    pass=$(prompt_tty "Proxy password" "" secret)
                    confirm=$(prompt_tty "Confirm proxy password" "" secret)
                    if [[ -z "$pass" ]]; then
                        warn "Enter the proxy password."
                    elif [[ "$pass" != "$confirm" ]]; then
                        warn "The passwords do not match. Enter them again."
                    else
                        break
                    fi
                done
            fi
            while :; do
                extra=$(prompt_tty "Extra hosts that bypass the proxy, comma-separated (blank = none)" "${NO_PROXY:-${no_proxy:-}}")
                [[ -z "$extra" ]] && break
                valid_no_proxy "$extra" && break
                warn "Enter comma-separated host names, domains, IPs or CIDRs (no spaces)."
            done
        fi
    fi
    if [[ -n "$url" && -n "$user" ]]; then
        # RFC 3986 userinfo: everything outside the unreserved set is
        # percent-encoded (DOMAIN\user, p@ss:w/rd!# ...). reqwest decodes it.
        url="${url%%://*}://$(pct_encode "$user"):$(pct_encode "$pass")@${url#*://}"
    fi
    user="" pass="" confirm=""
    # Append the effective assignments so a symlinked .env remains a link
    # (and keeps its 0600 mode).
    if [[ -n "$url" ]]; then
        printf 'HTTPS_PROXY=%s\nHTTP_PROXY=%s\n' "$url" "$url" >> .env
        [[ -n "$extra" ]] && printf 'NO_PROXY=%s\n' "$extra" >> .env
        log "nano's outbound calls use the proxy $(redact_proxy_url "$url") (HTTPS_PROXY in .env; internal services and private ranges bypass it)"
        log "Docker image pulls use the Docker daemon's own proxy settings (a systemd drop-in for docker.service), not nano's: https://nano.rs/docs/getting-started/self-run#corporate-proxy"
    fi
    printf 'NANO_OUTBOUND_PROXY_ASKED=true\n' >> .env
}

# Private-address AI providers (a BYO local LLM on 10.x / 192.168.x). The AI
# base-URL validator refuses private addresses unless
# NANOSIEM_ALLOW_PRIVATE_AI_ENDPOINTS is on (cloud-metadata stays blocked
# either way). Asked once, only while .env has no value; the answer is kept in
# .env so a re-run or upgrade never asks again. Unattended installs pass
# NANO_ALLOW_PRIVATE_AI_ENDPOINTS=true|false; with no TTY the default is false.
configure_private_ai_endpoints() {
    local recorded answer
    recorded=$(env_value NANOSIEM_ALLOW_PRIVATE_AI_ENDPOINTS)
    if [[ -n "$recorded" ]]; then
        PRIVATE_AI_ENDPOINTS="$recorded"
        return 0
    fi
    if [[ -n "${NANO_ALLOW_PRIVATE_AI_ENDPOINTS:-}" ]]; then
        PRIVATE_AI_ENDPOINTS=$(normalize_bool "$NANO_ALLOW_PRIVATE_AI_ENDPOINTS")
    elif have_controlling_tty; then
        while :; do
            answer=$(prompt_tty "Will nano use an AI model hosted on your own network (e.g. a local LLM on 192.168.x / 10.x)? This allows the AI provider URL to point at private addresses (cloud-metadata stays blocked). [y/N]")
            [[ -z "$answer" ]] && answer=n
            PRIVATE_AI_ENDPOINTS=$(normalize_bool "$answer")
            [[ -n "$PRIVATE_AI_ENDPOINTS" ]] && break
            warn "Answer y or n."
        done
    else
        PRIVATE_AI_ENDPOINTS=false
    fi
    # Append the effective assignment so a symlinked .env remains a link.
    printf 'NANOSIEM_ALLOW_PRIVATE_AI_ENDPOINTS=%s\n' "$PRIVATE_AI_ENDPOINTS" >> .env
    if [[ "$PRIVATE_AI_ENDPOINTS" == "true" ]]; then
        log "AI providers on private addresses are allowed (NANOSIEM_ALLOW_PRIVATE_AI_ENDPOINTS=true in .env)"
    fi
}

# Automatic backups (NAN-5204). Asked once on a TTY, only while .env records
# no answer; a re-run or upgrade never asks again, and
# `scripts/nano backup-schedule --configure` changes it later. Unattended
# installs pass NANO_BACKUP_ENABLED=true plus NANO_BACKUP_* (no TTY and no
# input means off). The prompts, the destination probe (write + delete a test
# object) and the .env update live in scripts/nano-backup-scheduler.py so the
# installer and the later reconfigure share one implementation.
configure_automatic_backups() {
    [[ "$(env_value NANO_BACKUP_ASKED)" == "true" ]] && return 0
    if [[ "$MULTI_NODE" == "1" ]]; then
        if [[ ",${ROLE_ARG}," == *,app,* ]]; then
            log "Automatic backups for a role-split cluster run from the app host: scripts/nano backup-schedule --configure"
        fi
        return 0
    fi
    # A release without the scheduler (or a trimmed fixture) has nothing to set up.
    [[ -f scripts/nano-backup-scheduler.py ]] || return 0
    if ! command -v python3 >/dev/null 2>&1; then
        warn "Automatic backups need python3 on this host; install it, then run scripts/nano backup-schedule --configure."
        return 0
    fi
    python3 -I scripts/nano-backup-scheduler.py --install-dir "$PWD" configure --from-installer \
        || fail "Automatic backup setup failed (see above). Fix the destination, or set NANO_BACKUP_ENABLED=false, and re-run."
}

# ----------------------------------------------------------------------------
# Licence (NAN-5172): asked once on first install, recorded in .env.
# ----------------------------------------------------------------------------
# Enterprise api/jobs either check in online with the three values from the
# deployment's page in app.nano.rs (LICENSE_URL, LICENSE_TOKEN,
# NANO_DEPLOYMENT_ID) or are admitted by an offline C05 licence file imported
# after install. NANO_LICENSE_MODE in .env records the choice
# (online | offline | airgap) so a re-run or upgrade never asks again;
# "pending" marks a prepared .env whose values are still to be added.
LICENSE_DEFAULT_URL="https://api.nano.rs/api/license/status"
LICENSE_PAGE_HINT="https://app.nano.rs → Deployments → your Self-run deployment → Licence"
# nanosiem-enterprise/src/sovereign_license/wire.rs MAX_LICENSE_BYTES.
OFFLINE_LICENSE_MAX_BYTES=262144

valid_license_url() {
    [[ "${1:-}" =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$ ]]
}
# app.nano.rs issues 32 random bytes as base64url (43 characters); older
# platform tokens are 64 hex characters. Either fits this shape.
valid_license_token() {
    [[ "${1:-}" =~ ^[A-Za-z0-9_-]{32,255}$ ]]
}
# A nano-main typeid: deploy_ + 26 lowercase Crockford base32 characters.
valid_deployment_id() {
    [[ "${1:-}" =~ ^deploy_[0-9a-hjkmnp-tv-z]{26}$ ]]
}
is_truthy() {
    [[ "$(normalize_bool "${1:-}")" == "true" ]]
}

# A value pasted with its KEY= prefix ("LICENSE_TOKEN=abc", as the deployment
# page shows it) is accepted as the bare value; surrounding quotes and
# whitespace are dropped.
strip_license_paste() {
    local value="${1:-}" key="$2"
    value=$(printf '%s' "$value" | tr -d '\r' | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')
    value="${value#export }"
    value="${value#"$key"=}"
    [[ "$key" == "LICENSE_TOKEN" ]] && value="${value#DEPLOYMENT_TOKEN=}"
    value="${value#\"}"; value="${value%\"}"
    value="${value#\'}"; value="${value%\'}"
    printf '%s' "$value"
}

# Offline licence file to import after install: a readable regular file of
# 1..OFFLINE_LICENSE_MAX_BYTES bytes holding a JSON object. Prints the
# absolute path. The signature is verified by nano-api at import.
resolve_offline_license_file() {
    local path="$1" size first
    [[ -f "$path" && -r "$path" ]] || { warn "Offline licence file not found or not readable: $path"; return 1; }
    size=$(wc -c < "$path" | tr -d '[:space:]')
    if (( size < 1 || size > OFFLINE_LICENSE_MAX_BYTES )); then
        warn "Offline licence file must be 1 to $OFFLINE_LICENSE_MAX_BYTES bytes (got $size): $path"
        return 1
    fi
    first=$(tr -d ' \t\r\n' < "$path" | head -c 1)
    [[ "$first" == "{" ]] || { warn "Offline licence file is not a signed licence JSON file: $path"; return 1; }
    printf '%s/%s' "$(cd "$(dirname "$path")" && pwd -P)" "$(basename "$path")"
}

# Validate the licence values given in the environment. Runs before anything
# is written, including under NANO_CHECK_ONLY. Never prints the token.
validate_license_inputs() {
    [[ "$NANO_EDITION" == "enterprise" ]] || return 0
    case "$LICENSE_MODE_INPUT" in
        ""|online|offline) ;;
        *) fail "NANO_LICENSE_MODE must be online or offline (got '$LICENSE_MODE_INPUT')." ;;
    esac
    if [[ -n "$LICENSE_URL_INPUT" ]] && ! valid_license_url "$LICENSE_URL_INPUT"; then
        fail "LICENSE_URL must be an https:// URL such as $LICENSE_DEFAULT_URL (got '$LICENSE_URL_INPUT'). Copy it from $LICENSE_PAGE_HINT."
    fi
    if [[ -n "$LICENSE_TOKEN_INPUT" ]] && ! valid_license_token "$LICENSE_TOKEN_INPUT"; then
        fail "LICENSE_TOKEN is not an enrollment token (expected 32+ letters, digits, '-' or '_'; value not shown). Copy it from $LICENSE_PAGE_HINT."
    fi
    # NANO_DEPLOYMENT_ID alone is not a licence input: older role-split
    # guides exported it for other purposes. It is checked with a token.
    if [[ -n "$LICENSE_TOKEN_INPUT" && -n "$LICENSE_DEPLOYMENT_ID_INPUT" ]] \
        && ! valid_deployment_id "$LICENSE_DEPLOYMENT_ID_INPUT"; then
        fail "NANO_DEPLOYMENT_ID must be the deployment ID from app.nano.rs, like deploy_01h2x3y4z5... (got '$LICENSE_DEPLOYMENT_ID_INPUT')."
    fi
    # A re-run may still export LICENSE_URL alone; the recorded token covers it.
    if [[ -z "$LICENSE_TOKEN_INPUT" && -n "$LICENSE_URL_INPUT" && "$LICENSE_MODE_INPUT" != "online" ]] \
        && [[ -n "$(env_value LICENSE_TOKEN)$(env_value DEPLOYMENT_TOKEN)" ]]; then
        return 0
    fi
    if [[ -n "$LICENSE_URL_INPUT$LICENSE_TOKEN_INPUT" || "$LICENSE_MODE_INPUT" == "online" ]]; then
        [[ -n "$LICENSE_TOKEN_INPUT" && -n "$LICENSE_DEPLOYMENT_ID_INPUT" ]] \
            || fail "Set LICENSE_TOKEN and NANO_DEPLOYMENT_ID together (LICENSE_URL defaults to $LICENSE_DEFAULT_URL). Copy them from $LICENSE_PAGE_HINT."
        [[ "$LICENSE_MODE_INPUT" != "offline" && -z "$LICENSE_FILE_INPUT" ]] \
            || fail "Choose one licence: the online values (LICENSE_TOKEN, NANO_DEPLOYMENT_ID) or an offline licence (NANO_LICENSE_MODE=offline / NANO_LICENSE_FILE), not both."
        is_truthy "${AIRGAP_MODE:-}" \
            && fail "AIRGAP_MODE=true never checks in online; leave out LICENSE_URL/LICENSE_TOKEN and import an offline licence after install."
    fi
    if [[ -n "$LICENSE_FILE_INPUT" ]]; then
        resolve_offline_license_file "$LICENSE_FILE_INPUT" >/dev/null \
            || fail "NANO_LICENSE_FILE is not usable; nothing was written."
    fi
    return 0
}

# Decide the licence for this install. Sets LICENSE_ENV_LINES (assignments to
# append to .env, possibly empty), LICENSE_MODE and LICENSE_IMPORT_FILE. $1 is
# 1 on first install (no .env yet), 0 when an .env is reused.
# Prompts at most once, only with a controlling TTY.
LICENSE_ENV_LINES="" LICENSE_MODE="" LICENSE_IMPORT_FILE="" LICENSE_DEPLOYMENT_ID=""
resolve_license() {
    local first_install="$1" recorded_mode recorded_url recorded_token recorded_id choice default_choice
    local url token deployment_id path
    LICENSE_ENV_LINES="" LICENSE_MODE="" LICENSE_IMPORT_FILE="" LICENSE_DEPLOYMENT_ID=""
    if [[ "$NANO_EDITION" != "enterprise" ]]; then
        if [[ -n "$LICENSE_TOKEN_INPUT$LICENSE_FILE_INPUT" ]]; then
            warn "Open edition has no licence check; LICENSE_TOKEN / NANO_LICENSE_FILE are ignored."
        fi
        LICENSE_MODE=none
        return 0
    fi
    # Only the app role runs nano-api / nano-jobs. Data and ingest hosts get
    # the values in the shared .env copied from the app host.
    if [[ "$MULTI_NODE" == "1" && ",${ROLE_ARG}," != *,app,* ]]; then
        LICENSE_MODE=app-host
        return 0
    fi
    recorded_mode=$(env_value NANO_LICENSE_MODE)
    recorded_url=$(env_value LICENSE_URL)
    recorded_token=$(env_value LICENSE_TOKEN)
    [[ -n "$recorded_token" ]] || recorded_token=$(env_value DEPLOYMENT_TOKEN)
    recorded_id=$(env_value NANO_DEPLOYMENT_ID)

    # 1. Values given to this run (first install, a prepared .env, or a new
    #    token after "Regenerate licence token" on the deployment page).
    if [[ -n "$LICENSE_TOKEN_INPUT" ]]; then
        url="${LICENSE_URL_INPUT:-${recorded_url:-$LICENSE_DEFAULT_URL}}"
        LICENSE_MODE=online LICENSE_DEPLOYMENT_ID="$LICENSE_DEPLOYMENT_ID_INPUT"
        [[ "$url" == "$recorded_url" ]] || LICENSE_ENV_LINES+="LICENSE_URL=$url"$'\n'
        [[ "$LICENSE_TOKEN_INPUT" == "$recorded_token" ]] || LICENSE_ENV_LINES+="LICENSE_TOKEN=$LICENSE_TOKEN_INPUT"$'\n'
        [[ "$LICENSE_DEPLOYMENT_ID_INPUT" == "$recorded_id" ]] || LICENSE_ENV_LINES+="NANO_DEPLOYMENT_ID=$LICENSE_DEPLOYMENT_ID_INPUT"$'\n'
        if [[ "$first_install" == "0" && -n "$recorded_token" && "$LICENSE_TOKEN_INPUT" != "$recorded_token" ]]; then
            log "Replacing the licence token recorded in .env with the one given to this run (value not shown)"
        fi
    elif [[ "$LICENSE_MODE_INPUT" == "offline" || -n "$LICENSE_FILE_INPUT" ]]; then
        LICENSE_MODE=offline
        [[ -z "$LICENSE_FILE_INPUT" ]] || LICENSE_IMPORT_FILE=$(resolve_offline_license_file "$LICENSE_FILE_INPUT") \
            || fail "NANO_LICENSE_FILE is not usable; nothing was written."
    elif is_truthy "${AIRGAP_MODE:-}" || is_truthy "$(env_value AIRGAP_MODE)"; then
        LICENSE_MODE=airgap
    # 2. Already recorded: a re-run, an upgrade, or values appended by hand to
    #    a prepared .env. Never asks again.
    elif [[ -n "$recorded_token" && -n "$recorded_id" ]]; then
        LICENSE_MODE=online LICENSE_DEPLOYMENT_ID="$recorded_id"
        [[ -n "$recorded_url" ]] || LICENSE_ENV_LINES+="LICENSE_URL=$LICENSE_DEFAULT_URL"$'\n'
    elif [[ "$recorded_mode" == "offline" || "$recorded_mode" == "airgap" ]]; then
        LICENSE_MODE="$recorded_mode"
    # 3. Nothing known: ask once.
    elif have_controlling_tty; then
        # A pre-2.0.5 install that reaches here was admitted by an offline
        # licence imported in the UI (or not licensed yet): keep that default.
        default_choice=online
        [[ "$first_install" == "0" && -z "$recorded_mode" ]] && default_choice=offline
        while :; do
            choice=$(prompt_tty "Licence: online check-in (paste the 3 values from app.nano.rs) or offline file (path)? [online/offline]" "$default_choice")
            choice=$(printf '%s' "$choice" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
            case "$choice" in
                online|on|1) choice=online; break ;;
                offline|off|file|2) choice=offline; break ;;
                *) warn "Answer online or offline." ;;
            esac
        done
        if [[ "$choice" == "online" ]]; then
            while :; do
                url=$(strip_license_paste "$(prompt_tty "LICENSE_URL" "$LICENSE_DEFAULT_URL")" LICENSE_URL)
                valid_license_url "$url" && break
                warn "Enter the https:// licence URL shown on the deployment page."
            done
            while :; do
                token=$(strip_license_paste "$(prompt_tty "LICENSE_TOKEN (input hidden)" "" secret)" LICENSE_TOKEN)
                valid_license_token "$token" && break
                warn "That is not an enrollment token (value not shown). Paste LICENSE_TOKEN from the deployment page; if it was lost, regenerate it there."
            done
            while :; do
                deployment_id=$(strip_license_paste "$(prompt_tty "NANO_DEPLOYMENT_ID")" NANO_DEPLOYMENT_ID)
                valid_deployment_id "$deployment_id" && break
                warn "Enter the deployment ID from the deployment page (deploy_ followed by 26 characters)."
            done
            LICENSE_MODE=online LICENSE_DEPLOYMENT_ID="$deployment_id"
            LICENSE_ENV_LINES="LICENSE_URL=$url"$'\n'"LICENSE_TOKEN=$token"$'\n'"NANO_DEPLOYMENT_ID=$deployment_id"$'\n'
            token=""
        else
            LICENSE_MODE=offline
            while :; do
                path=$(prompt_tty "Offline licence file path (blank = import it after install under Settings → Licence)")
                [[ -z "$path" ]] && break
                LICENSE_IMPORT_FILE=$(resolve_offline_license_file "$path") && break
            done
        fi
    elif [[ "$first_install" == "0" && -z "$recorded_mode" ]]; then
        # Unattended upgrade of an install from before this choice existed:
        # it runs on the offline (C05) licence it already has. Don't block it.
        LICENSE_MODE=offline
    elif [[ "${NANO_PREPARE_ONLY:-0}" == "1" ]]; then
        LICENSE_MODE=pending
        [[ "$recorded_mode" == "pending" ]] || LICENSE_ENV_LINES="NANO_LICENSE_MODE=pending"$'\n'
        warn "No licence values yet. Before running ./install.sh, add LICENSE_URL, LICENSE_TOKEN and NANO_DEPLOYMENT_ID to .env (from $LICENSE_PAGE_HINT), or pass them to ./install.sh, or set NANO_LICENSE_MODE=offline."
        return 0
    else
        fail "No licence for this unattended enterprise install (no TTY to ask). Pass LICENSE_URL, LICENSE_TOKEN and NANO_DEPLOYMENT_ID from $LICENSE_PAGE_HINT, for example: NANO_IMAGES_LOCK=images.enterprise.customer.lock LICENSE_URL=$LICENSE_DEFAULT_URL LICENSE_TOKEN=<token> NANO_DEPLOYMENT_ID=<deployment id> ./install.sh. Without access to api.nano.rs, set NANO_LICENSE_MODE=offline (import the licence file after install) or AIRGAP_MODE=true. Nothing was started."
    fi
    [[ "$LICENSE_MODE" == "$recorded_mode" ]] || LICENSE_ENV_LINES+="NANO_LICENSE_MODE=$LICENSE_MODE"$'\n'
    return 0
}

# Append LICENSE_ENV_LINES to $1 and say what was decided (token redacted).
record_license() {
    local target="$1"
    [[ -z "$LICENSE_ENV_LINES" ]] || printf '%s' "$LICENSE_ENV_LINES" >> "$target"
    LICENSE_ENV_LINES=""
    case "$LICENSE_MODE" in
        online)
            ok "Licence: online check-in for deployment $LICENSE_DEPLOYMENT_ID (LICENSE_TOKEN ******** in .env)" ;;
        offline)
            if [[ -n "$LICENSE_IMPORT_FILE" ]]; then
                ok "Licence: offline; $LICENSE_IMPORT_FILE is imported after the admin account is created"
            else
                ok "Licence: offline; import the licence file after install under Settings → Licence"
            fi ;;
        airgap) ok "Licence: air-gapped (AIRGAP_MODE); import the offline licence after install" ;;
    esac
}

# Admin email / display name are kept in .env so a re-run (prepare, then
# install; or a retry after a failed start) can still create the account.
# Single-quoted for Compose, which would otherwise interpolate '$'. A value
# that cannot be single-quoted safely is not persisted. Never the password.
persistable_env_value() {
    [[ -n "${1:-}" && "$1" != *[\'\"\\\`\$]* && "$1" != *[[:cntrl:]]* ]]
}

# Import the offline licence file chosen at install (NANO_LICENSE_FILE or the
# prompt) as the admin, once the account exists. Best effort: nano is already
# up, so a refusal is reported with the manual path instead of failing.
# Secrets go to curl through 0600 files, never its command line.
import_offline_license() {
    [[ -n "${LICENSE_IMPORT_FILE:-}" ]] || return 0
    local manual="Import $LICENSE_IMPORT_FILE under Settings → Licence ($BASE_URL/settings/license)."
    local scratch code access_token
    if [[ -z "${ADMIN_PASSWORD:-}" ]]; then
        warn "$manual The installer needs the admin password (NANO_ADMIN_PASSWORD) to import it."
        return 0
    fi
    scratch=$(mktemp -d) || { warn "$manual"; return 0; }
    chmod 700 "$scratch"
    printf '{"email":%s,"password":%s}' "$(json_escape "$ADMIN_EMAIL")" "$(json_escape "$ADMIN_PASSWORD")" > "$scratch/login"
    if ! code=$(api_call "$scratch/session" -X POST -H "Content-Type: application/json" \
        --data-binary "@$scratch/login" "${API_BASE}/api/auth/login"); then
        rm -rf "$scratch"
        warn "Could not sign in as $ADMIN_EMAIL to import the offline licence (HTTP $code). $manual"
        return 0
    fi
    access_token=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tokens"]["access_token"])' "$scratch/session" </dev/null 2>/dev/null \
        || node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).tokens.access_token)' -- "$scratch/session" </dev/null 2>/dev/null) \
        || access_token=""
    if [[ -z "$access_token" ]]; then
        rm -rf "$scratch"
        warn "Could not read the sign-in response to import the offline licence. $manual"
        return 0
    fi
    printf 'Authorization: Bearer %s\n' "$access_token" > "$scratch/auth"
    access_token=""
    if code=$(api_call /dev/null -X POST -H "@$scratch/auth" -H "Content-Type: application/json" \
        --data-binary "@$LICENSE_IMPORT_FILE" "${API_BASE}/api/license/import"); then
        ok "Offline licence imported from $LICENSE_IMPORT_FILE"
    elif [[ "$code" == "409" ]]; then
        warn "The offline licence was refused (HTTP 409): it is bound to another installation, superseded or out of term. On your deployment's page in app.nano.rs, enter this install's installation and organization IDs (Settings → Licence) and download a new file. $manual"
    else
        warn "The offline licence was not imported (HTTP $code). $manual"
    fi
    rm -rf "$scratch"
}

gen_secret() { openssl rand -hex 32 </dev/null; }

# Keep first-run validation identical to nanosiem-core's authoritative policy.
# This runs before .env is written or any image is pulled/started, so a weak
# non-interactive password cannot leave a distributed install half-mutated.
validate_admin_password() {
    local password="$1" byte_length i char
    local has_upper=0 has_lower=0 has_digit=0 has_special=0
    local LC_ALL=C
    byte_length=${#password}
    if (( byte_length < 12 || byte_length > 1024 )); then
        fail "Admin password must be 12 to 1024 bytes and contain uppercase, lowercase, a digit, and a special character."
    fi
    for ((i = 0; i < byte_length; i++)); do
        char=${password:i:1}
        case "$char" in
            [A-Z]) has_upper=1 ;;
            [a-z]) has_lower=1 ;;
            [0-9]) has_digit=1 ;;
            '!'|'@'|'#'|'$'|'%'|'^'|'&'|'*'|'('|')'|'-'|'_'|'='|'+'|'['|']'|'{'|'}'|'|'|'\'|';'|':'|"'"|'"'|','|'.'|'<'|'>'|'/'|'?'|'`'|'~') has_special=1 ;;
        esac
    done
    if (( ! has_upper || ! has_lower || ! has_digit || ! has_special )); then
        fail "Admin password must be 12 to 1024 bytes and contain uppercase, lowercase, a digit, and a special character."
    fi
}
# NAN-4957: enrichment (the IPinfo, Tor, ThreatFox platform feeds) REQUIRES a
# 6G ClickHouse. Informational only — does not change the sizing above, and
# says nothing about smaller limits when the feeds are off (2-4G is fine for
# small and test tenants). Feeds are on unless .env turns
# PLATFORM_FEEDS_AUTO_UPDATE off.
ch_mem_feeds_note() {
    local v n unit mib
    # Dedicated app, ingest, PostgreSQL, and Keeper hosts do not run a
    # ClickHouse server. Their role-local sizing cannot act on this warning,
    # and emitting it made healthy split installs look under-provisioned.
    if [[ "${MULTI_NODE:-0}" == "1" && ",${ROLE_ARG:-}," != *,clickhouse,* ]]; then
        return 0
    fi
    if grep -qiE '^PLATFORM_FEEDS_AUTO_UPDATE=["'"'"']?(0|false|no|off)' .env 2>/dev/null; then
        return 0
    fi
    v="${CLICKHOUSE_MEM_LIMIT:-}"
    if [[ -z "$v" ]]; then
        v=$(grep -E '^CLICKHOUSE_MEM_LIMIT=' .env 2>/dev/null | tail -n1 | cut -d= -f2- | tr -d "\"' ")
    fi
    [[ -z "$v" ]] && v=2G   # compose fallback when the var is absent
    if [[ "$v" =~ ^([0-9]+)([gGmM])[bB]?$ ]]; then
        n=${BASH_REMATCH[1]}; unit=${BASH_REMATCH[2]}
        case "$unit" in g|G) mib=$((n * 1024)) ;; *) mib=$n ;; esac
    else
        return 0   # unparseable: leave it to the operator
    fi
    if (( mib < 6144 )); then
        warn "Enrichment requires 6 GB for ClickHouse; CLICKHOUSE_MEM_LIMIT is $v and the enrichment feeds (IPinfo, Tor, ThreatFox) are on. Raise it to CLICKHOUSE_MEM_LIMIT=6G in .env, or disable the feeds with PLATFORM_FEEDS_AUTO_UPDATE=false, then docker compose up -d. Without the memory, events get no geo/ASN (ingest keeps working)."
    fi
}

# Escape a string for safe embedding inside a JSON string literal.
# Handles backslash, double-quote, and the C0 controls that JSON forbids.
json_escape() {
    python3 -c 'import json,sys; sys.stdout.write(json.dumps(sys.argv[1]))' "$1" </dev/null 2>/dev/null \
        || node -e 'process.stdout.write(JSON.stringify(process.argv[1]))' -- "$1" </dev/null 2>/dev/null \
        || fail "Neither python3 nor node is available to JSON-escape the admin password. Install one and retry."
}

# Classify the rendered Vector data mount without trusting raw YAML text. Fresh
# single-node installs already require one of Python/Node for JSON-safe admin
# setup; retain that portable soft dependency rather than making Python alone a
# new quickstart prerequisite.
vector_data_storage_mode_from_json() {
    if command -v python3 >/dev/null 2>&1; then
        python3 -c '
import json
import sys

document = json.load(sys.stdin)
mounts = [
    mount
    for mount in document.get("services", {}).get("vector", {}).get("volumes", [])
    if mount.get("target") == "/var/lib/vector"
]
if len(mounts) != 1:
    raise SystemExit("Vector must have exactly one /var/lib/vector mount")
mount = mounts[0]
if mount.get("type") == "volume":
    definition = document.get("volumes", {}).get(mount.get("source"), {})
    driver = definition.get("driver", "local")
    options = definition.get("driver_opts") or {}
    external = bool(definition.get("external"))
    print("named" if driver == "local" and not options and not external else "bind")
else:
    print("bind")
'
        return
    fi
    if command -v node >/dev/null 2>&1; then
        node -e '
let input = "";
process.stdin.on("data", chunk => input += chunk).on("end", () => {
  const document = JSON.parse(input);
  const mounts = (((document.services || {}).vector || {}).volumes || [])
    .filter(mount => mount.target === "/var/lib/vector");
  if (mounts.length !== 1) process.exit(2);
  const mount = mounts[0];
  if (mount.type !== "volume") return console.log("bind");
  const definition = (document.volumes || {})[mount.source] || {};
  const options = definition.driver_opts || {};
  const named = (definition.driver || "local") === "local"
    && Object.keys(options).length === 0 && !definition.external;
  console.log(named ? "named" : "bind");
});
'
        return
    fi
    fail "Neither python3 nor node is available to inspect Vector's rendered data mount. Install one and retry."
}

# Verify that the images we just pulled match the sha256 manifest digests
# recorded in images.lock. Docker already checksum-verifies layers on pull, but
# that only proves the bytes are internally consistent — it does NOT prove a
# floating tag wasn't re-pushed with different content. Pinning to a vouched
# digest closes that supply-chain gap (NAN-1258).
#
# images.lock has two kinds of lines, told apart by whether the image reference
# carries a tag (a ':' in its last path segment):
#   - First-party  "ghcr.io/nano-rs/nano-api sha256:…"  (no tag) — the tag is
#     NANO_VERSION, and the digest is release-specific. CI regenerates these.
#   - Third-party  "postgres:17 sha256:…"  (tagged, self-contained) — mirrors
#     the @sha256 pins in docker-compose.opensource.yml. Version-independent.

# Resolve owner/repo from NANO_REPO_URL when it points at GitHub, else empty.
github_owner_repo() {
    local s="$NANO_REPO_URL"
    case "$s" in
        *github.com*) ;;
        *) return 1 ;;
    esac
    # Strip scheme/host and any trailing .git, normalize git@ and https forms.
    s="${s#*github.com}"; s="${s#:}"; s="${s#/}"; s="${s%.git}"; s="${s%/}"
    [[ "$s" == */* ]] || return 1
    printf '%s' "$s"
}

# Echo (newest first) the commit SHAs that touched images.lock on the configured
# GitHub repo, via the commits API. Needs python3 or node to parse JSON (same
# soft dep as json_escape). Empty on any failure.
github_lock_commit_shas() {
    local owner_repo json
    owner_repo=$(github_owner_repo) || return 1
    json=$(curl -fsSL -H "Accept: application/vnd.github+json" \
        "https://api.github.com/repos/${owner_repo}/commits?path=images.lock&per_page=100" </dev/null 2>/dev/null) \
        || return 1
    printf '%s' "$json" | python3 -c '
import json,sys
for c in json.load(sys.stdin): print(c["sha"])
' 2>/dev/null && return 0
    printf '%s' "$json" | node -e '
let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{for(const c of JSON.parse(s))console.log(c.sha);});
' 2>/dev/null
}

# Fetch the images.lock whose "# Release:" header matches the pinned version into
# a temp file and echo its path. The working-tree lock tracks the current release,
# so its first-party digests won't match an older pinned NANO_VERSION. We walk
# the commits that touched images.lock (newest first) and return the first whose
# header matches — this works whether the repo keeps a commit per release (the
# dev repo) or snapshot-sync commits (the public mirror), since both carry the
# "# Release:" header in the file itself. Empty on failure.
fetch_release_lock() {
    local want="${1#v}" want_re owner_repo sha tmp tried=0
    owner_repo=$(github_owner_repo) || return 1
    want_re="${want//./\\.}"   # dots are literal, not regex wildcards
    while read -r sha; do
        [[ -z "$sha" ]] && continue
        tried=$((tried + 1)); [[ "$tried" -gt 40 ]] && break
        tmp=$(mktemp) || return 1
        if curl -fsSL "https://raw.githubusercontent.com/${owner_repo}/${sha}/images.lock" -o "$tmp" </dev/null 2>/dev/null \
           && grep -qE "^# Release: v?${want_re}([^0-9]|\$)" "$tmp"; then
            printf '%s' "$tmp"; return 0
        fi
        rm -f "$tmp"
    done < <(github_lock_commit_shas)
    return 1
}

# Echo the manifest digest recorded in RepoDigests for the local image $1,
# picking the entry for repo $2 — a bare sha256:… or empty. Purely local: no
# network, no tag re-resolution.
repo_digest_of() {
    local line
    line=$(docker image inspect "$1" \
        --format '{{range .RepoDigests}}{{println .}}{{end}}' </dev/null 2>/dev/null \
        | grep -F "${2}@" | head -1)
    printf '%s' "${line##*@}"
}

# Compare one lock line's expected digest against the pulled image. $1=image
# reference (tag included for third-party, bare repo for first-party), $2=repo
# without tag (for matching RepoDigests), $3=expected sha256. Echoes "ok",
# "mismatch", or "missing".
verify_one_digest() {
    local inspect_ref="$1" repo_notag="$2" expected="$3" actual
    # RepoDigests records the manifest digest the reference resolved to on pull —
    # the same value recorded in images.lock. Pick this repo's entry.
    actual=$(repo_digest_of "$inspect_ref" "$repo_notag")
    # Compose v5 (Docker 29+, what `curl get.docker.com | sh` installs today)
    # pulls third-party images as repo:tag@sha256 and creates no local repo:tag,
    # so the inspect above finds nothing even though the image is present
    # (NAN-1328). It IS present under its pinned digest, so probe by
    # repo@<expected>: that resolves iff the deployed digest equals the lock —
    # exactly the check we want — without re-resolving the floating tag, so an
    # upstream tag that later drifts past the pin can't cause a false mismatch.
    if [[ -z "$actual" ]]; then
        actual=$(repo_digest_of "${repo_notag}@${expected}" "$repo_notag")
    fi
    if [[ -z "$actual" ]]; then echo "missing"; return; fi
    if [[ "$actual" == "$expected" ]]; then echo "ok"; else
        # To stderr — stdout is captured by the caller as the result token.
        warn "DIGEST MISMATCH for $repo_notag" >&2
        warn "  expected (images.lock): $expected" >&2
        warn "  actual   (pulled):      $actual" >&2
        echo "mismatch"
    fi
}

# The "# Release: vX.Y.Z" header of a lock file, without the leading v.
lock_release() {
    local r
    r=$(sed -n 's/^# Release: v\{0,1\}//p' "$1" 2>/dev/null | head -1)
    printf '%s' "${r%% *}"
}

verify_image_digests() {
    local lockfile="$IMAGES_LOCK"

    image_is_active() {
        local ref="$1" active
        while IFS= read -r active; do
            [[ "$active" == "$ref" || "$active" == "$ref@sha256:"* ]] && return 0
        done <<< "${ACTIVE_IMAGES:-}"
        return 1
    }

    # Escape hatch (NAN-1328): let an operator opt out of the supply-chain check
    # if they hit an environment the digest readback can't handle. Off by default
    # — verification stays on for everyone who doesn't deliberately disable it.
    if [[ "${NANO_SKIP_IMAGE_VERIFY:-0}" == "1" ]]; then
        warn "NANO_SKIP_IMAGE_VERIFY=1 — skipping image digest verification (supply-chain check disabled)."
        return 0
    fi

    if [[ ! -f "$lockfile" ]]; then
        warn "$lockfile not found — skipping image digest verification."
        return 0
    fi

    # Third-party base images are version-independent and always verified against
    # the local lock. First-party digests are release-specific. The local lock
    # already describes this release (the default: NANO_VERSION is read from it),
    # so only an explicitly pinned OTHER release needs its own lock fetched, which
    # keeps a pinned operator verified instead of skipped. Fetching walks the
    # public repo's history, so it exists for open core only.
    local fp_lockfile="$lockfile" fetched=""
    if [[ "$(lock_release "$lockfile")" != "${NANO_VERSION#v}" ]]; then
        if [[ "$NANO_EDITION" == "open" ]] && fetched=$(fetch_release_lock "$NANO_VERSION") && [[ -n "$fetched" ]]; then
            fp_lockfile="$fetched"
            ok "Fetched images.lock for pinned release v${NANO_VERSION#v}"
        else
            fp_lockfile=""
            warn "Could not fetch images.lock for pinned NANO_VERSION='$NANO_VERSION' — first-party digests not verified (base images still are)."
        fi
    fi

    log "Verifying pulled image digests against images.lock"
    local ref expected basename repo_notag inspect_ref result
    local mismatch=0 verified_fp=0 verified_tp=0

    # First-party lines (no tag): inspect repo:NANO_VERSION, from fp_lockfile.
    if [[ -n "$fp_lockfile" ]]; then
        while read -r ref expected; do
            [[ -z "$ref" || "$ref" == \#* ]] && continue
            basename="${ref##*/}"; [[ "$basename" == *:* ]] && continue
            inspect_ref="${ref}:${NANO_VERSION}"; repo_notag="$ref"
            # Only a Compose-selected image can affect this host. Inspecting a
            # cached same-tag image from an inactive role turns harmless stale
            # cache state into a false supply-chain failure.
            image_is_active "$inspect_ref" || continue
            result=$(verify_one_digest "$inspect_ref" "$repo_notag" "$expected")
            case "$result" in
                ok) verified_fp=$((verified_fp + 1)) ;;
                missing)
                    fail "No registry digest found for ${inspect_ref} — cannot verify an active role image against $lockfile. Refusing to start with unverifiable images." ;;
                *) mismatch=1 ;;
            esac
        done < "$fp_lockfile"
    fi

    # Third-party lines (tagged): self-contained, always from the local lock.
    while read -r ref expected; do
        [[ -z "$ref" || "$ref" == \#* ]] && continue
        basename="${ref##*/}"; [[ "$basename" == *:* ]] || continue
        inspect_ref="$ref"; repo_notag="${ref%:*}"
        image_is_active "$inspect_ref" || continue
        result=$(verify_one_digest "$inspect_ref" "$repo_notag" "$expected")
        case "$result" in
            ok) verified_tp=$((verified_tp + 1)) ;;
            missing)
                fail "No registry digest found for ${inspect_ref} — cannot verify an active role image against $lockfile. Refusing to start with unverifiable images." ;;
            *) mismatch=1 ;;
        esac
    done < "$lockfile"

    [[ -n "$fetched" ]] && rm -f "$fetched"

    if [[ "$mismatch" == "1" ]]; then
        fail "Image digest verification failed: pulled images do not match images.lock. Refusing to start. If you deliberately changed image versions this is expected — otherwise it may indicate a tampered or re-pushed tag."
    fi
    ok "Verified $verified_fp first-party + $verified_tp third-party image digest(s) against images.lock"
}

# ----------------------------------------------------------------------------
# 1. Prereq check
# ----------------------------------------------------------------------------
log "Checking prerequisites"

require_cmd docker   "Install Docker: https://docs.docker.com/get-docker/"
require_cmd git      "Install git (most package managers)."
require_cmd openssl  "Install openssl (most distros ship it by default)."
require_cmd curl     "Install curl."

if ! docker compose version </dev/null >/dev/null 2>&1; then
    fail "docker compose v2 is required. Update Docker or install the compose plugin."
fi

if [[ -n "$INVENTORY_ARG" ]]; then
    require_cmd python3 "Install Python 3 (used only to validate and render the sovereign host inventory)."
    compose_version=$(docker compose version --short </dev/null 2>/dev/null | sed 's/^v//' | cut -d- -f1)
    IFS=. read -r compose_major compose_minor compose_patch <<< "$compose_version"
    compose_major=${compose_major:-0}; compose_minor=${compose_minor:-0}; compose_patch=${compose_patch:-0}
    if (( compose_major < 2 || (compose_major == 2 && compose_minor < 24) || (compose_major == 2 && compose_minor == 24 && compose_patch < 4) )); then
        fail "Role-split installs require Docker Compose 2.24.4+ (found $compose_version)."
    fi
    [[ -f "$INVENTORY_ARG" ]] || fail "Inventory not found: $INVENTORY_ARG"
    INVENTORY_PATH="$(cd "$(dirname "$INVENTORY_ARG")" && pwd -P)/$(basename "$INVENTORY_ARG")"
fi

if [[ "${NANO_PREPARE_ONLY:-0}" != "1" && "${NANO_CHECK_ONLY:-0}" != "1" ]] \
    && ! docker info </dev/null >/dev/null 2>&1; then
    fail "Docker daemon is not running or this user can't talk to it. Start Docker and retry."
fi

# NAN-4906 / NAN-4999: ClickHouse 26.6+ and ClickHouse Keeper need AVX2 on
# x86-64 and die with an illegal instruction without it. Role-split app,
# ingest, and PostgreSQL hosts do not run either binary and must not inherit
# that hardware gate. Single-node installs still run ClickHouse locally.
AVX2_REQUIRED_BY=""
if [[ -z "$INVENTORY_ARG" ]]; then
    AVX2_REQUIRED_BY="ClickHouse server (single-node role)"
else
    [[ ",${ROLE_ARG}," == *,clickhouse,* ]] && AVX2_REQUIRED_BY="ClickHouse role"
    if [[ ",${ROLE_ARG}," == *,keeper,* ]]; then
        [[ -n "$AVX2_REQUIRED_BY" ]] && AVX2_REQUIRED_BY+=", "
        AVX2_REQUIRED_BY+="Keeper role"
    fi
fi
CPUINFO_PATH=/proc/cpuinfo
if [[ -n "${NANO_INSTALLER_TEST_CPUINFO_PATH:-}" ]]; then
    [[ "${NANO_INSTALLER_TEST_MODE:-0}" == "1" ]] \
        || fail "NANO_INSTALLER_TEST_CPUINFO_PATH is reserved for installer tests."
    CPUINFO_PATH="$NANO_INSTALLER_TEST_CPUINFO_PATH"
fi
# No /proc/cpuinfo on macOS: Docker runs inside a VM. The fail-closed
# clickhouse-preflight service runs in both ClickHouse and Keeper profiles,
# checks the Docker VM's /proc/cpuinfo, and each stateful role depends on it.
if [[ -n "$AVX2_REQUIRED_BY" && "$(uname -m)" == "x86_64" && -r "$CPUINFO_PATH" ]] \
    && ! grep -qw avx2 "$CPUINFO_PATH"; then
    fail "$AVX2_REQUIRED_BY requires AVX2 on x86-64 because it runs ClickHouse 26.6+ binaries. Use an AVX2-capable host (on Proxmox, set the VM CPU type to 'host' or x86-64-v3)."
fi

ok "All prerequisites present"

# v2 runs on ClickHouse. A 1.x install ran the OCSF object lake (gen1 `lake`
# profile or the lean `lean` profile), whose data and services this release
# does not have: an in-place upgrade would start an empty ClickHouse stack over
# it. Refuse BEFORE the checkout is touched, so the lake install stays intact.
if [[ -e "$NANO_INSTALL_DIR/.env" || -L "$NANO_INSTALL_DIR/.env" ]]; then
    validate_env_file "$NANO_INSTALL_DIR/.env"
    if tr -d '\r"'"'"'' < "$NANO_INSTALL_DIR/.env" \
        | grep -qE '^(COMPOSE_PROFILES=(.*,)?(lake|lean)(,|$)|NANO_LOG_QUERY_BACKEND=lake|NANO_ENABLE_LAKE_CONTROL_PLANE=(1|true)|NANO_LAKE_[A-Z_]+=)'; then
        fail "The install at $NANO_INSTALL_DIR runs the 1.x object-lake edition, which cannot be upgraded in place to this release. Install into a new directory (NANO_INSTALL_DIR=\$HOME/nano-v2) and move sources there."
    fi
fi

# ----------------------------------------------------------------------------
# 2. Clone or update the repo
# ----------------------------------------------------------------------------
if [[ -e "$NANO_INSTALL_DIR/.git" ]]; then
    if [[ "${NANO_SKIP_GIT_UPDATE:-0}" == "1" ]]; then
        log "NANO_SKIP_GIT_UPDATE=1 — installing the checkout at $NANO_INSTALL_DIR as is"
    else
        # Older checkouts predate the shipped ignore rule for the helper's stable
        # flock identity. Ignore only that generated, untracked root path; any
        # tracked change or other untracked customer file still blocks the reset.
        GIT_DIRTY_STATUS=$(git -C "$NANO_INSTALL_DIR" status --porcelain </dev/null 2>/dev/null \
            | awk '$0 != "?? .env.nano-generated-secrets.lock"')
        if [[ -n "$GIT_DIRTY_STATUS" ]]; then
            warn "$NANO_INSTALL_DIR has local changes — skipping git update so your edits stay intact."
        else
            log "Updating existing checkout at $NANO_INSTALL_DIR"
            git -C "$NANO_INSTALL_DIR" fetch --depth 1 origin "$NANO_BRANCH" </dev/null
            # The nano-rs/nano mirror is force-regenerated on every sync, so its
            # history diverges from any prior checkout and can never fast-forward.
            # Hard-reset to the fetched remote HEAD instead. Safe: the clean-tree
            # check above already skips this branch (preserving edits) when there
            # are local changes, so this only resets an unmodified checkout — the
            # authoritative state is always the mirror. (NAN-1929: an ff-only merge
            # left a stale images.lock and then failed digest verification against
            # the freshly-pulled images.)
            git -C "$NANO_INSTALL_DIR" reset --hard FETCH_HEAD </dev/null \
                || fail "Could not update $NANO_INSTALL_DIR to the current release. Remove it and re-run to reclone."
        fi
    fi
elif [[ -f "$NANO_INSTALL_DIR/.nano-bundle" ]]; then
    log "Using extracted release bundle at $NANO_INSTALL_DIR ($(head -1 "$NANO_INSTALL_DIR/.nano-bundle"))"
elif [[ -e "$NANO_INSTALL_DIR" ]]; then
    fail "$NANO_INSTALL_DIR exists but is not a git checkout. Move/remove it or set NANO_INSTALL_DIR to a different path."
else
    log "Cloning $NANO_REPO_URL → $NANO_INSTALL_DIR"
    git clone --depth 1 --branch "$NANO_BRANCH" "$NANO_REPO_URL" "$NANO_INSTALL_DIR" </dev/null
fi
ok "Sources ready at $NANO_INSTALL_DIR"
if [[ -f "$NANO_INSTALL_DIR/.nano-test-upgrade-root" ]]; then
    warn "NON-RELEASE TEST BUILD: this compose bundle trusts one embedded lab upgrade signing root. Never use it for production."
fi

cd "$NANO_INSTALL_DIR"

if [[ -e .env || -L .env ]]; then
    validate_env_file "$NANO_INSTALL_DIR/.env"
fi

# NAN-5126: a rerun never narrows this host's installed roles. Every run
# republishes the whole `.nano-generated` tree, but compose recreates only the
# services of the profiles it is given. A service left out (ClickHouse on a
# `--role ingest` rerun) keeps its directory bind mounts on the retired inode,
# hot-reloads an empty config.d and falls back to loopback-only listeners while
# the installer reports success. So the effective role set is the requested
# roles plus every role this host already runs (the last run's recorded
# profiles, and roles whose containers are running now), and all of them are
# recreated onto the new tree. NANO_ROLE_NARROW=1 deliberately removes roles.
if [[ -n "$ROLE_ARG" && "${NANO_ROLE_NARROW:-0}" != "1" ]]; then
    installed_roles=""
    installed_project=""
    installed_host=""
    if [[ -f .nano-role.env ]]; then
        IFS=$'\t' read -r installed_roles installed_project installed_host < <(
            python3 -I - .nano-role.env <<'PY_ROLES' || true
import json
import sys

values = {}
with open(sys.argv[1], encoding="utf-8") as role_env:
    for line in role_env:
        key, _, encoded = line.rstrip("\n").partition("=")
        try:
            values[key] = json.loads(encoded)
        except ValueError:
            continue
roles = values.get("NANO_ROLE_PROFILES") or values.get("COMPOSE_PROFILES") or ""
project = values.get("COMPOSE_PROJECT_NAME") or ""
host = values.get("NANO_HOST_NAME") or ""
print(*(v if isinstance(v, str) else "" for v in (roles, project, host)), sep="\t")
PY_ROLES
        )
    fi
    # Only this host's own record counts: a bundle copied from another host
    # carries that host's role env.
    current_host_name="${NANO_HOST_NAME:-$(hostname -s 2>/dev/null || hostname)}"
    if [[ -z "$installed_host" || "$installed_host" != "$current_host_name" ]]; then
        installed_roles=""
        installed_project=""
    fi
    running_roles=""
    if [[ -n "$installed_project" ]] && command -v docker >/dev/null 2>&1; then
        while IFS= read -r running_service; do
            case "$running_service" in
                postgres) running_roles+=",postgres" ;;
                clickhouse) running_roles+=",clickhouse" ;;
                keeper) running_roles+=",keeper" ;;
                vector|vector-config-consumer|vector-tap|ingest-edge) running_roles+=",ingest" ;;
                nano-api|nano-jobs|nano-search|nano-web|nginx|app-internal-edge) running_roles+=",app" ;;
            esac
        done < <(docker ps --filter "label=com.docker.compose.project=$installed_project" \
            --format '{{.Label "com.docker.compose.service"}}' </dev/null 2>/dev/null || true)
    fi
    effective_roles=""
    for canonical_role in app ingest clickhouse keeper postgres; do
        if [[ ",${ROLE_ARG},${installed_roles},${running_roles}," == *,"$canonical_role",* ]]; then
            effective_roles+="${effective_roles:+,}$canonical_role"
        fi
    done
    requested_sorted=$(printf '%s' "$ROLE_ARG" | tr ',' '\n' | sort -u | paste -sd, -)
    effective_sorted=$(printf '%s' "$effective_roles" | tr ',' '\n' | sort -u | paste -sd, -)
    if [[ -n "$effective_roles" && "$effective_sorted" != "$requested_sorted" ]]; then
        warn "Requested role(s) '$ROLE_ARG', but this host already runs '${effective_sorted}'. A rerun never narrows a host's roles (NAN-5126): installing and recreating '$effective_roles' so every service attaches the newly published configuration. To remove a role deliberately, rerun with NANO_ROLE_NARROW=1."
        ROLE_ARG="$effective_roles"
    fi
fi

if [[ ! -f "$COMPOSE_FILE" ]]; then
    fail "$COMPOSE_FILE not found in $NANO_INSTALL_DIR. Branch '$NANO_BRANCH' may not include the OSS quickstart yet."
fi

[[ -r scripts/lib/generated-secrets.sh ]] \
    || fail "scripts/lib/generated-secrets.sh not found in $NANO_INSTALL_DIR. The source tree or release bundle is incomplete."
# shellcheck source=scripts/lib/generated-secrets.sh
. scripts/lib/generated-secrets.sh
[[ -r scripts/lib/async-loader-readiness.sh ]] \
    || fail "scripts/lib/async-loader-readiness.sh not found in $NANO_INSTALL_DIR. The source tree or release bundle is incomplete."
# shellcheck source=scripts/lib/async-loader-readiness.sh
. scripts/lib/async-loader-readiness.sh
[[ -r scripts/lib/image-pull.sh ]] \
    || fail "scripts/lib/image-pull.sh not found in $NANO_INSTALL_DIR. The source tree or release bundle is incomplete."
# shellcheck source=scripts/lib/image-pull.sh
. scripts/lib/image-pull.sh

nano_async_loader_query() {
    local admin_password curl_password endpoint query resolve_address url_address
    local targets target address port response failed not_ok total
    local failed_sum=0 not_ok_sum=0 total_sum=0
    local -a curl_args target_list
    admin_password=$(env_value CLICKHOUSE_ADMIN_PASSWORD)
    [[ -n "$admin_password" ]] || return 1
    # curl config arrives on stdin, keeping the credential out of argv and logs.
    curl_password=${admin_password//\\/\\\\}
    curl_password=${curl_password//\"/\\\"}
    query="SELECT countIf(status = 'FAILED'), countIf(status != 'OK'), count() FROM system.asynchronous_loader FORMAT TabSeparatedRaw"
    targets=${NANO_CLICKHOUSE_HTTP_TARGETS:-${NANO_CLICKHOUSE_REMOTE_ADDRESS}@${NANO_CLICKHOUSE_HTTP_PORT}}
    IFS=',' read -r -a target_list <<< "$targets"
    ((${#target_list[@]} > 0)) || return 1

    # Probe each shard directly as the admin user. clusterAllReplicas would use
    # the runtime credentials embedded in remote_servers for its remote hops,
    # which would force REMOTE and system-table grants back onto that user.
    for target in "${target_list[@]}"; do
        address=${target%@*}
        port=${target##*@}
        [[ -n "$address" && "$target" == *@* && "$port" =~ ^[0-9]+$ ]] || return 1
        curl_args=(-fsS --max-time 15 --data-binary "$query")
        if [[ "${NANO_PRIVATE_TLS:-false}" == "true" ]]; then
            endpoint="https://${NANO_TLS_SERVER_NAME}:${port}/"
            resolve_address="$address"
            [[ "$resolve_address" == *:* && "$resolve_address" != \[*\] ]] \
                && resolve_address="[$resolve_address]"
            curl_args+=(--cacert "$NANO_TLS_CA" --resolve "${NANO_TLS_SERVER_NAME}:${port}:${resolve_address}")
        else
            url_address="$address"
            [[ "$url_address" == *:* && "$url_address" != \[*\] ]] \
                && url_address="[$url_address]"
            endpoint="http://${url_address}:${port}/"
        fi
        response=$(printf 'user = "nanosiem_admin:%s"\n' "$curl_password" \
            | curl --config - "${curl_args[@]}" "$endpoint") || return 1
        [[ "$response" =~ ^([0-9]+)[[:space:]]+([0-9]+)[[:space:]]+([0-9]+)$ ]] || return 1
        failed=${BASH_REMATCH[1]}
        not_ok=${BASH_REMATCH[2]}
        total=${BASH_REMATCH[3]}
        failed_sum=$((failed_sum + failed))
        not_ok_sum=$((not_ok_sum + not_ok))
        total_sum=$((total_sum + total))
    done
    printf '%s\t%s\t%s\n' "$failed_sum" "$not_ok_sum" "$total_sum"
}

[[ -r scripts/lib/resource-sizing.sh ]] \
    || fail "scripts/lib/resource-sizing.sh not found in $NANO_INSTALL_DIR. The source tree or release bundle is incomplete."
RESOURCE_SIZING="$PWD/scripts/lib/resource-sizing.sh"

# Replace only the installer-owned sizing block. It stays first in .env, so an
# operator assignment later in the file wins exactly as Docker Compose's
# last-assignment semantics promise. Existing pre-NAN-4997 keys are outside the
# block and are therefore treated as explicit overrides. Resolve a symlinked
# .env to preserve the link itself.
write_auto_sizing_block() {
    local env_path="$1" sizing_path="$2"
    local begin_marker='# BEGIN NANO AUTO SIZING (installer managed; explicit keys below override)'
    local end_marker='# END NANO AUTO SIZING'
    nano_replace_managed_env_block "$env_path" "$sizing_path" "$begin_marker" "$end_marker" \
        || fail "Could not safely replace the nano auto-sizing block in $env_path."
}

# Snapshot only sizing keys from an existing .env. This deliberately takes its
# key allowlist from the sizer output so credentials can never enter a diff or
# an installer log. Docker Compose uses the last assignment, so do the same.
snapshot_effective_sizing_env() {
    local source_env="$1" sizing_keys="$2" output="$3"
    awk -F= '
        NR == FNR {
            if ($0 ~ /^[A-Z][A-Z0-9_]*=/) {
                key = $1
                wanted[key] = 1
                order[++count] = key
            }
            next
        }
        $0 ~ /^[A-Z][A-Z0-9_]*=/ && ($1 in wanted) {
            key = $1
            sub(/^[^=]*=/, "")
            value[key] = $0
        }
        END {
            for (i = 1; i <= count; i++) {
                key = order[i]
                if ((key in ENVIRON) && ENVIRON[key] != "")
                    print key "=" ENVIRON[key]
                else if (key in value)
                    print key "=" value[key]
            }
        }
    ' "$sizing_keys" "$source_env" > "$output"
}

sizing_numeric_value() {
    local key="$1" value="$2"
    value="${value%\"}" value="${value#\"}"
    value="${value%\'}" value="${value#\'}"
    awk -v key="$key" -v value="$value" '
        BEGIN {
            if (key ~ /CPU/) {
                if (value ~ /^[0-9]+([.][0-9]+)?m$/) {
                    sub(/m$/, "", value)
                    print value / 1000
                } else if (value ~ /^[0-9]+([.][0-9]+)?$/) {
                    print value + 0
                }
                exit
            }
            if (value ~ /^[0-9]+([.][0-9]+)?([KMGT]i?B?|[kmgt]i?b?)$/) {
                unit = value
                sub(/^[0-9]+([.][0-9]+)?/, "", unit)
                number = value
                sub(/[^0-9.].*$/, "", number)
                unit = toupper(unit)
                if (unit ~ /^K/) number /= 1024
                else if (unit ~ /^G/) number *= 1024
                else if (unit ~ /^T/) number *= 1048576
                print number + 0
                exit
            }
            if (value ~ /^[0-9]+([.][0-9]+)?$/)
                print value + 0
        }
    '
}

report_sizing_changes() {
    local old_env="$1" new_env="$2" old_server="$3" new_server="$4" old_users="$5" new_users="$6"
    local key old_value new_value old_number new_number xml_kind old_xml new_xml line reductions=""

    while IFS=$'\t' read -r key old_value new_value; do
        [[ -n "$key" ]] || continue
        log "Sizing change: env $key: $old_value -> $new_value"
        old_number=$(sizing_numeric_value "$key" "$old_value")
        new_number=$(sizing_numeric_value "$key" "$new_value")
        if [[ -n "$old_number" && -n "$new_number" ]] \
            && awk -v old="$old_number" -v new="$new_number" 'BEGIN { exit !(new < old) }'; then
            reductions="${reductions}${reductions:+, }$key ($old_value -> $new_value)"
        fi
    done < <(
        awk -F= '
            NR == FNR {
                if ($0 ~ /^[A-Z][A-Z0-9_]*=/) {
                    key = $1
                    sub(/^[^=]*=/, "")
                    old[key] = $0
                }
                next
            }
            $0 ~ /^[A-Z][A-Z0-9_]*=/ {
                key = $1
                sub(/^[^=]*=/, "")
                new = $0
                before = (key in old) ? old[key] : "<unset>"
                if (before != new)
                    print key "\t" before "\t" new
            }
        ' "$old_env" "$new_env"
    )

    for xml_kind in server users; do
        if [[ "$xml_kind" == server ]]; then
            old_xml="$old_server" new_xml="$new_server"
        else
            old_xml="$old_users" new_xml="$new_users"
        fi
        [[ -s "$old_xml" && -s "$new_xml" ]] || continue
        while IFS= read -r line; do
            case "$line" in
                ---*|+++*|@@*) continue ;;
                -*|+*) log "Sizing change: ClickHouse $xml_kind XML: $line" ;;
            esac
        done < <(diff -U0 "$old_xml" "$new_xml" || true)
    done

    if [[ -n "$reductions" ]]; then
        warn "RESOURCE LIMIT REDUCTION ON RERUN — review before services restart: $reductions"
    fi
}

# ----------------------------------------------------------------------------
# Edition, release and image source (fail closed; nothing written yet)
# ----------------------------------------------------------------------------
# One value from .env (KEY=value), quotes and CR stripped; empty when absent.
env_value() {
    [[ -f .env ]] || return 0
    awk -v k="$1" '
        index($0, k "=") == 1 {
            sub(/^[^=]*=/, "")
            gsub(/[\r"'"'"']/, "")
            value = $0
        }
        END { print value }
    ' .env
}

RECORDED_EDITION=$(env_value NANO_EDITION)
RECORDED_PREFIX=$(env_value NANO_IMAGE_PREFIX)
if [[ -f .env && -z "$RECORDED_EDITION" ]]; then
    # A .env without NANO_EDITION was written before editions existed, when
    # only open core had a compose installer, unless it already carries an
    # image prefix (written by this installer), which makes it ambiguous.
    if [[ -n "$RECORDED_PREFIX" ]]; then
        fail ".env records NANO_IMAGE_PREFIX=$RECORDED_PREFIX but no NANO_EDITION. Add NANO_EDITION=open or NANO_EDITION=enterprise to $NANO_INSTALL_DIR/.env to match what this install runs, then re-run."
    fi
    RECORDED_EDITION=open
fi
MARKER_EDITION=""
[[ -f .nano-edition ]] && MARKER_EDITION=$(tr -d '[:space:]' < .nano-edition)

NANO_EDITION="" EDITION_FROM=""
for src in "the source tree (.nano-edition)=$MARKER_EDITION" "this install's .env=$RECORDED_EDITION" "the NANO_EDITION environment variable=$ENV_EDITION"; do
    value="${src##*=}" origin="${src%=*}"
    [[ -z "$value" ]] && continue
    [[ "$value" == open || "$value" == enterprise ]] || fail "Invalid edition '$value' from $origin (expected open or enterprise)."
    if [[ -z "$NANO_EDITION" ]]; then
        NANO_EDITION="$value" EDITION_FROM="$origin"
    elif [[ "$value" != "$NANO_EDITION" ]]; then
        fail "Edition mismatch: $EDITION_FROM says $NANO_EDITION but $origin says $value. An install never switches edition; use the bundle for this install's edition, or a new NANO_INSTALL_DIR."
    fi
done
[[ -n "$NANO_EDITION" ]] || fail "Cannot determine the edition: $NANO_INSTALL_DIR has no .nano-edition marker and no recorded install. Set NANO_EDITION=open or NANO_EDITION=enterprise."

case "$NANO_EDITION" in
    open) IMAGES_LOCK="images.lock" ;;
    enterprise) IMAGES_LOCK="${NANO_IMAGES_LOCK:-images.enterprise.lock}" ;;
esac
[[ -f "$IMAGES_LOCK" ]] || fail "$IMAGES_LOCK not found in $NANO_INSTALL_DIR. Edition $NANO_EDITION needs it (the enterprise lock ships only in the enterprise compose bundle)."

MULTI_NODE=0
if [[ -n "$INVENTORY_ARG" ]]; then
    [[ "$NANO_EDITION" == "enterprise" ]] \
        || fail "--role/--inventory is available only in the enterprise compose bundle; open core keeps the shared single-node edge."
    COMPOSE_FILE="deploy/compose/docker-compose.enterprise.yml"
    [[ -f "$COMPOSE_FILE" ]] \
        || fail "$COMPOSE_FILE not found. Use the enterprise compose bundle for a role-split install."
    [[ -x deploy/compose/render-inventory.py || -f deploy/compose/render-inventory.py ]] \
        || fail "deploy/compose/render-inventory.py not found in the enterprise compose bundle."
    MULTI_NODE=1
fi

if [[ -z "$NANO_VERSION" ]]; then
    NANO_VERSION=$(lock_release "$IMAGES_LOCK")
    [[ -n "$NANO_VERSION" ]] || fail "$IMAGES_LOCK has no '# Release:' header. Set NANO_VERSION explicitly."
    is_line_release "$NANO_VERSION" \
        || fail "$IMAGES_LOCK is for release $NANO_VERSION, which is not a v${RELEASE_FLOOR_MAJOR}+ release. This source tree has not been released yet; use a released bundle or checkout."
fi

NANO_IMAGE_PREFIX=$(awk '$1 ~ /-api$/ && $2 ~ /^sha256:/ {sub(/-api$/, "", $1); print $1; exit}' "$IMAGES_LOCK")
[[ -n "$NANO_IMAGE_PREFIX" ]] || fail "$IMAGES_LOCK records no <prefix>-api image."
OPEN_IMAGE_PREFIX="ghcr.io/nano-rs/nano"
if [[ "$NANO_EDITION" == open && "$NANO_IMAGE_PREFIX" != "$OPEN_IMAGE_PREFIX" ]] \
    || [[ "$NANO_EDITION" == enterprise && "$NANO_IMAGE_PREFIX" == "$OPEN_IMAGE_PREFIX" ]]; then
    fail "$IMAGES_LOCK lists $NANO_IMAGE_PREFIX-* images, which are not the $NANO_EDITION edition's."
fi
if [[ -n "$RECORDED_PREFIX" && "$RECORDED_PREFIX" != "$NANO_IMAGE_PREFIX" ]]; then
    fail "This install runs $RECORDED_PREFIX-* images but $IMAGES_LOCK lists $NANO_IMAGE_PREFIX-*. Refusing to switch image source on a re-run."
fi
ok "Edition $NANO_EDITION (from $EDITION_FROM), release $NANO_VERSION ($NANO_IMAGE_PREFIX-*)"

if [[ -n "${NANO_ALLOW_PRIVATE_AI_ENDPOINTS:-}" && -z "$(normalize_bool "$NANO_ALLOW_PRIVATE_AI_ENDPOINTS")" ]]; then
    fail "NANO_ALLOW_PRIVATE_AI_ENDPOINTS must be true or false (got '$NANO_ALLOW_PRIVATE_AI_ENDPOINTS')."
fi

if [[ -n "${NANO_HTTPS_PROXY:-}" ]] && ! valid_proxy_url "$NANO_HTTPS_PROXY"; then
    fail "NANO_HTTPS_PROXY must look like http://host:port or https://host:port (got '$(redact_proxy_url "$NANO_HTTPS_PROXY")')."
fi
if [[ -n "${NANO_NO_PROXY:-}" ]] && ! valid_no_proxy "$NANO_NO_PROXY"; then
    fail "NANO_NO_PROXY must be comma-separated host names, domains, IPs or CIDRs without spaces."
fi
if [[ -n "${NANO_NO_PROXY:-}" && -z "${NANO_HTTPS_PROXY:-}" ]]; then
    fail "NANO_NO_PROXY needs NANO_HTTPS_PROXY."
fi
if [[ -n "${NANO_PROXY_USERNAME:-}${NANO_PROXY_PASSWORD:-}" ]]; then
    [[ -n "${NANO_HTTPS_PROXY:-}" ]] || fail "NANO_PROXY_USERNAME/NANO_PROXY_PASSWORD need NANO_HTTPS_PROXY."
    [[ -n "${NANO_PROXY_USERNAME:-}" && -n "${NANO_PROXY_PASSWORD:-}" ]] \
        || fail "Set both NANO_PROXY_USERNAME and NANO_PROXY_PASSWORD, or neither."
    valid_proxy_hostport "$NANO_HTTPS_PROXY" \
        || fail "With NANO_PROXY_USERNAME/NANO_PROXY_PASSWORD, NANO_HTTPS_PROXY must not carry credentials (got '$(redact_proxy_url "$NANO_HTTPS_PROXY")')."
fi

validate_license_inputs

if [[ "${NANO_CHECK_ONLY:-0}" == "1" ]]; then
    printf 'edition=%s\nversion=%s\nimage_prefix=%s\nlock=%s\n' "$NANO_EDITION" "$NANO_VERSION" "$NANO_IMAGE_PREFIX" "$IMAGES_LOCK"
    exit 0
fi

# ----------------------------------------------------------------------------
# 3. Collect admin info (env first, then interactive)
# ----------------------------------------------------------------------------
ADMIN_EMAIL="${NANO_ADMIN_EMAIL:-}"
ADMIN_NAME="${NANO_ADMIN_NAME:-}"
ADMIN_PASSWORD="${NANO_ADMIN_PASSWORD:-}"
BASE_URL="${NANO_BASE_URL:-http://localhost}"
# NAN-5172: a reused .env (prepared earlier, or a retry after a failed start)
# remembers the admin email/name and base URL from the first run, so the
# second run no longer needs them exported again.
if [[ -f .env ]]; then
    [[ -n "$ADMIN_EMAIL" ]] || ADMIN_EMAIL=$(env_value NANO_ADMIN_EMAIL)
    [[ -n "$ADMIN_NAME" ]] || ADMIN_NAME=$(env_value NANO_ADMIN_NAME)
    if [[ -z "${NANO_BASE_URL:-}" && -n "$(env_value BASE_URL)" ]]; then
        BASE_URL=$(env_value BASE_URL)
    fi
fi

if [[ "$MULTI_NODE" == "1" && ! -f .env && ",${ROLE_ARG}," != *,app,* ]]; then
    fail "A role-split cluster's shared .env must be created on an app-role host first (use NANO_PREPARE_ONLY=1), then copied securely to this host before installing role(s) $ROLE_ARG."
fi

if [[ -f .env ]]; then
    warn ".env already exists — keeping existing secrets, will only (re)start the stack."
    REUSE_ENV=1
    # Role-split compose intentionally exposes only the five fixed roles. The
    # single-node-only Tenzir profile is not silently dropped or allowed to
    # replace the requested host profile set.
    BUNDLE_TENZIR=0
    grep -qE '^COMPOSE_PROFILES=.*tenzir' .env 2>/dev/null && BUNDLE_TENZIR=1
    if [[ "$MULTI_NODE" == "1" && "$BUNDLE_TENZIR" == "1" ]]; then
        fail "The bundled Tenzir profile is single-node only; role-split installs must use the ocsf or udm schema profile without bundled Tenzir."
    fi
    secret_mode=generate
    if [[ "$MULTI_NODE" == "1" && ",${ROLE_ARG}," != *,app,* ]]; then
        secret_mode=validate-only
    fi
    # NAN-5148: only an ingest host runs a Vector config consumer.
    NANO_SECRETS_HOST_CONSUMES_VECTOR_CONFIG=1
    if [[ "$MULTI_NODE" == "1" && ",${ROLE_ARG}," != *,ingest,* ]]; then
        NANO_SECRETS_HOST_CONSUMES_VECTOR_CONFIG=0
    fi
    NANO_SECRETS_HOST_CONSUMES_VECTOR_CONFIG="$NANO_SECRETS_HOST_CONSUMES_VECTOR_CONFIG" \
        nano_backfill_generated_secrets .env "$secret_mode" \
        || fail "Could not validate/backfill required generated secrets in $NANO_INSTALL_DIR/.env."
    if [[ -n "$NANO_BACKFILLED_SECRET_KEYS" ]]; then
        log "Backfilled required generated secrets in .env: $NANO_BACKFILLED_SECRET_KEYS"
    fi
    # Security review 2026-11-08: values nano once shipped as defaults or
    # examples are public. They are replaced here, before any service starts.
    if [[ ",${NANO_ROTATED_SECRET_KEYS// /}," == *,JWT_SECRET,* ]]; then
        warn "JWT_SECRET was a publicly known example value; replaced it with a generated one. Everyone signs in again; API keys keep working."
    fi
    if [[ ",${NANO_ROTATED_SECRET_KEYS// /}," == *,NANOSIEM_ENCRYPTION_KEY,* ]]; then
        warn "NANOSIEM_ENCRYPTION_KEY was a publicly known example key. Moved .env to a key ring: a new generated active key, with the old key kept decrypt-only (legacy-0) so every stored credential still opens."
        warn "nano re-encrypts stored credentials in the background. Check progress with: docker compose -f $COMPOSE_FILE exec nano-jobs nanosiem-jobs credential-keys status"
        warn "When it reports nothing pending, and no backup older than today still needs restoring, retire the old key: ... credential-keys retire legacy-0"
    fi
    if [[ ",${NANO_ROTATED_SECRET_KEYS// /}," == *,NANO_VECTOR_CONFIG_DELIVERY_TOKEN,* ]]; then
        warn "NANO_VECTOR_CONFIG_DELIVERY_TOKEN was a placeholder; replaced it with a generated one."
    fi
    # NAN-5013 (v2.0.6): nano refuses a publicly known install token on every
    # ingest lane, so it is replaced here. The services started below read the
    # new value: nano-api republishes Vector's tokens file and Vector's static
    # config picks it up when it is recreated. Named per-source tokens are
    # stored as hashes in PostgreSQL and keep working unchanged.
    if [[ ",${NANO_ROTATED_SECRET_KEYS// /}," == *,VECTOR_AUTH_TOKEN,* ]]; then
        warn "VECTOR_AUTH_TOKEN (the forwarder install token) was a publicly known default, which nano now refuses; replaced it with a generated one."
        warn "Senders using named ingest tokens keep working. Senders that still send the old public token get HTTP 401: issue each one a named token in $BASE_URL/ingestion/ingest-tokens."
        if [[ "$MULTI_NODE" == "1" ]]; then
            warn "Securely copy $NANO_INSTALL_DIR/.env to every inventory host before re-running install.sh there: their copy still holds the public token, which they now refuse."
        fi
    fi
    # NAN-5042: strict Vector config delivery (refuse the install token once
    # the dedicated token exists) is never inferred on an upgraded role-split
    # cluster. An ingest host whose .env predates the delivery token presents
    # the install token; refused, its consumer stops refreshing readiness and
    # the load balancer drops the host. Pin the compatible mode explicitly and
    # say how to finish. Fresh installs write true (below).
    if [[ "$MULTI_NODE" == "1" ]] && ! grep -qE '^[[:space:]]*NANO_VECTOR_CONFIG_DELIVERY_STRICT=' .env; then
        # Appended (symlink-safe; the last assignment wins).
        echo "NANO_VECTOR_CONFIG_DELIVERY_STRICT=false" >> .env
        warn "Pinned NANO_VECTOR_CONFIG_DELIVERY_STRICT=false in .env: this cluster predates strict Vector config delivery, so nano-api still accepts a private install token from an ingest host whose .env lacks NANO_VECTOR_CONFIG_DELIVERY_TOKEN (warned per host)."
        warn "To finish: copy the app host's .env to every inventory host and re-run install.sh there, then set NANO_VECTOR_CONFIG_DELIVERY_STRICT=true in the app host's .env and re-run install.sh on it. v2.1 enforces strict delivery regardless."
    fi
    # NAN-5148: on a role-split app host, a delivery token generated just now
    # exists only in this .env. Ingest hosts still present their old value or
    # the install token; nano-api refuses a placeholder and a public install
    # token (rotated just now, NAN-5013), and a private one too in strict
    # mode, so starting the API now would stop config delivery to them. Stop
    # before anything starts. The token is saved in .env, so the re-run after
    # the copy goes ahead.
    delivery_token_new=0
    if [[ ",${NANO_ROTATED_SECRET_KEYS// /}," == *,NANO_VECTOR_CONFIG_DELIVERY_TOKEN,* ]]; then
        delivery_token_new=1
    elif [[ ",${NANO_BACKFILLED_SECRET_KEYS// /}," == *,NANO_VECTOR_CONFIG_DELIVERY_TOKEN,* ]] \
        && { [[ ",${NANO_ROTATED_SECRET_KEYS// /}," == *,VECTOR_AUTH_TOKEN,* ]] \
            || [[ "$(env_value NANO_VECTOR_CONFIG_DELIVERY_STRICT)" == true ]]; }; then
        delivery_token_new=1
    fi
    if [[ "$MULTI_NODE" == "1" && "$secret_mode" == generate && "${NANO_PREPARE_ONLY:-0}" != "1" \
        && "$delivery_token_new" == 1 ]]; then
        fail "Generated NANO_VECTOR_CONFIG_DELIVERY_TOKEN in $NANO_INSTALL_DIR/.env. Ingest hosts need it before nano-api starts: nano-api refuses their install token for Vector config delivery (a publicly known one always, a private one with NANO_VECTOR_CONFIG_DELIVERY_STRICT=true), and a placeholder delivery token too. Securely copy $NANO_INSTALL_DIR/.env to every inventory host, then re-run this command here and install.sh on each ingest host. Nothing was started."
    fi
    if [[ -n "${NANO_PUBLIC_DB_PASSWORD_KEYS:-}" ]]; then
        warn "Database password(s) $NANO_PUBLIC_DB_PASSWORD_KEYS are publicly known defaults. They are not changed automatically: PostgreSQL and ClickHouse keep the password their data was created with."
        warn "These services are reachable only on the internal Docker network, but change them: see 'Changing a database password' in docs/getting-started/docker-deployment.md."
    fi
    VECTOR_AUTH_TOKEN_PRESENT=0
    grep -qE '^VECTOR_AUTH_TOKEN=.' .env && VECTOR_AUTH_TOKEN_PRESENT=1
    # Schema profile is fixed at first install (see below); read it back so the
    # summary reflects the live value. A .env without the key predates the
    # profile choice, so its data is UDM: pin that explicitly (NAN-4903) so the
    # install never depends on a compose/runtime fallback, which new installs
    # no longer share. An existing value is never rewritten.
    SCHEMA_PROFILE=$(env_value NANO_SCHEMA_PROFILE)
    if [[ -z "$SCHEMA_PROFILE" ]]; then
        SCHEMA_PROFILE=udm
        # Append the effective assignment so a symlinked .env remains a link.
        echo "NANO_SCHEMA_PROFILE=udm" >> .env
        log "Pinned NANO_SCHEMA_PROFILE=udm in .env (this install predates the schema choice)"
    fi
    # Appended (symlink-safe; the last assignment wins) only when this run
    # adds or changes a licence value.
    resolve_license 0
    record_license .env
else
    REUSE_ENV=0
    log "Configuring first-time admin account"

    [[ -z "$ADMIN_EMAIL" ]]    && ADMIN_EMAIL=$(prompt_tty "Admin email")
    [[ -z "$ADMIN_EMAIL" ]]    && fail "Admin email is required."

    [[ -z "$ADMIN_NAME" ]]     && ADMIN_NAME=$(prompt_tty "Admin display name" "Admin")
    [[ -z "$ADMIN_NAME" ]]     && fail "Admin name is required."

    if [[ -z "$ADMIN_PASSWORD" && "${NANO_PREPARE_ONLY:-0}" == "1" ]]; then
        # The password is never written to .env, so a prepare run does not
        # ask for it: ./install.sh asks when it creates the account.
        :
    elif [[ -z "$ADMIN_PASSWORD" ]]; then
        ADMIN_PASSWORD=$(prompt_tty "Admin password (blank = autogenerate)" "" secret)
        if [[ -z "$ADMIN_PASSWORD" ]]; then
            ADMIN_PASSWORD="N!a1$(gen_secret | cut -c1-20)"
            GENERATED_PASSWORD=1
        fi
    fi
    [[ -z "$ADMIN_PASSWORD" ]] || validate_admin_password "$ADMIN_PASSWORD"

    # An explicit environment value makes the documented non-interactive
    # install path fully non-interactive.
    if [[ -z "${NANO_BASE_URL:-}" ]]; then
        BASE_URL=$(prompt_tty "Public base URL" "$BASE_URL")
    fi

    # Plain-HTTP deployments need NANOSIEM_DEV_MODE=true so the auth refresh
    # cookie is set without the Secure flag — otherwise browsers silently
    # drop it and the user is bounced to /login every ~15 min (NAN-807 bug #12).
    if [[ "$BASE_URL" == http://* ]]; then
        DEV_MODE=true
        warn "BASE_URL is http:// — enabling NANOSIEM_DEV_MODE so login cookies work over plain HTTP."
    else
        DEV_MODE=false
    fi

    # Storage schema profile — OCSF (the default for new installs, NAN-4903) or
    # UDM (the legacy nano-native, CIM-style schema). This picks the ClickHouse
    # tables, parsers, rules content channel and field universe the whole stack
    # runs against, so it CANNOT be changed after the first event is ingested
    # (switching repoints search/detection to a different, empty table). Pinned
    # in .env on first install and never re-prompted on later runs.
    # NAN-1604: 'ocsf+tenzir' = the OCSF profile PLUS a bundled Tenzir node
    # (compose `tenzir` profile) pre-wired to the native OCSF entrypoint, for
    # direct ingestion. It resolves to NANO_SCHEMA_PROFILE=ocsf + BUNDLE_TENZIR=1.
    BUNDLE_TENZIR=0
    SCHEMA_PROFILE="${NANO_SCHEMA_PROFILE:-}"
    if [[ -z "$SCHEMA_PROFILE" ]] && ! have_controlling_tty; then
        # Fully non-interactive (no TTY): take the default rather than fail.
        SCHEMA_PROFILE=ocsf
    elif [[ -z "$SCHEMA_PROFILE" ]]; then
        while :; do
            SCHEMA_PROFILE=$(prompt_tty \
                "Schema profile — 'ocsf' (recommended), 'ocsf+tenzir' (OCSF + a bundled Tenzir node for direct ingestion), or 'udm' (legacy CIM-style)" "ocsf")
            SCHEMA_PROFILE=$(printf '%s' "$SCHEMA_PROFILE" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
            case "$SCHEMA_PROFILE" in
                ""|ocsf)     SCHEMA_PROFILE=ocsf; break ;;
                udm)         break ;;
                ocsf+tenzir) SCHEMA_PROFILE=ocsf; BUNDLE_TENZIR=1; break ;;
                *) warn "Enter 'ocsf', 'ocsf+tenzir', or 'udm'." ;;
            esac
        done
    else
        SCHEMA_PROFILE=$(printf '%s' "$SCHEMA_PROFILE" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
        case "$SCHEMA_PROFILE" in
            udm|ocsf)    ;;
            ocsf+tenzir) SCHEMA_PROFILE=ocsf; BUNDLE_TENZIR=1 ;;
            *) fail "NANO_SCHEMA_PROFILE must be 'udm', 'ocsf', or 'ocsf+tenzir' (got '$SCHEMA_PROFILE')." ;;
        esac
    fi
    if [[ "$MULTI_NODE" == "1" && "$BUNDLE_TENZIR" == "1" ]]; then
        fail "The bundled Tenzir profile is single-node only; role-split installs must use the ocsf or udm schema profile without bundled Tenzir."
    fi

    # Licence: asked here, before anything is written, and fails closed for an
    # unattended install without one.
    resolve_license 1

    log "Generating secrets and writing .env"
    ENV_TEMP_FILE=$(mktemp .env.tmp.XXXXXX)
    chmod 600 "$ENV_TEMP_FILE"
    cat > "$ENV_TEMP_FILE" <<EOF
NANO_VERSION=$NANO_VERSION
NANO_IMAGE_PREFIX=$NANO_IMAGE_PREFIX
NANO_EDITION=$NANO_EDITION
BASE_URL=$BASE_URL
NANOSIEM_DEV_MODE=$DEV_MODE
NANO_SCHEMA_PROFILE=$SCHEMA_PROFILE
RUST_LOG=info
# Fresh install: every host gets NANO_VECTOR_CONFIG_DELIVERY_TOKEN from this
# file, so config delivery refuses the forwarder install token from day one.
NANO_VECTOR_CONFIG_DELIVERY_STRICT=true
EOF
    nano_backfill_generated_secrets "$ENV_TEMP_FILE" generate "$PWD/.env" \
        || fail "Could not generate required secrets for $NANO_INSTALL_DIR/.env."
    # The success summary needs only to know that ingest is configured. Secret
    # values stay in .env and are never copied into output-bearing variables.
    VECTOR_AUTH_TOKEN_PRESENT=1
    # NAN-1604: 'ocsf+tenzir' install — activate the bundled Tenzir compose
    # profile. `docker compose` reads COMPOSE_PROFILES from .env, so the existing
    # `pull` / `up -d` below bring the nano-tenzir service along automatically.
    if [[ "${BUNDLE_TENZIR:-0}" == "1" ]]; then
        echo "COMPOSE_PROFILES=tenzir" >> "$ENV_TEMP_FILE"
    fi
    # NAN-5172: the admin identity (never its password) survives to the run
    # that creates the account; see persistable_env_value.
    for kv in "NANO_ADMIN_EMAIL=$ADMIN_EMAIL" "NANO_ADMIN_NAME=$ADMIN_NAME"; do
        if persistable_env_value "${kv#*=}"; then
            printf "%s='%s'\n" "${kv%%=*}" "${kv#*=}" >> "$ENV_TEMP_FILE"
        else
            warn "${kv%%=*} contains quotes, '\\', '\$' or '\`', so it is not kept in .env; set it again if a later run must create the admin account."
        fi
    done
    record_license "$ENV_TEMP_FILE"
    # Persist the autogenerated admin password BEFORE the docker pull so a
    # mid-install failure doesn't lose it (NAN-807 bug #9). User-supplied
    # passwords are already known to the user — only stash the generated ones.
    if [[ "${GENERATED_PASSWORD:-0}" == "1" ]]; then
        cat >> "$ENV_TEMP_FILE" <<EOF

# Autogenerated initial admin password — printed by install.sh on success.
# Safe to delete once you've signed in and confirmed the credentials.
INITIAL_ADMIN_PASSWORD=$ADMIN_PASSWORD
EOF
    fi

    mv "$ENV_TEMP_FILE" .env
    ENV_TEMP_FILE=""

    ok "Wrote .env (mode 600)"
fi
configure_outbound_proxy
configure_private_ai_endpoints
configure_automatic_backups

# Resolve overlays before sizing as well as startup: an overlay can replace the
# Vector data volume with a host bind/external driver, whose capacity cannot be
# inferred from DockerRootDir. Keeping one validated list prevents the sizing
# and runtime Compose graphs from disagreeing.
read -r -a NANO_OVERLAY_LIST <<< "${NANO_COMPOSE_OVERLAYS:-}"
for overlay in ${NANO_OVERLAY_LIST[@]+"${NANO_OVERLAY_LIST[@]}"}; do
    if [[ ! "$overlay" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*\.ya?ml$ ]]; then
        fail "NANO_COMPOSE_OVERLAYS: '$overlay' is not a compose file name in the install directory"
    fi
    [[ -f "$overlay" ]] || fail "NANO_COMPOSE_OVERLAYS: '$overlay' does not exist in $NANO_INSTALL_DIR"
done

# NAN-4997: single-node sizing is recalculated on every install/upgrade. The
# managed block contains defaults only; any same-named assignment outside it,
# or in the invoking environment, remains an explicit operator override. A
# role-split cluster cannot share one host's defaults in its common .env, so its
# renderer performs this same calculation independently on every role host.
if [[ "$MULTI_NODE" != "1" ]]; then
    sizing_compose_args=(-f "$COMPOSE_FILE")
    for overlay in ${NANO_OVERLAY_LIST[@]+"${NANO_OVERLAY_LIST[@]}"}; do
        sizing_compose_args+=(-f "$overlay")
    done
    if ! NANO_VECTOR_DATA_STORAGE_MODE=$(
        docker compose "${sizing_compose_args[@]}" config --format json </dev/null \
            | vector_data_storage_mode_from_json
    ); then
        fail "Could not determine whether Vector data uses Docker-root or bind/external storage."
    fi
    export NANO_VECTOR_DATA_STORAGE_MODE
    sizing_roles=app,ingest,clickhouse,postgres
    [[ "${BUNDLE_TENZIR:-0}" == "1" ]] && sizing_roles+=,tenzir
    sizing_defaults=$(mktemp .nano-sizing.defaults.XXXXXX)
    "$RESOURCE_SIZING" \
        --topology single \
        --roles "$sizing_roles" \
        --shards 1 \
        --format env </dev/null > "$sizing_defaults"

    old_sizing_env="" old_sizing_server="" old_sizing_users=""
    if [[ "$REUSE_ENV" == "1" ]]; then
        old_sizing_env=$(mktemp .nano-sizing.old-env.XXXXXX)
        old_sizing_server=$(mktemp .nano-sizing.old-server.XXXXXX)
        old_sizing_users=$(mktemp .nano-sizing.old-users.XXXXXX)
        snapshot_effective_sizing_env .env "$sizing_defaults" "$old_sizing_env"
        [[ -f .nano-generated/sizing/clickhouse-config.xml ]] \
            && cp .nano-generated/sizing/clickhouse-config.xml "$old_sizing_server"
        [[ -f .nano-generated/sizing/clickhouse-users.xml ]] \
            && cp .nano-generated/sizing/clickhouse-users.xml "$old_sizing_users"
    fi

    write_auto_sizing_block .env "$sizing_defaults"
    rm -f "$sizing_defaults"
    mkdir -p .nano-generated/sizing
    new_sizing_env=$(mktemp .nano-generated/sizing/host.env.XXXXXX)
    "$RESOURCE_SIZING" \
        --topology single \
        --roles "$sizing_roles" \
        --shards 1 \
        --override-env .env \
        --server-output .nano-generated/sizing/clickhouse-config.xml \
        --users-output .nano-generated/sizing/clickhouse-users.xml \
        --format env </dev/null > "$new_sizing_env"
    mv "$new_sizing_env" .nano-generated/sizing/host.env
    if [[ "$REUSE_ENV" == "1" ]]; then
        report_sizing_changes \
            "$old_sizing_env" .nano-generated/sizing/host.env \
            "$old_sizing_server" .nano-generated/sizing/clickhouse-config.xml \
            "$old_sizing_users" .nano-generated/sizing/clickhouse-users.xml
        rm -f "$old_sizing_env" "$old_sizing_server" "$old_sizing_users"
    fi
    sized_cpu=$(env_value NANO_DETECTED_CPU_CORES)
    sized_memory=$(env_value NANO_DETECTED_MEMORY_MIB)
    sized_ch=$(env_value CLICKHOUSE_MEM_LIMIT)
    log "Rendered shared-host sizing for ${sized_cpu} CPU / ${sized_memory} MiB RAM (ClickHouse limit $sized_ch)"
fi

# NAN-3322 / NAN-4909: the unauthenticated ingest ports (Vector native :6000,
# raw OTLP :4317/:4318, Fluent :24224, bundled Tenzir :9095) bind 127.0.0.1
# unless the operator opts
# in. A bind override given to the installer must survive a later plain
# `docker compose up`, which reads only .env, so persist it there.
for key in NANO_VECTOR_NATIVE_BIND_ADDRESS NANO_OTLP_BIND_ADDRESS NANO_FLUENT_BIND_ADDRESS NANO_TENZIR_BIND_ADDRESS; do
    if [[ -n "${!key:-}" ]]; then
        # The last assignment wins in Compose and append follows a symlinked
        # .env without replacing the link.
        printf '%s=%s\n' "$key" "${!key}" >> .env
        log "Persisted $key=${!key} to .env (re-exposes an unauthenticated ingest port)"
    fi
done

# Build the compose invocation only after edition resolution and .env creation.
# The role env contains no secrets: it is a validated rendering of inventory
# addresses, ports, profiles and generated-config paths. Compose reads it
# directly; values needed by this script are decoded without evaluating them as
# shell input.
COMPOSE_ARGS=()
if [[ "$MULTI_NODE" == "1" ]]; then
    log "Validating durable topology identity before rendering host configuration"
    candidate_identity_json=$(python3 -I deploy/compose/render-inventory.py \
        --inventory "$INVENTORY_PATH" \
        --roles "$ROLE_ARG" \
        --identity-only \
        --override-env .env </dev/null) \
        || fail "Inventory identity validation failed. Published role configuration was not changed."
    IFS=$'\t' read -r candidate_identity candidate_deployment candidate_host candidate_plaintext < <(
        python3 -I -c 'import json,sys; value=json.loads(sys.argv[1]); print(value["sha256"], value["deployment_id"], value["host_id"], "1" if value["allow_plaintext_private_network"] else "0", sep="\t")' \
            "$candidate_identity_json" </dev/null
    )
    if [[ "$candidate_plaintext" == "1" ]]; then
        if [[ "${NANO_LAB_ONLY_PLAINTEXT:-0}" != "1" ]]; then
            fail "cluster.allow_plaintext_private_network=true is refused for production installs. It is only available on an isolated disposable lab when every installer invocation explicitly sets NANO_LAB_ONLY_PLAINTEXT=1. Published role configuration was not changed."
        fi
        warn "======================================================================"
        warn "TEST/LAB ONLY: NANO_LAB_ONLY_PLAINTEXT=1 explicitly accepted plaintext"
        warn "Private credentials and event data will cross the inventory network unencrypted."
        warn "This mode is forbidden for production and must never be exposed to untrusted networks."
        warn "======================================================================"
    fi
    recorded_identity=$(env_value NANO_DEPLOYMENT_IDENTITY_SHA256)
    topology_migration_accepted=0
    if [[ -n "$recorded_identity" && "$recorded_identity" != "$candidate_identity" ]]; then
        if [[ "$TOPOLOGY_MIGRATION_SHA" != "$recorded_identity" ]]; then
            fail "Inventory durable topology identity changed. Existing identity is $recorded_identity; candidate identity is $candidate_identity. Published role configuration was not changed. Complete the data-movement runbook, then acknowledge that exact current identity with --accept-topology-migration $recorded_identity."
        fi
        topology_migration_accepted=1
        warn "Explicit topology migration acknowledged for $recorded_identity -> $candidate_identity"
    elif [[ -n "$TOPOLOGY_MIGRATION_SHA" ]]; then
        fail "--accept-topology-migration was supplied, but the inventory durable topology identity did not change. Remove the stale acknowledgement flag."
    fi

    host_identity_file=.nano-host-identity
    if [[ -e "$host_identity_file" || -L "$host_identity_file" ]]; then
        validate_env_file "$NANO_INSTALL_DIR/$host_identity_file"
        recorded_deployment=$(awk -F= '$1 == "NANO_DEPLOYMENT_ID" {print $2; exit}' "$host_identity_file")
        recorded_host=$(awk -F= '$1 == "NANO_HOST_ID" {print $2; exit}' "$host_identity_file")
        if [[ "$recorded_deployment" != "$candidate_deployment" || "$recorded_host" != "$candidate_host" ]]; then
            fail "This install directory belongs to deployment/host $recorded_deployment/$recorded_host, not $candidate_deployment/$candidate_host. Published role configuration was not changed."
        fi
    fi

    had_prior_role_sizing=0
    old_role_sizing_env=$(mktemp .nano-sizing.old-env.XXXXXX)
    old_role_sizing_server=$(mktemp .nano-sizing.old-server.XXXXXX)
    old_role_sizing_users=$(mktemp .nano-sizing.old-users.XXXXXX)
    if [[ -f .nano-generated/sizing/host.env ]]; then
        cp .nano-generated/sizing/host.env "$old_role_sizing_env"
        had_prior_role_sizing=1
    elif [[ -f .nano-role.env ]]; then
        python3 -I - .nano-role.env > "$old_role_sizing_env" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as env_file:
    for line in env_file:
        key, encoded = line.rstrip("\n").split("=", 1)
        value = json.loads(encoded)
        if isinstance(value, str) and "\n" not in value:
            print(f"{key}={value}")
PY
        had_prior_role_sizing=1
    fi
    if [[ -f .nano-generated/sizing/clickhouse-config.xml ]]; then
        cp .nano-generated/sizing/clickhouse-config.xml "$old_role_sizing_server"
    elif [[ -f .nano-generated/clickhouse/config.d/zzzz-nano-sizing.xml ]]; then
        cp .nano-generated/clickhouse/config.d/zzzz-nano-sizing.xml "$old_role_sizing_server"
    fi
    if [[ -f .nano-generated/sizing/clickhouse-users.xml ]]; then
        cp .nano-generated/sizing/clickhouse-users.xml "$old_role_sizing_users"
    elif [[ -f .nano-generated/clickhouse/users.d/zzzz-nano-sizing.xml ]]; then
        cp .nano-generated/clickhouse/users.d/zzzz-nano-sizing.xml "$old_role_sizing_users"
    fi

    ROLE_CONFIG_WAS_PUBLISHED=0
    if [[ -d .nano-generated || -f .nano-role.env ]]; then
        ROLE_CONFIG_WAS_PUBLISHED=1
    fi
    log "Rendering host roles '$ROLE_ARG' from $INVENTORY_PATH"
    python3 -I deploy/compose/render-inventory.py \
        --inventory "$INVENTORY_PATH" \
        --roles "$ROLE_ARG" \
        --output-dir .nano-generated \
        --env-output .nano-role.env \
        --override-env .env \
        </dev/null \
        || fail "Inventory validation/rendering failed. No services have started."
    while IFS= read -r -d '' role_key && IFS= read -r -d '' role_value; do
        printf -v "$role_key" '%s' "$role_value"
        export "${role_key?}"
    done < <(
        python3 -I - .nano-role.env <<'PY'
import json
import re
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as role_env:
    for line in role_env:
        key, encoded = line.rstrip("\n").split("=", 1)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            raise SystemExit(f"{path}: invalid key {key!r}")
        value = json.loads(encoded)
        if not isinstance(value, str):
            raise SystemExit(f"{path}: {key} is not a string")
        sys.stdout.buffer.write(key.encode() + b"\0" + value.encode() + b"\0")
PY
    )
    if [[ "$had_prior_role_sizing" == "1" ]]; then
        report_sizing_changes \
            "$old_role_sizing_env" .nano-generated/sizing/host.env \
            "$old_role_sizing_server" .nano-generated/sizing/clickhouse-config.xml \
            "$old_role_sizing_users" .nano-generated/sizing/clickhouse-users.xml
    fi
    rm -f "$old_role_sizing_env" "$old_role_sizing_server" "$old_role_sizing_users"
    log "Rendered host-local sizing for ${NANO_DETECTED_CPU_CORES} CPU / ${NANO_DETECTED_MEMORY_MIB} MiB RAM"
    if [[ ",${ROLE_ARG}," == *,clickhouse,* ]]; then
        log "Using host-local ClickHouse memory limit $CLICKHOUSE_MEM_LIMIT"
    fi
    if [[ "$NANO_PRIVATE_TLS" == "true" ]]; then
        for tls_path in "$NANO_TLS_CERT" "$NANO_TLS_KEY" "$NANO_TLS_CA"; do
            [[ -f "$tls_path" && -r "$tls_path" ]] \
                || fail "Inventory TLS file is not a readable regular file on this host: $tls_path"
        done
    else
        warn "PLAINTEXT PRIVATE NETWORK ENABLED — ClickHouse, Keeper, and app-internal traffic is not encrypted."
    fi

    [[ "$NANO_DEPLOYMENT_IDENTITY_SHA256" == "$candidate_identity" ]] \
        || fail "Renderer identity changed between preflight and publication; refusing to continue."
    if [[ -z "$recorded_identity" || "$topology_migration_accepted" == "1" ]]; then
        printf 'NANO_DEPLOYMENT_IDENTITY_SHA256=%s\n' "$candidate_identity" >> .env
    fi

    if [[ ! -e "$host_identity_file" && ! -L "$host_identity_file" ]]; then
        ENV_TEMP_FILE=$(mktemp .nano-host-identity.XXXXXX)
        printf 'NANO_DEPLOYMENT_ID=%s\nNANO_HOST_ID=%s\n' "$NANO_DEPLOYMENT_ID" "$NANO_HOST_ID" > "$ENV_TEMP_FILE"
        chmod 600 "$ENV_TEMP_FILE"
        mv "$ENV_TEMP_FILE" "$host_identity_file"
        ENV_TEMP_FILE=""
    fi
    COMPOSE_ARGS=(--env-file .env --env-file .nano-role.env -f "$COMPOSE_FILE")
    HOST_PORT="$NANO_APP_PORT"
    API_BASE="http://localhost:${HOST_PORT}"
else
    COMPOSE_ARGS=(-f "$COMPOSE_FILE")
fi
ch_mem_feeds_note

# Security review 2026-11-08: ClickHouse's passwordless `default` user now only
# accepts connections from inside the ClickHouse container
# (clickhouse/users.d/default-user.xml). Before restarting an existing
# single-host stack, look for clients that logged in as `default` from another
# address in the last 7 days. They stop working with this release, so say who
# they are and require an explicit acknowledgement. Role-split installs never
# had a reachable `default` (the inventory renderer removes it).
clickhouse_default_user_preflight() {
    local query remote
    [[ "${REUSE_ENV:-0}" == "1" && "$MULTI_NODE" != "1" ]] || return 0
    docker compose "${COMPOSE_ARGS[@]}" ps --status running --services 2>/dev/null </dev/null \
        | grep -qx clickhouse || return 0
    query="SELECT IPv6NumToString(address) AS client, count() AS queries, max(event_time) AS last_seen FROM system.query_log WHERE user = 'default' AND event_date >= today() - 7 AND type = 'QueryStart' AND NOT (address = toIPv6('::1') OR isIPAddressInRange(IPv6NumToString(address), '::ffff:127.0.0.0/104')) GROUP BY address ORDER BY queries DESC LIMIT 20 FORMAT TSV"
    # The admin password is already in the ClickHouse container's environment;
    # it never appears on this host's command line.
    # shellcheck disable=SC2016
    remote=$(docker compose "${COMPOSE_ARGS[@]}" exec -T clickhouse sh -c \
        'clickhouse-client --user nanosiem_admin --password "$CLICKHOUSE_ADMIN_PASSWORD" --query "$1"' \
        sh "$query" </dev/null 2>/dev/null) || return 0
    [[ -n "$remote" ]] || return 0
    warn "ClickHouse's passwordless 'default' user is now reachable only from inside the ClickHouse container."
    warn "These clients logged in as 'default' over the network in the last 7 days (address, queries, last seen):"
    printf '%s\n' "$remote" | sed 's/^/      /' >&2
    warn "Move each one to its own password-protected user before relying on it: nanosiem_ingest (INSERT-only, CLICKHOUSE_INGEST_PASSWORD in .env) for event writers, nanosiem_rawsql (read-only, CLICKHOUSE_RAWSQL_PASSWORD) for queries and BI tools."
    if [[ "${NANO_ACK_CH_DEFAULT_LOCALHOST:-0}" != "1" ]]; then
        fail "Stopping before restarting the stack. Re-run with NANO_ACK_CH_DEFAULT_LOCALHOST=1 once those clients are moved (or to accept that they stop working)."
    fi
    warn "NANO_ACK_CH_DEFAULT_LOCALHOST=1: continuing; the clients above can no longer log in as 'default'."
}
clickhouse_default_user_preflight

# Optional root-level compose overlays, ported from the sovereign single-host
# installer. The list was validated before sizing so a storage override affects
# both the capacity contract and the graph that starts below.
for overlay in ${NANO_OVERLAY_LIST[@]+"${NANO_OVERLAY_LIST[@]}"}; do
    COMPOSE_ARGS+=(-f "$overlay")
    # NAN-5124: the TLS overlay 301-redirects :80 to https, so the installer's
    # own calls go straight to the HTTPS edge on loopback. The certificate is
    # issued for the public name, not localhost, so verification is skipped for
    # this loopback-only connection.
    if [[ "$overlay" == "docker-compose.tls.yml" && "$MULTI_NODE" != "1" ]]; then
        API_BASE="https://localhost:443"
        API_CURL_ARGS=(--insecure)
    fi
done

# ----------------------------------------------------------------------------
# 4. Pull images + bring stack up
# ----------------------------------------------------------------------------
# NAN-1604: docker compose gives the *shell environment* precedence over .env when
# interpolating ${NANO_SCHEMA_PROFILE}. A non-interactive install run with
# NANO_SCHEMA_PROFILE=ocsf+tenzir would otherwise leak that raw token into the
# api/jobs/search/migrate containers (which only accept udm|ocsf) and the migrator
# fails. Re-export the *resolved* profile (and the compose profile) so the value
# the containers see matches what we wrote to .env in both fresh and re-run paths.
export NANO_SCHEMA_PROFILE="$SCHEMA_PROFILE"
# Export the recorded profiles: the shell environment wins over .env, and
# .env may also carry the `backup` profile (NAN-5204).
COMPOSE_PROFILES_RECORDED=$(env_value COMPOSE_PROFILES)
if [[ "${BUNDLE_TENZIR:-0}" == "1" && ",$COMPOSE_PROFILES_RECORDED," != *",tenzir,"* ]]; then
    COMPOSE_PROFILES_RECORDED="${COMPOSE_PROFILES_RECORDED:+$COMPOSE_PROFILES_RECORDED,}tenzir"
fi
[[ -n "$COMPOSE_PROFILES_RECORDED" ]] && export COMPOSE_PROFILES="$COMPOSE_PROFILES_RECORDED"

# Record the resolved release + image source in .env (a re-run upgrades an
# existing install to this checkout's release) and export them, since the shell
# environment wins over .env during compose interpolation.
for kv in "NANO_EDITION=$NANO_EDITION" "NANO_VERSION=$NANO_VERSION" "NANO_IMAGE_PREFIX=$NANO_IMAGE_PREFIX"; do
    # Append the effective assignment so a symlinked .env remains a link.
    echo "$kv" >> .env
done
export NANO_VERSION NANO_IMAGE_PREFIX

if [[ "${NANO_PREPARE_ONLY:-0}" == "1" ]]; then
    ok "Prepared .env and role configuration without pulling the application stack or starting services (the pinned Vector image may be cached/pulled for the storage-capacity probe)"
    if [[ "$MULTI_NODE" == "1" ]]; then
        printf 'Securely copy %s/.env and %s to every inventory host, then install the data roles before the app role.\n' \
            "$NANO_INSTALL_DIR" "$INVENTORY_PATH"
    fi
    exit 0
fi

ACTIVE_IMAGES=$(docker compose "${COMPOSE_ARGS[@]}" config --images </dev/null)

# NAN-5197: every active image is pinned (third-party by @sha256 in the Compose
# files, first-party by the images lock), so only images whose pinned digest
# is not already local are pulled, by digest, each attempt bounded by
# NANO_PULL_TIMEOUT. A stale local tag counts as missing and is re-pulled. The
# lock pins first-party tags only when it describes this release.
log "Checking images from ${NANO_IMAGE_PREFIX%/*} (pulling only what is missing)"
NANO_PULL_LOCK=""
if [[ -f "$IMAGES_LOCK" && "$(lock_release "$IMAGES_LOCK")" == "${NANO_VERSION#v}" ]]; then
    NANO_PULL_LOCK="$IMAGES_LOCK"
fi
# NANO_SKIP_IMAGE_VERIFY=1 is the escape hatch for a store whose digest
# readback is unusable; presence then falls back to a plain inspect.
if ! NANO_PULL_LOCK="$NANO_PULL_LOCK" NANO_PULL_TRUST_TAGS="${NANO_SKIP_IMAGE_VERIFY:-0}" \
    nano_pull_images "$ACTIVE_IMAGES"; then
    if [[ "$NANO_EDITION" == "enterprise" ]]; then
        fail "Image pull failed. Enterprise images are in a private registry: log in to ${NANO_IMAGE_PREFIX%%/*} with the pull credential nano issued you, then re-run."
    fi
    fail "Image pull failed. If you see '401 Unauthorized', the GHCR packages may still be private — run 'docker login ghcr.io' or wait for nano-rs to flip them public."
fi

# Runs whether or not anything was pulled: every active image is re-checked
# against the lock before anything starts.
verify_image_digests

if [[ -n "${NANO_PRE_START_HOOK:-}" ]]; then
    [[ "$NANO_PRE_START_HOOK" == /* && -x "$NANO_PRE_START_HOOK" ]] \
        || fail "NANO_PRE_START_HOOK must be an absolute path to an executable."
    log "Running the pre-start hook"
    "$NANO_PRE_START_HOOK" pre-start </dev/null \
        || fail "Pre-start hook failed. No product services have started."
fi

# Plaintext is admitted only for an explicitly opted-in disposable lab. Before
# an app role starts, close Keeper's otherwise-open root namespace with the
# shared digest identity and prove that an anonymous create is rejected. Data
# roles are installed first, so a split Keeper quorum is available here. For a
# co-located app+Keeper lab, start only Keeper before applying the guard.
if [[ "$MULTI_NODE" == "1" && "${candidate_plaintext:-0}" == "1" \
    && ",${ROLE_ARG}," == *,app,* ]]; then
    [[ -r scripts/nano-keeper-root-guard ]] \
        || fail "scripts/nano-keeper-root-guard not found in $NANO_INSTALL_DIR. The release bundle is incomplete."
    if [[ ",${ROLE_ARG}," == *,keeper,* ]]; then
        log "Starting co-located lab Keeper before protecting its root namespace"
        docker compose "${COMPOSE_ARGS[@]}" up -d keeper </dev/null
    fi
    keeper_password=$(env_value NANO_KEEPER_PASSWORD)
    [[ -n "$keeper_password" ]] \
        || fail "NANO_KEEPER_PASSWORD is missing; cannot protect the plaintext lab Keeper root."
    IFS=',' read -r -a keeper_endpoint_list <<< "$NANO_KEEPER_ENDPOINTS"
    keeper_guard_args=()
    for keeper_endpoint in "${keeper_endpoint_list[@]}"; do
        [[ -n "$keeper_endpoint" ]] && keeper_guard_args+=(--endpoint "$keeper_endpoint")
    done
    ((${#keeper_guard_args[@]} > 0)) \
        || fail "The rendered role configuration has no Keeper endpoints for the plaintext lab guard."
    log "Protecting the plaintext lab Keeper root before starting the app role"
    printf '%s' "$keeper_password" \
        | python3 -I scripts/nano-keeper-root-guard "${keeper_guard_args[@]}" \
            --password-stdin --timeout "${NANO_KEEPER_ROOT_GUARD_TIMEOUT:-120}" \
        || fail "Could not protect the plaintext lab Keeper root. Confirm the Keeper quorum is ready, then retry the app role."
    unset keeper_password
    ok "Keeper root rejects anonymous znode creation"
fi

log "Starting services"
compose_up_args=(up -d)
if [[ "$MULTI_NODE" == "1" && "${ROLE_CONFIG_WAS_PUBLISHED:-0}" == "1" ]]; then
    # The renderer transactionally swaps `.nano-generated`. A running Docker
    # container keeps a directory bind mount attached to the retired inode,
    # so a plain `up -d` can leave ClickHouse with an empty config.d after a
    # rerun or role change. Recreate every selected role service immediately
    # after publication so all mounts bind the newly published tree.
    compose_up_args+=(--force-recreate)
    log "Recreating selected role services to attach the newly published configuration"
fi
docker compose "${COMPOSE_ARGS[@]}" "${compose_up_args[@]}" </dev/null

# On a re-run/upgrade, `up -d` recreates the app containers (new IPs) but leaves
# nginx as-is — and it won't have loaded an updated nginx.conf either. Reload
# nginx so it picks up any config change and re-resolves upstream IPs, otherwise
# it proxies dead old IPs and 502s until restarted (NAN-1237). Best-effort.
docker compose "${COMPOSE_ARGS[@]}" exec -T nginx nginx -s reload </dev/null >/dev/null 2>&1 || true

# ----------------------------------------------------------------------------
# 5. Wait for API health
# ----------------------------------------------------------------------------
HAS_APP=1
HAS_INGEST=0
if [[ "$MULTI_NODE" == "1" ]]; then
    HAS_APP=0
    [[ ",${ROLE_ARG}," == *,app,* ]] && HAS_APP=1
    [[ ",${ROLE_ARG}," == *,ingest,* ]] && HAS_INGEST=1
fi

if [[ "$HAS_APP" == "1" ]]; then
    log "Waiting for API to become healthy through the app edge (up to 5 min — first run includes DB migrations)"
    HEALTH_URL="${API_BASE}/api/health"
    deadline=$(( $(date +%s) + 300 ))
    while (( $(date +%s) < deadline )); do
        if api_call /dev/null "$HEALTH_URL" >/dev/null; then
            ok "API healthy"
            break
        fi
        sleep 3
    done
    if ! health_code=$(api_call /dev/null "$HEALTH_URL"); then
        fail "API did not become healthy within 5 min (HTTP $health_code from $HEALTH_URL). Check 'docker compose ${COMPOSE_ARGS[*]} logs nano-api nginx clickhouse-migrate'."
    fi
    if [[ "$MULTI_NODE" == "1" ]]; then
        log "Waiting for every ClickHouse asynchronous-loader object to become OK"
        nano_wait_async_loaders "${NANO_ASYNC_LOADER_TIMEOUT:-300}" 3 \
            || fail "ClickHouse asynchronous-loader readiness failed. Check ClickHouse logs and system.asynchronous_loader before retrying."
        ok "ClickHouse asynchronous loaders ready"
    fi
elif [[ "$HAS_INGEST" == "1" ]]; then
    INGEST_HEALTH_URL="http://localhost:${NANO_INGEST_PORT}/healthz"
    log "Waiting for the ingest edge at $INGEST_HEALTH_URL"
    deadline=$(( $(date +%s) + 120 ))
    while (( $(date +%s) < deadline )); do
        curl -fsS -o /dev/null "$INGEST_HEALTH_URL" </dev/null && break
        sleep 2
    done
    curl -fsS -o /dev/null "$INGEST_HEALTH_URL" </dev/null \
        || fail "Ingest edge did not become healthy. Check 'docker compose ${COMPOSE_ARGS[*]} logs vector vector-config-consumer ingest-edge'."
    ok "Ingest edge healthy"
else
    # Stateful roles have their scenario-level readiness proven by the e2e
    # harness. Here, fail quickly if the requested long-running container died.
    for role_service in ${ROLE_ARG//,/ }; do
        case "$role_service" in
            postgres|clickhouse|keeper)
                docker compose "${COMPOSE_ARGS[@]}" ps --status running --services </dev/null | grep -qx "$role_service" \
                    || fail "$role_service did not stay running. Check 'docker compose ${COMPOSE_ARGS[*]} logs $role_service'." ;;
        esac
    done
    ok "Requested role container(s) running"
fi

# ----------------------------------------------------------------------------
# 6. Initialize admin user only when setup status is still uninitialized
# ----------------------------------------------------------------------------
if [[ "$HAS_APP" != "1" ]]; then
    ok "Admin initialization belongs to the app role; skipped on this host"
else
    STATUS_FILE=$(mktemp)
    if ! status_code=$(api_call "$STATUS_FILE" "${API_BASE}/api/setup/status"); then
        rm -f "$STATUS_FILE"
        fail "Could not read setup status (HTTP $status_code from ${API_BASE}/api/setup/status). Check 'docker compose ${COMPOSE_ARGS[*]} logs nano-api nginx'."
    fi
    STATUS_JSON=$(cat "$STATUS_FILE")
    rm -f "$STATUS_FILE"
    if echo "$STATUS_JSON" | grep -q '"initialized":true'; then
        warn "System is already initialized — skipping admin creation."
    else
        if [[ "$REUSE_ENV" == "1" ]]; then
            # NAN-5172: email/name come from .env (kept by the first run) or
            # the environment; with a TTY anything still missing is asked.
            # The password is never in .env unless it was autogenerated.
            not_initialized="This install has no admin account yet. Set NANO_ADMIN_EMAIL, NANO_ADMIN_NAME and NANO_ADMIN_PASSWORD, or run ./install.sh in a terminal to be asked, then re-run"
            [[ "$MULTI_NODE" == "1" ]] && not_initialized+=" the app role"
            not_initialized+="."
            if [[ -z "$ADMIN_EMAIL" ]]; then
                have_controlling_tty || fail "$not_initialized"
                ADMIN_EMAIL=$(prompt_tty "Admin email")
                [[ -n "$ADMIN_EMAIL" ]] || fail "Admin email is required."
                persistable_env_value "$ADMIN_EMAIL" && printf "NANO_ADMIN_EMAIL='%s'\n" "$ADMIN_EMAIL" >> .env
            fi
            if [[ -z "$ADMIN_NAME" ]]; then
                have_controlling_tty || fail "$not_initialized"
                ADMIN_NAME=$(prompt_tty "Admin display name" "Admin")
                [[ -n "$ADMIN_NAME" ]] || fail "Admin name is required."
                persistable_env_value "$ADMIN_NAME" && printf "NANO_ADMIN_NAME='%s'\n" "$ADMIN_NAME" >> .env
            fi
            if [[ -z "$ADMIN_PASSWORD" ]]; then
                ADMIN_PASSWORD=$(env_value INITIAL_ADMIN_PASSWORD)
                [[ -n "$ADMIN_PASSWORD" ]] && GENERATED_PASSWORD=1
            fi
            if [[ -z "$ADMIN_PASSWORD" ]]; then
                have_controlling_tty || fail "$not_initialized"
                ADMIN_PASSWORD=$(prompt_tty "Admin password (blank = autogenerate)" "" secret)
                if [[ -z "$ADMIN_PASSWORD" ]]; then
                    ADMIN_PASSWORD="N!a1$(gen_secret | cut -c1-20)"
                    GENERATED_PASSWORD=1
                    printf '\n# Autogenerated initial admin password — printed by install.sh on success.\n# Safe to delete once you have signed in and confirmed the credentials.\nINITIAL_ADMIN_PASSWORD=%s\n' "$ADMIN_PASSWORD" >> .env
                fi
            fi
            validate_admin_password "$ADMIN_PASSWORD"
        fi
        log "Creating admin user $ADMIN_EMAIL"
        payload=$(printf '{"email":%s,"name":%s,"password":%s}' \
            "$(json_escape "$ADMIN_EMAIL")" \
            "$(json_escape "$ADMIN_NAME")" \
            "$(json_escape "$ADMIN_PASSWORD")")
        if ! init_code=$(api_call /dev/null -X POST \
            -H "Content-Type: application/json" \
            -d "$payload" \
            "${API_BASE}/api/setup/initialize"); then
            fail "Admin initialization failed (HTTP $init_code from ${API_BASE}/api/setup/initialize). Check 'docker compose ${COMPOSE_ARGS[*]} logs nano-api nginx'."
        fi
        ok "Admin user created"
    fi
    import_offline_license
fi

# ----------------------------------------------------------------------------
# 7. Done
# ----------------------------------------------------------------------------
echo
printf "%bnano is up.%b\n" "$c_green$c_bold" "$c_reset"
echo
printf "  Open:     %s\n" "$BASE_URL"
if [[ "$MULTI_NODE" == "1" ]]; then
    printf "  Host:     %s\n" "$NANO_HOST_NAME"
    printf "  Roles:    %s\n" "$ROLE_ARG"
fi
printf "  Login:    %s\n" "${ADMIN_EMAIL:-(existing user)}"
printf "  Schema:   %s\n" "$(printf '%s' "${SCHEMA_PROFILE:-udm}" | tr '[:lower:]' '[:upper:]')"
if [[ "${GENERATED_PASSWORD:-0}" == "1" ]]; then
    printf "  Password: see %s/.env (INITIAL_ADMIN_PASSWORD)\n" "$NANO_INSTALL_DIR"
fi
# NAN-835 / NAN-836: surface every ingest endpoint + one-line curl so users
# can point external Vector / Splunk forwarder / curl at the new instance
# without spelunking through .env or docker-compose.
if [[ "${VECTOR_AUTH_TOKEN_PRESENT:-0}" == "1" ]]; then
    INGEST_BASE_URL="$BASE_URL"
    if [[ "$MULTI_NODE" == "1" ]]; then
        case "$BASE_URL" in
            https://*) INGEST_BASE_URL="https://${NANO_INGEST_HOSTNAME}" ;;
            *) INGEST_BASE_URL="http://${NANO_INGEST_HOSTNAME}" ;;
        esac
    fi
    # Strip scheme + path from BASE_URL to get bare host for host:port endpoints
    INGEST_HOST="${INGEST_BASE_URL#http://}"
    INGEST_HOST="${INGEST_HOST#https://}"
    INGEST_HOST="${INGEST_HOST%%/*}"
    INGEST_HOST="${INGEST_HOST%%:*}"
    echo
    # NAN-4907: the token decides the source. Senders use a named ingest token
    # per source (shown once in the UI); the install token is not an ingest
    # credential on a fresh install. An upgraded install keeps it in the
    # deprecated legacy multiplex mode (routed by X-Source-Type / sourcetype).
    printf "  Ingest tokens: issue one per sender in %s/ingestion/ingest-tokens\n" "$BASE_URL"
    printf "              (bound to one log source, which it decides; shown once)\n"
    if [[ "${REUSE_ENV:-0}" == "1" ]]; then
        printf "  Install token: VECTOR_AUTH_TOKEN in %s/.env  ← legacy multiplex (deprecated) on upgraded installs\n" "$NANO_INSTALL_DIR"
    fi
    echo
    printf "  HTTP:     POST %s/ingest\n" "$INGEST_BASE_URL"
    printf "              curl -X POST %s/ingest \\\\\n" "$INGEST_BASE_URL"
    printf "                -H 'Authorization: Bearer <ingest token>' \\\\\n"
    printf "                -d '{\"message\":\"hello nano\"}'\n"
    echo
    if [[ "$MULTI_NODE" == "1" ]]; then
        HEC_URL="$INGEST_BASE_URL/services/collector/event"
    else
        HEC_URL="http://$INGEST_HOST:8088/services/collector/event"
    fi
    printf "  HEC:      POST %s\n" "$HEC_URL"
    printf "              curl -X POST %s \\\\\n" "$HEC_URL"
    printf "                -H 'Authorization: Splunk <ingest token>' \\\\\n"
    printf "                -H 'X-Splunk-Request-Channel: <uuid>' \\\\\n"
    printf "                -d '{\"event\":\"hello nano\"}'\n"
    echo
    printf "  OTLP:     POST %s/otlp/v1/{logs,traces,metrics}  (Authorization: Bearer <ingest token>)\n" "$INGEST_BASE_URL"
    echo
    printf "  Vector:   %s:6000  (Vector → Vector native protocol, v2; loopback by default)\n" "$INGEST_HOST"
    printf "              no credential check: events land as source_type=vector_native\n"
    printf "              (prefer an HEC sink with a named ingest token per source)\n"
    # NAN-1603 / NAN-1604: direct OCSF ingestion (Tenzir / Cribl / custom) writes
    # straight into ClickHouse, bypassing Vector. Only meaningful on the OCSF profile.
    if [[ "$SCHEMA_PROFILE" == "ocsf" ]]; then
        echo
        printf "  Direct OCSF ingestion (Tenzir / Cribl / custom)\n"
        if [[ "$MULTI_NODE" == "1" ]]; then
            printf "            Native sink(s): %s\n" "$NANO_CLICKHOUSE_NATIVE_ENDPOINTS"
        else
            printf "            Native sink: clickhouse:9000  (internal docker network)\n"
        fi
        printf "            User/Table:  nanosiem_ingest → nanosiem.ocsf_logs_native_raw\n"
        printf "            Password:    see %s/.env (CLICKHOUSE_INGEST_PASSWORD)\n" "$NANO_INSTALL_DIR"
        printf "            Docs:        https://nano.rs/docs/ocsf/integrations/direct-ocsf\n"
        if [[ "${BUNDLE_TENZIR:-0}" == "1" ]]; then
            echo
            printf "  Tenzir:   bundled node %b'nano-tenzir'%b is running (Tenzir ≥ 6.4.0).\n" "$c_bold" "$c_reset"
            printf "              Send OCSF NDJSON:  POST http://%s:9095/  (UNAUTHENTICATED)\n" "$INGEST_HOST"
            printf "                                 binds 127.0.0.1 unless NANO_TENZIR_BIND_ADDRESS is set.\n"
            printf "              Edit its pipeline: %s/tenzir/pipeline.tql\n" "$NANO_INSTALL_DIR"
            printf "                                 (add your sources + OCSF mapping; the sink is pre-wired)\n"
            printf "              Apply edits:       docker compose -f %s/%s restart tenzir\n" "$NANO_INSTALL_DIR" "$COMPOSE_FILE"
        else
            printf "            Native client (Tenzir ≥ 6.4.0): configure TLS to match the inventory transport mode\n"
        fi
    fi
fi
echo
echo "  Logs:     cd $NANO_INSTALL_DIR && docker compose ${COMPOSE_ARGS[*]} logs -f"
echo "  Stop:     cd $NANO_INSTALL_DIR && docker compose ${COMPOSE_ARGS[*]} down"
echo "  Reset:    cd $NANO_INSTALL_DIR && docker compose ${COMPOSE_ARGS[*]} down -v   (DELETES ALL DATA)"
echo
}

# Keep this invocation as the final parsed command. When install.sh arrives via
# `curl ... | bash`, Bash must read the complete function body before any child
# can inherit stdin, so Docker or another CLI cannot consume unparsed source.
# The top-level BASH_SOURCE is empty for a streamed script and the file path
# for direct execution; read it here, never from inside main().
NANO_INSTALLER_SCRIPT_PATH="${BASH_SOURCE[0]:-}"
main "$@"
