#!/usr/bin/env bash
#
# nano — one-line installer for the open-source edition.
#
# Designed to be piped from curl:
#
#   curl -fsSL https://raw.githubusercontent.com/nano-rs/nano/main/install.sh | bash
#
# What it does:
#   1. Validates prerequisites (docker, docker compose v2, git, openssl, curl)
#   2. Clones (or pulls) nano-rs/nano into $NANO_INSTALL_DIR (default ~/nano)
#   3. Prompts for admin email / password / public BASE_URL (reads /dev/tty
#      even when stdin is piped from curl)
#   4. Generates strong random secrets and writes .env
#   5. Pulls images from ghcr.io/nano-rs and brings the stack up
#   6. Waits for the API to report healthy
#   7. POSTs to /api/setup/initialize to create the first admin account
#   8. Prints the login URL
#
# Non-interactive use: set the prompt values as env vars before running.
#   NANO_ADMIN_EMAIL, NANO_ADMIN_NAME, NANO_ADMIN_PASSWORD, NANO_BASE_URL
#
# Override defaults: NANO_INSTALL_DIR, NANO_REPO_URL, NANO_BRANCH, NANO_VERSION.

set -euo pipefail

NANO_INSTALL_DIR="${NANO_INSTALL_DIR:-$HOME/nano}"
NANO_REPO_URL="${NANO_REPO_URL:-https://github.com/nano-rs/nano.git}"
NANO_BRANCH="${NANO_BRANCH:-main}"
NANO_VERSION="${NANO_VERSION:-latest}"
COMPOSE_FILE="docker-compose.opensource.yml"
# All traffic goes through the nginx reverse proxy on port 80. The internal
# nano-api / nano-search ports are not exposed to the host by default.
HOST_PORT="${NANO_HOST_PORT:-80}"
API_BASE="http://localhost:${HOST_PORT}"

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

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "$1 is required but not installed. $2"
}

prompt_tty() {
    # $1 = prompt, $2 = default value (optional), $3 = "secret" to suppress echo
    local prompt="$1" default="${2:-}" secret="${3:-}" answer=""
    local display_prompt="$prompt"
    [[ -n "$default" ]] && display_prompt="$prompt [$default]"

    if [[ ! -t 0 && ! -e /dev/tty ]]; then
        # No TTY at all (e.g., piped without /dev/tty access) — must use env vars
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

gen_secret() { openssl rand -hex 32; }

# Escape a string for safe embedding inside a JSON string literal.
# Handles backslash, double-quote, and the C0 controls that JSON forbids.
json_escape() {
    python3 -c 'import json,sys; sys.stdout.write(json.dumps(sys.argv[1]))' "$1" 2>/dev/null \
        || node -e 'process.stdout.write(JSON.stringify(process.argv[1]))' -- "$1" 2>/dev/null \
        || fail "Neither python3 nor node is available to JSON-escape the admin password. Install one and retry."
}

# ----------------------------------------------------------------------------
# 1. Prereq check
# ----------------------------------------------------------------------------
log "Checking prerequisites"

require_cmd docker   "Install Docker: https://docs.docker.com/get-docker/"
require_cmd git      "Install git (most package managers)."
require_cmd openssl  "Install openssl (most distros ship it by default)."
require_cmd curl     "Install curl."

if ! docker compose version >/dev/null 2>&1; then
    fail "docker compose v2 is required. Update Docker or install the compose plugin."
fi

if ! docker info >/dev/null 2>&1; then
    fail "Docker daemon is not running or this user can't talk to it. Start Docker and retry."
fi

ok "All prerequisites present"

# ----------------------------------------------------------------------------
# 2. Clone or update the repo
# ----------------------------------------------------------------------------
if [[ -d "$NANO_INSTALL_DIR/.git" ]]; then
    if [[ -n "$(git -C "$NANO_INSTALL_DIR" status --porcelain 2>/dev/null)" ]]; then
        warn "$NANO_INSTALL_DIR has local changes — skipping git update so your edits stay intact."
    else
        log "Updating existing checkout at $NANO_INSTALL_DIR"
        git -C "$NANO_INSTALL_DIR" fetch --depth 1 origin "$NANO_BRANCH"
        git -C "$NANO_INSTALL_DIR" merge --ff-only "origin/$NANO_BRANCH" \
            || warn "Fast-forward merge failed (diverged history?). Keeping current checkout."
    fi
elif [[ -e "$NANO_INSTALL_DIR" ]]; then
    fail "$NANO_INSTALL_DIR exists but is not a git checkout. Move/remove it or set NANO_INSTALL_DIR to a different path."
else
    log "Cloning $NANO_REPO_URL → $NANO_INSTALL_DIR"
    git clone --depth 1 --branch "$NANO_BRANCH" "$NANO_REPO_URL" "$NANO_INSTALL_DIR"
fi
ok "Sources ready at $NANO_INSTALL_DIR"

cd "$NANO_INSTALL_DIR"

if [[ ! -f "$COMPOSE_FILE" ]]; then
    fail "$COMPOSE_FILE not found in $NANO_INSTALL_DIR. Branch '$NANO_BRANCH' may not include the OSS quickstart yet."
fi

# ----------------------------------------------------------------------------
# 3. Collect admin info (env first, then interactive)
# ----------------------------------------------------------------------------
ADMIN_EMAIL="${NANO_ADMIN_EMAIL:-}"
ADMIN_NAME="${NANO_ADMIN_NAME:-}"
ADMIN_PASSWORD="${NANO_ADMIN_PASSWORD:-}"
BASE_URL="${NANO_BASE_URL:-http://localhost}"

if [[ -f .env ]]; then
    warn ".env already exists — keeping existing secrets, will only (re)start the stack."
    REUSE_ENV=1
else
    REUSE_ENV=0
    log "Configuring first-time admin account"

    [[ -z "$ADMIN_EMAIL" ]]    && ADMIN_EMAIL=$(prompt_tty "Admin email")
    [[ -z "$ADMIN_EMAIL" ]]    && fail "Admin email is required."

    [[ -z "$ADMIN_NAME" ]]     && ADMIN_NAME=$(prompt_tty "Admin display name" "Admin")
    [[ -z "$ADMIN_NAME" ]]     && fail "Admin name is required."

    if [[ -z "$ADMIN_PASSWORD" ]]; then
        ADMIN_PASSWORD=$(prompt_tty "Admin password (blank = autogenerate)" "" secret)
        if [[ -z "$ADMIN_PASSWORD" ]]; then
            ADMIN_PASSWORD=$(gen_secret | cut -c1-24)
            GENERATED_PASSWORD=1
        fi
    fi
    if [[ ${#ADMIN_PASSWORD} -lt 12 ]]; then
        fail "Admin password must be at least 12 characters (got ${#ADMIN_PASSWORD})."
    fi

    BASE_URL=$(prompt_tty "Public base URL" "$BASE_URL")

    log "Generating secrets and writing .env"
    cat > .env <<EOF
NANO_VERSION=$NANO_VERSION
BASE_URL=$BASE_URL
POSTGRES_PASSWORD=$(gen_secret)
CLICKHOUSE_PASSWORD=$(gen_secret)
CLICKHOUSE_ADMIN_PASSWORD=$(gen_secret)
JWT_SECRET=$(gen_secret)
NANOSIEM_ENCRYPTION_KEY=$(gen_secret)
VECTOR_AUTH_TOKEN=$(gen_secret)
RUST_LOG=info
EOF
    chmod 600 .env
    ok "Wrote .env (mode 600)"
fi

# ----------------------------------------------------------------------------
# 4. Pull images + bring stack up
# ----------------------------------------------------------------------------
log "Pulling images from ghcr.io/nano-rs (this may take a minute on first run)"
if ! docker compose -f "$COMPOSE_FILE" pull; then
    fail "docker compose pull failed. If you see '401 Unauthorized', the GHCR packages may still be private — run 'docker login ghcr.io' or wait for nano-rs to flip them public."
fi

log "Starting services"
docker compose -f "$COMPOSE_FILE" up -d

# ----------------------------------------------------------------------------
# 5. Wait for API health
# ----------------------------------------------------------------------------
log "Waiting for API to become healthy through nginx (up to 5 min — first run includes DB migrations)"
HEALTH_URL="${API_BASE}/api/health"
deadline=$(( $(date +%s) + 300 ))
while (( $(date +%s) < deadline )); do
    if curl -fsS -o /dev/null "$HEALTH_URL"; then
        ok "API healthy"
        break
    fi
    sleep 3
done
if ! curl -fsS -o /dev/null "$HEALTH_URL"; then
    fail "API did not become healthy within 5 min. Check 'docker compose -f $COMPOSE_FILE logs nano-api nano-nginx'."
fi

# ----------------------------------------------------------------------------
# 6. Initialize admin user (skip if .env was reused — likely already done)
# ----------------------------------------------------------------------------
if [[ "$REUSE_ENV" == "1" ]]; then
    ok "Skipping admin initialization (existing .env reused — system already configured)"
else
    STATUS_JSON=$(curl -fsS "${API_BASE}/api/setup/status" || echo '{}')
    if echo "$STATUS_JSON" | grep -q '"initialized":true'; then
        warn "System is already initialized — skipping admin creation."
    else
        log "Creating admin user $ADMIN_EMAIL"
        payload=$(printf '{"email":%s,"name":%s,"password":%s}' \
            "$(json_escape "$ADMIN_EMAIL")" \
            "$(json_escape "$ADMIN_NAME")" \
            "$(json_escape "$ADMIN_PASSWORD")")
        if ! curl -fsS -X POST \
            -H "Content-Type: application/json" \
            -d "$payload" \
            "${API_BASE}/api/setup/initialize" > /dev/null; then
            fail "Admin initialization failed. Check 'docker compose -f $COMPOSE_FILE logs nano-api'."
        fi
        ok "Admin user created"
    fi
fi

# ----------------------------------------------------------------------------
# 7. Done
# ----------------------------------------------------------------------------
echo
printf "%bnano is up.%b\n" "$c_green$c_bold" "$c_reset"
echo
printf "  Open:     %s\n" "$BASE_URL"
printf "  Login:    %s\n" "${ADMIN_EMAIL:-(existing user)}"
if [[ "${GENERATED_PASSWORD:-0}" == "1" ]]; then
    printf "  Password: %b%s%b  ← autogenerated, save this now\n" "$c_yellow$c_bold" "$ADMIN_PASSWORD" "$c_reset"
fi
echo
echo "  Logs:     docker compose -f $NANO_INSTALL_DIR/$COMPOSE_FILE logs -f"
echo "  Stop:     docker compose -f $NANO_INSTALL_DIR/$COMPOSE_FILE down"
echo "  Reset:    docker compose -f $NANO_INSTALL_DIR/$COMPOSE_FILE down -v   (DELETES ALL DATA)"
echo
