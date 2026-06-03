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
#   3. Prompts for admin email / password / public BASE_URL (reads /dev/tty
#      even when stdin is piped from curl)
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

# Verify that the first-party images we just pulled match the sha256 manifest
# digests recorded in images.lock (generated + committed by CI). Docker already
# checksum-verifies layers on pull, but that only proves the bytes are internally
# consistent — it does NOT prove the tag wasn't re-pushed with different content.
# Pinning to the CI-vouched digest closes that supply-chain gap. Only the
# ghcr.io/nano-rs/* images are listed; stock third-party images are out of scope.
verify_image_digests() {
    local lockfile="images.lock"

    if [[ ! -f "$lockfile" ]]; then
        warn "images.lock not found — skipping image digest verification."
        return 0
    fi

    # images.lock tracks the latest release on this branch, so a user-pinned
    # NANO_VERSION won't match it. Only enforce on the default 'latest'; for a
    # pinned release, check out the matching git tag (its images.lock matches).
    if [[ "$NANO_VERSION" != "latest" ]]; then
        warn "NANO_VERSION is pinned to '$NANO_VERSION' — skipping images.lock verification (lockfile tracks 'latest')."
        return 0
    fi

    log "Verifying pulled image digests against images.lock"
    local repo expected actual mismatch=0 verified=0
    while read -r repo expected; do
        [[ -z "$repo" || "$repo" == \#* ]] && continue
        # RepoDigests records the manifest(-list) digest the tag resolved to on
        # pull — the same value CI writes to images.lock. Pick the entry for this
        # repo and strip everything up to the '@'.
        actual=$(docker image inspect "${repo}:${NANO_VERSION}" \
            --format '{{range .RepoDigests}}{{println .}}{{end}}' 2>/dev/null \
            | grep -F "${repo}@" | head -1)
        actual="${actual##*@}"
        if [[ -z "$actual" ]]; then
            fail "No registry digest found for ${repo}:${NANO_VERSION} — cannot verify it against images.lock. Refusing to start with unverifiable images."
        fi
        if [[ "$actual" != "$expected" ]]; then
            warn "DIGEST MISMATCH for $repo"
            warn "  expected (images.lock): $expected"
            warn "  actual   (pulled):      $actual"
            mismatch=1
        else
            verified=$((verified + 1))
        fi
    done < "$lockfile"

    if [[ "$mismatch" == "1" ]]; then
        fail "Image digest verification failed: pulled images do not match images.lock. Refusing to start. If you deliberately changed image versions this is expected — otherwise it may indicate a tampered or re-pushed tag."
    fi
    ok "Verified $verified first-party image digest(s) against images.lock"
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
    # NAN-835: pick the existing ingest token out of .env so the success
    # block can re-print it on every install run (not just the first one).
    VECTOR_AUTH_TOKEN=$(grep -E '^VECTOR_AUTH_TOKEN=' .env | head -1 | cut -d= -f2- || true)
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

    # Plain-HTTP deployments need NANOSIEM_DEV_MODE=true so the auth refresh
    # cookie is set without the Secure flag — otherwise browsers silently
    # drop it and the user is bounced to /login every ~15 min (NAN-807 bug #12).
    if [[ "$BASE_URL" == http://* ]]; then
        DEV_MODE=true
        warn "BASE_URL is http:// — enabling NANOSIEM_DEV_MODE so login cookies work over plain HTTP."
    else
        DEV_MODE=false
    fi

    log "Generating secrets and writing .env"
    # NAN-835: bind the ingest token to a shell var so the success block can
    # surface it. (Other secrets stay inline — they aren't user-facing.)
    VECTOR_AUTH_TOKEN=$(gen_secret)
    cat > .env <<EOF
NANO_VERSION=$NANO_VERSION
BASE_URL=$BASE_URL
NANOSIEM_DEV_MODE=$DEV_MODE
POSTGRES_PASSWORD=$(gen_secret)
CLICKHOUSE_PASSWORD=$(gen_secret)
CLICKHOUSE_ADMIN_PASSWORD=$(gen_secret)
JWT_SECRET=$(gen_secret)
NANOSIEM_ENCRYPTION_KEY=$(gen_secret)
VECTOR_AUTH_TOKEN=$VECTOR_AUTH_TOKEN
RUST_LOG=info
EOF
    chmod 600 .env

    # Persist the autogenerated admin password BEFORE the docker pull so a
    # mid-install failure doesn't lose it (NAN-807 bug #9). User-supplied
    # passwords are already known to the user — only stash the generated ones.
    if [[ "${GENERATED_PASSWORD:-0}" == "1" ]]; then
        cat >> .env <<EOF

# Autogenerated initial admin password — printed by install.sh on success.
# Safe to delete once you've signed in and confirmed the credentials.
INITIAL_ADMIN_PASSWORD=$ADMIN_PASSWORD
EOF
    fi

    ok "Wrote .env (mode 600)"
fi

# ----------------------------------------------------------------------------
# 4. Pull images + bring stack up
# ----------------------------------------------------------------------------
log "Pulling images from ghcr.io/nano-rs (this may take a minute on first run)"
if ! docker compose -f "$COMPOSE_FILE" pull; then
    fail "docker compose pull failed. If you see '401 Unauthorized', the GHCR packages may still be private — run 'docker login ghcr.io' or wait for nano-rs to flip them public."
fi

verify_image_digests

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
# NAN-835 / NAN-836: surface every ingest endpoint + one-line curl so users
# can point external Vector / Splunk forwarder / curl at the new instance
# without spelunking through .env or docker-compose.
if [[ -n "${VECTOR_AUTH_TOKEN:-}" ]]; then
    # Strip scheme + path from BASE_URL to get bare host for host:port endpoints
    INGEST_HOST="${BASE_URL#http://}"
    INGEST_HOST="${INGEST_HOST#https://}"
    INGEST_HOST="${INGEST_HOST%%/*}"
    INGEST_HOST="${INGEST_HOST%%:*}"
    echo
    printf "  Token:    %b%s%b  ← bearer for all ingest endpoints below\n" "$c_yellow$c_bold" "$VECTOR_AUTH_TOKEN" "$c_reset"
    echo
    printf "  HTTP:     POST %s/ingest\n" "$BASE_URL"
    printf "              curl -X POST %s/ingest \\\\\n" "$BASE_URL"
    printf "                -H 'Authorization: Bearer %s' \\\\\n" "$VECTOR_AUTH_TOKEN"
    printf "                -H 'X-Source-Type: my_source' \\\\\n"
    printf "                -d '{\"message\":\"hello nano\"}'\n"
    echo
    printf "  Splunk HEC: POST http://%s:8088/services/collector/event\n" "$INGEST_HOST"
    printf "              curl -X POST http://%s:8088/services/collector/event \\\\\n" "$INGEST_HOST"
    printf "                -H 'Authorization: Splunk %s' \\\\\n" "$VECTOR_AUTH_TOKEN"
    printf "                -d '{\"event\":\"hello nano\",\"sourcetype\":\"my_source\"}'\n"
    echo
    printf "  Vector:   %s:6000  (Vector → Vector native protocol, v2)\n" "$INGEST_HOST"
    printf "              point on-prem Vector aggregators here; use a vector\n"
    printf "              sink with auth = {{ strategy = \"bearer\", token = \"%s\" }}\n" "$VECTOR_AUTH_TOKEN"
fi
echo
echo "  Logs:     docker compose -f $NANO_INSTALL_DIR/$COMPOSE_FILE logs -f"
echo "  Stop:     docker compose -f $NANO_INSTALL_DIR/$COMPOSE_FILE down"
echo "  Reset:    docker compose -f $NANO_INSTALL_DIR/$COMPOSE_FILE down -v   (DELETES ALL DATA)"
echo
