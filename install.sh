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
#   NANO_SCHEMA_PROFILE (udm | ocsf, default udm) — chosen at first install
#   and immutable afterward; see the prompt below for the trade-off.
#
# Override defaults: NANO_INSTALL_DIR, NANO_REPO_URL, NANO_BRANCH, NANO_VERSION.
# Set NANO_SKIP_IMAGE_VERIFY=1 to skip the image digest supply-chain check.

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
        "https://api.github.com/repos/${owner_repo}/commits?path=images.lock&per_page=100" 2>/dev/null) \
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
# a temp file and echo its path. The working-tree lock tracks the latest release,
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
        if curl -fsSL "https://raw.githubusercontent.com/${owner_repo}/${sha}/images.lock" -o "$tmp" 2>/dev/null \
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
        --format '{{range .RepoDigests}}{{println .}}{{end}}' 2>/dev/null \
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

verify_image_digests() {
    local lockfile="images.lock"

    # Escape hatch (NAN-1328): let an operator opt out of the supply-chain check
    # if they hit an environment the digest readback can't handle. Off by default
    # — verification stays on for everyone who doesn't deliberately disable it.
    if [[ "${NANO_SKIP_IMAGE_VERIFY:-0}" == "1" ]]; then
        warn "NANO_SKIP_IMAGE_VERIFY=1 — skipping image digest verification (supply-chain check disabled)."
        return 0
    fi

    if [[ ! -f "$lockfile" ]]; then
        warn "images.lock not found — skipping image digest verification."
        return 0
    fi

    # Third-party base images are version-independent and always verified against
    # the local lock. First-party digests are release-specific: on 'latest' the
    # local lock matches; on a pinned NANO_VERSION we fetch the matching release's
    # lock so a careful (pinned) operator stays verified instead of skipped.
    local fp_lockfile="$lockfile" fetched=""
    if [[ "$NANO_VERSION" != "latest" ]]; then
        if fetched=$(fetch_release_lock "$NANO_VERSION") && [[ -n "$fetched" ]]; then
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
            result=$(verify_one_digest "$inspect_ref" "$repo_notag" "$expected")
            case "$result" in
                ok) verified_fp=$((verified_fp + 1)) ;;
                missing) fail "No registry digest found for ${inspect_ref} — cannot verify it against images.lock. Refusing to start with unverifiable images." ;;
                *) mismatch=1 ;;
            esac
        done < "$fp_lockfile"
    fi

    # Third-party lines (tagged): self-contained, always from the local lock.
    while read -r ref expected; do
        [[ -z "$ref" || "$ref" == \#* ]] && continue
        basename="${ref##*/}"; [[ "$basename" == *:* ]] || continue
        inspect_ref="$ref"; repo_notag="${ref%:*}"
        result=$(verify_one_digest "$inspect_ref" "$repo_notag" "$expected")
        case "$result" in
            ok) verified_tp=$((verified_tp + 1)) ;;
            missing) fail "No registry digest found for ${inspect_ref} — cannot verify it against images.lock. Refusing to start with unverifiable images." ;;
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
    # Schema profile is fixed at first install (see below); read it back so the
    # summary reflects the live value. Default udm for .env files predating it.
    SCHEMA_PROFILE=$(grep -E '^NANO_SCHEMA_PROFILE=' .env | head -1 | cut -d= -f2- || true)
    SCHEMA_PROFILE="${SCHEMA_PROFILE:-udm}"
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

    # Storage schema profile — UDM (nano-native, CIM-style) or OCSF. This
    # picks the ClickHouse tables, parsers, and field universe the whole stack
    # runs against, so it CANNOT be changed after the first event is ingested
    # (switching repoints search/detection to a different, empty table). Pinned
    # in .env on first install and never re-prompted on later runs.
    SCHEMA_PROFILE="${NANO_SCHEMA_PROFILE:-}"
    if [[ -z "$SCHEMA_PROFILE" ]]; then
        while :; do
            SCHEMA_PROFILE=$(prompt_tty \
                "Schema profile — 'udm' (CIM-style, recommended) or 'ocsf'" "udm")
            SCHEMA_PROFILE=$(printf '%s' "$SCHEMA_PROFILE" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
            case "$SCHEMA_PROFILE" in
                ""|udm) SCHEMA_PROFILE=udm; break ;;
                ocsf)   break ;;
                *) warn "Enter 'udm' or 'ocsf'." ;;
            esac
        done
    else
        SCHEMA_PROFILE=$(printf '%s' "$SCHEMA_PROFILE" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
        case "$SCHEMA_PROFILE" in
            udm|ocsf) ;;
            *) fail "NANO_SCHEMA_PROFILE must be 'udm' or 'ocsf' (got '$SCHEMA_PROFILE')." ;;
        esac
    fi

    log "Generating secrets and writing .env"
    # NAN-835: bind the ingest token to a shell var so the success block can
    # surface it. (Other secrets stay inline — they aren't user-facing.)
    VECTOR_AUTH_TOKEN=$(gen_secret)
    cat > .env <<EOF
NANO_VERSION=$NANO_VERSION
BASE_URL=$BASE_URL
NANOSIEM_DEV_MODE=$DEV_MODE
NANO_SCHEMA_PROFILE=$SCHEMA_PROFILE
POSTGRES_PASSWORD=$(gen_secret)
CLICKHOUSE_PASSWORD=$(gen_secret)
CLICKHOUSE_ADMIN_PASSWORD=$(gen_secret)
CLICKHOUSE_INGEST_PASSWORD=$(gen_secret)
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

# On a re-run/upgrade, `up -d` recreates the app containers (new IPs) but leaves
# nginx as-is — and it won't have loaded an updated nginx.conf either. Reload
# nginx so it picks up any config change and re-resolves upstream IPs, otherwise
# it proxies dead old IPs and 502s until restarted (NAN-1237). Best-effort.
docker exec nano-nginx nginx -s reload >/dev/null 2>&1 || true

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
printf "  Schema:   %s\n" "$(printf '%s' "${SCHEMA_PROFILE:-udm}" | tr '[:lower:]' '[:upper:]')"
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
