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
#      even when stdin is piped from curl). Storage is the OCSF 1.9 object
#      lake. The ClickHouse edition is retired (NAN-3491): it cannot be
#      installed, and an existing ClickHouse install is refused before
#      anything is changed (NAN-3853; it is a fresh install, see the message).
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
#   An env value always wins over its prompt. For unattended runs (Ansible,
#   cloud-init, CI) also pass NANO_NONINTERACTIVE=1 or `--non-interactive`
#   (alias `--yes`/`-y`; `curl … | bash -s -- --yes`): no prompt ever reads
#   /dev/tty, unset values take their defaults, and a value with no default
#   (NANO_ADMIN_EMAIL) is a hard error instead of a hang. Without a usable
#   terminal the installer switches to this mode on its own.
#   A blank NANO_ADMIN_PASSWORD autogenerates one that satisfies the API's
#   password policy; it is kept in .env (mode 600) until you delete it.
#   New installs use the OCSF 1.9 object lake. The retired ClickHouse
#   edition (NANO_ENABLE_LAKE_CONTROL_PLANE=0, NANO_SCHEMA_PROFILE=udm) is
#   refused.
#
# Ingest mode (NAN-3807), persisted in .env as NANO_VECTOR_PROFILE:
#   (default)      Vector ingest (HTTP /ingest, HEC, OTLP, pull connectors) AND
#                  the OCSF bucket drop (lean-landing): Tenzir can drop files
#                  into the object store beside Vector.
#   --tenzir       Tenzir-direct: no Vector and no connector runner. Tenzir
#                  writes OCSF files into the object store; lean-landing turns
#                  them into lake rows. Same as NANO_INGEST_MODE=tenzir.
#   --add-vector   Turn a Tenzir-direct install back into the default (adds
#                  Vector). Same as NANO_INGEST_MODE=vector.
#   A re-run without either flag keeps the mode the install already has.
#
# Override defaults: NANO_INSTALL_DIR, NANO_REPO_URL, NANO_BRANCH, NANO_VERSION.
# Set NANO_SKIP_IMAGE_VERIFY=1 to skip the image digest supply-chain check.
# NANO_HEALTH_TIMEOUT_SECONDS bounds the wait for the API (default 1800 on the
# lake profile, whose first boot waits for the query worker's bootstrap
# generation; 300 on the legacy ClickHouse profile).
#
# Re-running is safe: if a previous run timed out before the admin account was
# created, the next run creates it (keyed on GET /api/setup/status, not on
# whether .env exists) with the same credentials.

# Keep this guard POSIX-safe: piped scripts ignore the Bash shebang.
if [ -z "${BASH_VERSION:-}" ]; then
    if [ "$#" -gt 0 ]; then
        printf '%s\n' "nano's installer needs bash: curl -fsSL https://get.nano.rs | bash -s -- $*" >&2
    else
        printf '%s\n' "nano's installer needs bash: curl -fsSL https://get.nano.rs | bash" >&2
    fi
    exit 1
fi

# Parse the complete script before any subprocess can consume curl's stdin.
main() {
set -euo pipefail

# NAN-3402: containers bind-mount files from this checkout (Hydra, nginx,
# Vector, ClickHouse configs) and run as non-root users, so they must be
# world-readable. A hardened `umask 077` login made the cloned Hydra config
# unreadable. Secret files (.env) are created 0600 explicitly instead.
umask 022

NANO_INSTALL_DIR="${NANO_INSTALL_DIR:-$HOME/nano}"
NANO_REPO_URL="${NANO_REPO_URL:-https://github.com/nano-rs/nano.git}"
NANO_BRANCH="${NANO_BRANCH:-main}"
# Image release. Empty = the release recorded in the checkout's images.lock.
# NAN-3491 froze `:latest` on the last ClickHouse release (0.1.703); lean never
# pulls it (see resolve_lean_version).
NANO_VERSION="${NANO_VERSION:-}"
COMPOSE_FILE="docker-compose.opensource.yml"
# All traffic goes through the nginx reverse proxy on port 80. The internal
# nano-api / nano-search ports are not exposed to the host by default.
HOST_PORT="${NANO_HOST_PORT:-80}"
API_BASE="http://localhost:${HOST_PORT}"
NANO_NONINTERACTIVE="${NANO_NONINTERACTIVE:-0}"

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

usage() {
    cat <<'EOF'
Usage: install.sh [--non-interactive | --yes | -y] [--tenzir | --add-vector] [--help]

  --non-interactive, --yes, -y
      Never prompt. Every value comes from its env var or its default
      (same as NANO_NONINTERACTIVE=1). NANO_ADMIN_EMAIL is then required on
      the first install.
  --tenzir
      Tenzir-direct install: the lean lake WITHOUT Vector. Tenzir writes
      OCSF 1.9 files into the install's object store (the bucket drop);
      HTTP /ingest, HEC, OTLP and pull connectors are not offered.
  --add-vector
      Add Vector to a --tenzir install (Vector ingest plus the bucket drop,
      the default). A re-run without either flag keeps the current mode.

See the header of this script for every NANO_* environment variable.
EOF
}

is_truthy() {
    # No ${1,,}: macOS still ships bash 3.2.
    case "$1" in
        1|[Tt][Rr][Uu][Ee]|[Yy][Ee][Ss]|[Yy]|[Oo][Nn]) return 0 ;;
        *) return 1 ;;
    esac
}

# True when /dev/tty can actually be opened. `-e /dev/tty` is not enough: the
# node exists in every container and under cron/systemd, but opening it fails
# with ENXIO when the process has no controlling terminal.
tty_usable() {
    { : < /dev/tty; } 2>/dev/null
}

prompt_tty() {
    # $1 = prompt, $2 = default value (optional), $3 = "secret" to suppress echo
    # In non-interactive mode this never touches /dev/tty and returns the
    # default (possibly empty — the caller decides whether that is fatal).
    local prompt="$1" default="${2:-}" secret="${3:-}" answer=""
    local display_prompt="$prompt"
    [[ -n "$default" ]] && display_prompt="$prompt [$default]"

    if [[ "${NANO_NONINTERACTIVE:-0}" == "1" ]] || ! tty_usable; then
        printf "%s" "$default"
        return 0
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

# NAN-3807: the compose profile Vector and the connector runner carry
# (`${NANO_VECTOR_PROFILE:-lean}`). `none` = Tenzir-direct (no Vector).
# --tenzir / --add-vector (NANO_INGEST_MODE) decide; otherwise the install
# keeps the mode its .env records, and a new install gets Vector.
resolve_vector_profile() {
    case "${NANO_INGEST_MODE:-}" in
        tenzir) echo none ;;
        vector) echo lean ;;
        *) if [[ "$(env_file_value NANO_VECTOR_PROFILE)" == none ]]; then echo none; else echo lean; fi ;;
    esac
}

gen_secret() { openssl rand -hex 32; }

# Mirror of nanosiem-core/src/auth/password.rs `validate_password` (the policy
# POST /api/setup/initialize enforces): 12..1024 bytes with at least one ASCII
# uppercase, lowercase, digit, and special character. The Rust special set is
# exactly ASCII punctuation, i.e. [[:punct:]] in the C locale. Checking here
# lets a weak operator-supplied password fail in seconds instead of after the
# first-boot wait.
password_meets_policy() {
    local LC_ALL=C pw="$1"
    (( ${#pw} >= 12 && ${#pw} <= 1024 )) || return 1
    [[ "$pw" =~ [A-Z] ]] || return 1
    [[ "$pw" =~ [a-z] ]] || return 1
    [[ "$pw" =~ [0-9] ]] || return 1
    [[ "$pw" =~ [[:punct:]] ]] || return 1
}

# Autogenerate an initial admin password that satisfies password_meets_policy.
# 24 characters from letters, digits, and a special set chosen to survive
# every place the value travels unquoted: .env (no '#', '$', quotes, spaces),
# compose interpolation, the JSON payload (json_escape), and a terminal
# copy/paste. Rejection sampling keeps the draw uniform; a draw lacking a
# required class (~8% of draws, mostly no special) is simply redrawn.
ADMIN_PASSWORD_SPECIALS='@%+=_-.'
gen_admin_password() {
    local alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789${ADMIN_PASSWORD_SPECIALS}"
    local n=${#alphabet} limit pw byte attempt
    limit=$(( 256 - 256 % n ))
    for (( attempt = 0; attempt < 100; attempt++ )); do
        pw=""
        while read -r byte; do
            (( byte < limit )) || continue
            pw+="${alphabet:byte % n:1}"
            (( ${#pw} == 24 )) && break
        done < <(openssl rand 96 | od -An -v -tu1 | tr -s ' ' '\n' | grep -v '^$')
        if (( ${#pw} == 24 )) && password_meets_policy "$pw"; then
            printf '%s' "$pw"
            return 0
        fi
    done
    return 1
}

# Return the memory capacity Docker can actually use. On Docker Desktop this is
# the VM allocation, which can be much smaller than the physical Mac/Windows
# host. Linux falls back to MemTotal and macOS to hw.memsize when Docker does
# not report a numeric value. NANO_MEMORY_CAPACITY_BYTES exists for deterministic
# installer tests and unusual runtimes that cannot expose their cgroup capacity.
memory_capacity_bytes() {
    local bytes kb

    bytes="${NANO_MEMORY_CAPACITY_BYTES:-}"
    if [[ -n "$bytes" ]]; then
        [[ "$bytes" =~ ^[0-9]+$ ]] || fail "NANO_MEMORY_CAPACITY_BYTES must be an integer number of bytes."
        echo "$bytes"
        return
    fi

    bytes=$(docker </dev/null info --format '{{.MemTotal}}' 2>/dev/null || true)
    if [[ "$bytes" =~ ^[0-9]+$ ]] && (( bytes > 0 )); then
        echo "$bytes"
        return
    fi

    kb=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || true)
    if [[ "$kb" =~ ^[0-9]+$ ]] && (( kb > 0 )); then
        echo $((kb * 1024))
        return
    fi

    bytes=$(sysctl -n hw.memsize 2>/dev/null || true)
    if [[ "$bytes" =~ ^[0-9]+$ ]] && (( bytes > 0 )); then
        echo "$bytes"
        return
    fi

    echo 0
}

memory_capacity_gib() {
    local bytes
    bytes=$(memory_capacity_bytes)
    if (( bytes < 1073741824 )); then
        echo 0
    else
        # Floor rather than round up: a 15.6 GiB Docker VM must be planned as
        # 15 GiB or the simultaneous interactive + durable lanes can overcommit.
        echo $((bytes / 1073741824))
    fi
}

# NAN-2252: size the ClickHouse container memory limit from available Docker RAM
# rounded to whole GiB minus a fixed 4G reserve for the rest of the stack
# (api/search/jobs/vector/postgres/dragonfly limits total ~3.7G and do NOT
# scale with RAM), floored at the historical 2G. ClickHouse 26.x sizes its
# usable memory ceiling to the container cgroup limit, so the old flat 2G gave
# every host a 1.6 GiB ceiling that permanently wedges ingest around 300 eps
# (NAN-2251) while leaving bigger hosts mostly idle. 8G host → 4G, 16G → 12G,
# 32G → 28G. Falls back to 2G when Docker and both host probes are unreadable.
ch_mem_limit() {
    local g
    g=$(memory_capacity_gib)
    if (( g == 0 )); then
        echo "2G"
        return
    fi
    g=$((g - 4))
    (( g < 2 )) && g=2
    echo "${g}G"
}

# NAN-2361: derive a safe open-core lake memory envelope from Docker's actual
# capacity. Only one durable child runs at once, but it overlaps the interactive
# worker. The reserve covers Nano services, PostgreSQL, Dragonfly, RustFS, and
# the catalog. The interactive container briefly holds both generations'
# derivative/catalog state during an atomic cutover, while reusing the native
# executor. Reserve twice the query ceiling plus one GiB so a generation swap
# cannot wedge at the cgroup boundary. This is reload headroom, not additional
# analyst-query memory.
#
# Operators may override the plan, but must provide the complete five-value set.
# Accepting a partial override can put a 32 GiB chDB ceiling in a 16 GiB cgroup,
# which turns a controlled query failure into a container OOM.
#
# NAN-3402 (auto-v3): the durable classes are derived FROM the runner container
# with the job runner's own arithmetic, instead of guessing large = runner - 1.
# lake_job_runner clamps the large class to 80% of its cgroup limit
# (job_capacity::container_memory_budget) and, with retries on, refuses to start
# unless large > medium. auto-v2 sized 12 GiB as runner 3G / large 2G /
# medium 2G (crash loop), and on 32 GiB asked for 14G that the runner silently
# clamped to 12G. scripts/test-install-lake-memory-plan.sh pins the invariants.
LAKE_GIB=1073741824
LAKE_MIB=1048576
# Mirror of nanosiem-lake-worker job_capacity::container_memory_budget.
lake_runner_budget_bytes() {
    # shellcheck disable=SC2017 # the truncation order mirrors the Rust exactly
    echo $(( ($1 / 5 * 4) / LAKE_MIB * LAKE_MIB ))
}

lake_memory_plan() {
    local total_gib interactive_gib query_container_gib reserve_gib
    local large_bytes medium_bytes runner_container_gib override_count

    override_count=0
    [[ -n "${NANO_LAKE_MAX_MEMORY_BYTES:-}" ]] && override_count=$((override_count + 1))
    [[ -n "${NANO_LAKE_QUERY_CONTAINER_MEM_LIMIT:-}" ]] && override_count=$((override_count + 1))
    [[ -n "${NANO_LAKE_DURABLE_MEDIUM_MEMORY_BYTES:-}" ]] && override_count=$((override_count + 1))
    [[ -n "${NANO_LAKE_DURABLE_LARGE_MEMORY_BYTES:-}" ]] && override_count=$((override_count + 1))
    [[ -n "${NANO_LAKE_DURABLE_RUNNER_MEM_LIMIT:-}" ]] && override_count=$((override_count + 1))

    if (( override_count != 0 && override_count != 5 )); then
        fail "Override all five NANO_LAKE_* memory settings together, or leave all five unset for automatic sizing."
    fi

    if (( override_count == 5 )); then
        [[ "${NANO_LAKE_MAX_MEMORY_BYTES}" =~ ^[0-9]+$ ]] \
            || fail "NANO_LAKE_MAX_MEMORY_BYTES must be an integer number of bytes."
        [[ "${NANO_LAKE_DURABLE_MEDIUM_MEMORY_BYTES}" =~ ^[0-9]+$ ]] \
            || fail "NANO_LAKE_DURABLE_MEDIUM_MEMORY_BYTES must be an integer number of bytes."
        [[ "${NANO_LAKE_DURABLE_LARGE_MEMORY_BYTES}" =~ ^[0-9]+$ ]] \
            || fail "NANO_LAKE_DURABLE_LARGE_MEMORY_BYTES must be an integer number of bytes."
        [[ "${NANO_LAKE_QUERY_CONTAINER_MEM_LIMIT}" =~ ^[0-9]+([.][0-9]+)?[KMGT]?[iI]?[bB]?$ ]] \
            || fail "NANO_LAKE_QUERY_CONTAINER_MEM_LIMIT is not a Docker memory value."
        [[ "${NANO_LAKE_DURABLE_RUNNER_MEM_LIMIT}" =~ ^[0-9]+([.][0-9]+)?[KMGT]?[iI]?[bB]?$ ]] \
            || fail "NANO_LAKE_DURABLE_RUNNER_MEM_LIMIT is not a Docker memory value."
        LAKE_MAX_MEMORY_BYTES="$NANO_LAKE_MAX_MEMORY_BYTES"
        LAKE_QUERY_CONTAINER_MEM_LIMIT="$NANO_LAKE_QUERY_CONTAINER_MEM_LIMIT"
        LAKE_DURABLE_MEDIUM_MEMORY_BYTES="$NANO_LAKE_DURABLE_MEDIUM_MEMORY_BYTES"
        LAKE_DURABLE_LARGE_MEMORY_BYTES="$NANO_LAKE_DURABLE_LARGE_MEMORY_BYTES"
        LAKE_DURABLE_RUNNER_MEM_LIMIT="$NANO_LAKE_DURABLE_RUNNER_MEM_LIMIT"
        LAKE_MEMORY_SIZING="manual"
        LAKE_MEMORY_CAPACITY_GIB="operator-defined"
        return
    fi

    total_gib=$(memory_capacity_gib)
    (( total_gib >= 12 )) \
        || fail "The lake profile needs at least 12 GiB available to Docker (detected ${total_gib} GiB). Increase the memory available to Docker (on Docker Desktop: Settings → Resources → Memory)."

    interactive_gib=$((total_gib / 8))
    (( interactive_gib < 1 )) && interactive_gib=1
    (( interactive_gib > 4 )) && interactive_gib=4
    query_container_gib=$((interactive_gib * 2 + 1))

    # 12 GiB -> 6 GiB reserve; 16 GiB -> 6; 32+ GiB -> 8. This reserve
    # deliberately grows before query classes do so normal ingestion and UI
    # traffic remain healthy while a durable query spills/merges.
    reserve_gib=$(((total_gib + 7) / 8 + 4))
    (( reserve_gib < 5 )) && reserve_gib=5
    (( reserve_gib > 8 )) && reserve_gib=8

    # The durable runner gets everything left. 40 GiB is enough for the 32 GiB
    # large-class cap (80% of 40) — more would only idle.
    runner_container_gib=$((total_gib - reserve_gib - query_container_gib))
    (( runner_container_gib > 40 )) && runner_container_gib=40
    (( runner_container_gib >= 3 )) \
        || fail "Internal error: lake memory plan left ${runner_container_gib} GiB for the durable runner (${total_gib} GiB detected)."

    large_bytes=$(lake_runner_budget_bytes $((runner_container_gib * LAKE_GIB)))
    (( large_bytes > 32 * LAKE_GIB )) && large_bytes=$((32 * LAKE_GIB))
    medium_bytes=$((large_bytes / 2 / LAKE_MIB * LAKE_MIB))
    (( medium_bytes > 16 * LAKE_GIB )) && medium_bytes=$((16 * LAKE_GIB))
    # The runner rejects classes below 1 GiB. Runner >= 3 GiB gives large
    # >= 2.4 GiB, so this floor still leaves medium strictly below large.
    (( medium_bytes < LAKE_GIB )) && medium_bytes=$LAKE_GIB

    LAKE_MAX_MEMORY_BYTES=$((interactive_gib * LAKE_GIB))
    LAKE_QUERY_CONTAINER_MEM_LIMIT="${query_container_gib}G"
    LAKE_DURABLE_MEDIUM_MEMORY_BYTES=$medium_bytes
    LAKE_DURABLE_LARGE_MEMORY_BYTES=$large_bytes
    LAKE_DURABLE_RUNNER_MEM_LIMIT="${runner_container_gib}G"
    LAKE_MEMORY_SIZING="auto-v3"
    LAKE_MEMORY_CAPACITY_GIB="$total_gib"
}

env_file_value() {
    local key="$1"
    awk -F= -v key="$key" '$1 == key {sub(/^[^=]*=/, ""); print; exit}' .env 2>/dev/null || true
}

# Compose's project name for the install at $1: COMPOSE_PROJECT_NAME from the
# environment or the install's .env, else the directory name; lowercased, with
# only [a-z0-9_-] kept, as Compose normalizes it.
install_compose_project() {
    local project="${COMPOSE_PROJECT_NAME:-}"
    if [[ -z "$project" && -f "$1/.env" ]]; then
        project=$(awk -F= '$1 == "COMPOSE_PROJECT_NAME" {sub(/^[^=]*=/, ""); print; exit}' "$1/.env" 2>/dev/null || true)
    fi
    [[ -n "$project" ]] || project=$(basename "$1")
    printf '%s' "$project" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9_-'
}

# NAN-3853: the retired ClickHouse edition (NAN-3491) cannot be upgraded in
# place. Echo why the install at $1 is that edition and return 0, or return 1.
# Runs before the checkout is updated, so it reads only what is on disk and in
# Docker, and changes neither.
#
# A lean .env (COMPOSE_PROFILES=lean) always wins: an install that took the
# fresh-lean cutover keeps its old ClickHouse variables and volumes for
# rollback but is lean. A gen1 lake .env (COMPOSE_PROFILES with `lake`, or
# NANO_LOG_QUERY_BACKEND=lake) is not this edition either; the main flow
# handles it. Otherwise any of these marks the ClickHouse edition:
#   - .env selects the ClickHouse query backend or the `legacy` compose profile
#   - .env carries CLICKHOUSE_PASSWORD (every ClickHouse install wrote it,
#     including those from before compose profiles existed)
#   - this compose project has a clickhouse container or the
#     nano-clickhouse-data volume (Compose creates neither for a lean stack:
#     the clickhouse service and its volume belong to the `legacy` profile)
legacy_clickhouse_reason() {
    local dir="$1" env_file="$1/.env" profiles="" backend="" project ids
    if [[ -f "$env_file" ]]; then
        # Tolerate an operator's CRLF line endings or quoted values.
        profiles=$(awk -F= '$1 == "COMPOSE_PROFILES" {sub(/^[^=]*=/, ""); print; exit}' "$env_file" 2>/dev/null | tr -d '\r"'"'"' ' || true)
        backend=$(awk -F= '$1 == "NANO_LOG_QUERY_BACKEND" {sub(/^[^=]*=/, ""); print; exit}' "$env_file" 2>/dev/null | tr -d '\r"'"'"' ' || true)
        [[ "$profiles" == lean ]] && return 1
        [[ ",${profiles}," == *,lake,* || "$backend" == lake ]] && return 1
        if [[ "$backend" == clickhouse ]]; then
            echo "its .env sets NANO_LOG_QUERY_BACKEND=clickhouse"; return 0
        fi
        if [[ ",${profiles}," == *,legacy,* ]]; then
            echo "its .env selects the legacy ClickHouse compose profile"; return 0
        fi
        if grep -qE '^CLICKHOUSE_PASSWORD=' "$env_file" 2>/dev/null; then
            echo "its .env holds ClickHouse credentials and no lean settings"; return 0
        fi
    fi
    project=$(install_compose_project "$dir")
    [[ -n "$project" ]] || return 1
    ids=$(docker </dev/null ps -aq \
        --filter "label=com.docker.compose.project=${project}" \
        --filter "label=com.docker.compose.service=clickhouse" 2>/dev/null || true)
    if [[ -n "$ids" ]]; then
        echo "Docker has a ClickHouse container for its compose project '${project}'"; return 0
    fi
    if docker </dev/null volume inspect "${project}_nano-clickhouse-data" >/dev/null 2>&1; then
        echo "Docker has its ClickHouse data volume ${project}_nano-clickhouse-data"; return 0
    fi
    return 1
}

# Print why the ClickHouse edition cannot be upgraded and what to do instead,
# then exit non-zero. There is deliberately no override.
refuse_legacy_clickhouse_install() {
    local dir="$1" reason="$2" project stop_cmd
    project=$(install_compose_project "$dir")
    if [[ -f "$dir/$COMPOSE_FILE" ]]; then
        stop_cmd="cd ${dir} && docker compose -f ${COMPOSE_FILE} down"
    else
        stop_cmd="docker compose -p ${project} down"
    fi
    printf "%b✗ %s is the retired ClickHouse edition of nano%b\n" "$c_red$c_bold" "$dir" "$c_reset" >&2
    cat >&2 <<EOF

  Detected because ${reason}.

  This edition cannot be upgraded in place. The current edition stores events
  in an OCSF object lake, not ClickHouse, and is a fresh install: nothing is
  migrated from the old one. This run changed nothing: no update, pull,
  migration, restart, or data change.

  To move to the current edition:

    1. Back up what you want to keep: copy out the detection rules, saved
       searches, and results you need from the web UI, and keep a copy of
       ${dir}/.env (it holds this install's secrets).

    2. Stop the old stack:
         ${stop_cmd}
       Its data volumes (ClickHouse events, PostgreSQL) are kept. Do not add
       -v unless you want that data deleted.

    3. Install the current edition into a new directory, so it gets its own
       volumes and never opens the old ones:
         curl -fsSL https://get.nano.rs | NANO_INSTALL_DIR=\$HOME/nano-lake bash
       To reuse ${dir} instead, first delete the old directory AND its
       volumes (docker volume ls | grep '^${project}_'; deleting them deletes
       the old data), then re-run the installer.

  What happens to your data: the new install starts empty. Events, users,
  rules, dashboards, and cases stay in the old volumes and are not imported.
  They remain on disk until you remove them with docker volume rm.

  To stay on the ClickHouse edition (unsupported, no further fixes), do not
  re-run this installer. Its last source is the legacy/clickhouse branch of
  ${NANO_REPO_URL%.git}, and its last images are tagged 0.1.703.
EOF
    exit 1
}

upsert_env_file_value() {
    local key="$1" value="$2" tmp
    tmp=$(mktemp "${TMPDIR:-/tmp}/nano-env.XXXXXX") \
        || fail "Could not create a temporary file while updating .env."
    awk -F= -v key="$key" -v value="$value" '
        BEGIN { found = 0 }
        $1 == key { if (!found) print key "=" value; found = 1; next }
        { print }
        END { if (!found) print key "=" value }
    ' .env > "$tmp"
    chmod 600 "$tmp"
    mv "$tmp" .env
}

write_lake_memory_plan() {
    upsert_env_file_value NANO_LAKE_MEMORY_SIZING "$LAKE_MEMORY_SIZING"
    upsert_env_file_value NANO_LAKE_MAX_MEMORY_BYTES "$LAKE_MAX_MEMORY_BYTES"
    upsert_env_file_value NANO_LAKE_QUERY_CONTAINER_MEM_LIMIT "$LAKE_QUERY_CONTAINER_MEM_LIMIT"
    upsert_env_file_value NANO_LAKE_DURABLE_MEDIUM_MEMORY_BYTES "$LAKE_DURABLE_MEDIUM_MEMORY_BYTES"
    upsert_env_file_value NANO_LAKE_DURABLE_LARGE_MEMORY_BYTES "$LAKE_DURABLE_LARGE_MEMORY_BYTES"
    upsert_env_file_value NANO_LAKE_DURABLE_RUNNER_MEM_LIMIT "$LAKE_DURABLE_RUNNER_MEM_LIMIT"
}

# Encode a string as a JSON string literal (quotes included).
# Handles backslash, double-quote, and the C0 controls that JSON forbids.
# Pure bash: a fresh host has no Node (NAN-3306 lab: Debian 12 LXC), and a
# `fail` inside the caller's $(...) only exits the subshell, so a missing
# helper used to send `{"email":,...}` and fail admin setup with a 400.
json_escape() {
    local s=$1 out="" c i code
    for (( i = 0; i < ${#s}; i++ )); do
        c=${s:i:1}
        # shellcheck disable=SC1003 # '\' is a literal backslash, not an escaped quote
        case "$c" in
            '"')  out+='\"' ;;
            '\') out+='\\' ;;
            $'\n') out+='\n' ;;
            $'\r') out+='\r' ;;
            $'\t') out+='\t' ;;
            *)
                LC_ALL=C printf -v code '%d' "'$c" 2>/dev/null || code=32
                if (( code >= 0 && code < 32 )); then
                    printf -v c '\\u%04x' "$code"
                fi
                out+=$c
                ;;
        esac
    done
    printf '"%s"' "$out"
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
#   - Third-party  "postgres:18 sha256:…"  (tagged, self-contained) — mirrors
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
# GitHub repo, via the commits API. Needs Node to parse JSON (same
# soft dep). Empty on any failure.
github_lock_commit_shas() {
    local owner_repo json
    owner_repo=$(github_owner_repo) || return 1
    json=$(curl -fsSL -H "Accept: application/vnd.github+json" \
        "https://api.github.com/repos/${owner_repo}/commits?path=images.lock&per_page=100" 2>/dev/null) \
        || return 1
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
    line=$(docker </dev/null image inspect "$1" \
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
    local fp_lockfile="$lockfile" fetched="" want_re
    want_re="${NANO_VERSION#v}"; want_re="${want_re//./\\.}"
    if grep -qE "^# Release: v?${want_re}([^0-9]|\$)" "$lockfile"; then
        : # this checkout's lock is the pinned release's lock
    elif [[ "$NANO_VERSION" != "latest" ]]; then
        if fetched=$(fetch_release_lock "$NANO_VERSION") && [[ -n "$fetched" ]]; then
            fp_lockfile="$fetched"
            ok "Fetched images.lock for pinned release v${NANO_VERSION#v}"
        else
            fp_lockfile=""
            warn "Could not fetch images.lock for pinned NANO_VERSION='$NANO_VERSION' — first-party digests not verified (base images still are)."
        fi
    fi

    log "Verifying pulled image digests against images.lock"
    local ref expected basename repo_notag inspect_ref result active_images
    local mismatch=0 verified_fp=0 verified_tp=0
    active_images=$(docker </dev/null compose -f "$COMPOSE_FILE" config --images 2>/dev/null || true)

    # First-party lines (no tag): inspect repo:NANO_VERSION, from fp_lockfile.
    if [[ -n "$fp_lockfile" ]]; then
        while read -r ref expected; do
            [[ -z "$ref" || "$ref" == \#* ]] && continue
            basename="${ref##*/}"; [[ "$basename" == *:* ]] && continue
            inspect_ref="${ref}:${NANO_VERSION}"; repo_notag="$ref"
            result=$(verify_one_digest "$inspect_ref" "$repo_notag" "$expected")
            case "$result" in
                ok) verified_fp=$((verified_fp + 1)) ;;
                missing)
                    if printf '%s\n' "$active_images" | grep -qxF "$inspect_ref"; then
                        fail "No registry digest found for active image ${inspect_ref} — cannot verify it against images.lock. Refusing to start with unverifiable images."
                    fi
                    warn "Skipping digest verify for ${inspect_ref} — not pulled because its optional profile is inactive." ;;
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
            # NAN-1659: a "missing" third-party image was NOT pulled — i.e. it
            # belongs to an optional compose profile that's off for this install
            # (e.g. tenzir, `profiles: ["tenzir"]`, only pulled when
            # COMPOSE_PROFILES=tenzir). images.lock records every profile's
            # images, but `docker compose pull` only fetches the active set, so
            # the purely-local digest readback finds nothing. That's not a
            # supply-chain risk — the image isn't deployed, and the compose file
            # pins it inline by @sha256 for when the profile IS enabled — so skip
            # it rather than refuse to start. A tampered image that IS running
            # would be present and caught as a "mismatch" below. First-party
            # cores are always deployed, so their "missing" stays fatal.
            missing)
                warn "Skipping digest verify for ${inspect_ref} — not pulled (optional/profile-gated image, not deployed)." ;;
            *) mismatch=1 ;;
        esac
    done < "$lockfile"

    # NAN-2361: the loops above iterate images.lock, so an image the compose
    # actually DEPLOYS but the lock does not record is never considered at all —
    # no warning, no failure, and the summary below still reports a clean
    # verification. Cross-check the other way round: every first-party image in
    # the ACTIVE profile must have a lock line, or it is unverifiable and we
    # refuse rather than pretend. (Third-party images are pinned inline by
    # @sha256 in the compose, so an absent lock line there cannot go unnoticed.)
    local uncovered=""
    if [[ -n "$fp_lockfile" && -f "$fp_lockfile" ]]; then
        while read -r active_ref; do
            # NAN-3604: first-party is ghcr.io/nano-rs/nano-* only (the
            # ghcr.io/nano-rs/vector fork is digest-pinned like third-party).
            [[ "$active_ref" == ghcr.io/nano-rs/nano-* ]] || continue
            repo_notag="${active_ref%:*}"
            awk -v r="$repo_notag" '$1 == r { found = 1 } END { exit !found }' "$fp_lockfile" \
                || uncovered="${uncovered}${repo_notag}"$'\n'
        done <<< "$active_images"
    fi

    [[ -n "$fetched" ]] && rm -f "$fetched"

    if [[ -n "$uncovered" ]]; then
        warn "Deployed by $COMPOSE_FILE but absent from images.lock:"
        while read -r u; do [[ -n "$u" ]] && warn "  $u"; done <<< "$uncovered"
        fail "images.lock does not cover every first-party image this profile deploys, so they cannot be verified against a vouched digest. Regenerate images.lock (build-and-push.yml merge-manifests records one line per built component) or re-run with NANO_SKIP_IMAGE_VERIFY=1 to proceed unverified."
    fi

    if [[ "$mismatch" == "1" ]]; then
        fail "Image digest verification failed: pulled images do not match images.lock. Refusing to start. If you deliberately changed image versions this is expected — otherwise it may indicate a tampered or re-pushed tag."
    fi
    ok "Verified $verified_fp first-party + $verified_tp third-party image digest(s) against images.lock"
}

# NAN-3402: containers read bind-mounted config as non-root users. A checkout
# made under a restrictive umask (077) leaves those files 0600 root-owned, and
# `git reset` does not repair modes of unchanged files, so re-runs stayed
# broken. Open up only TRACKED files under the compose file's bind-mount
# sources (they are public repo content); untracked operator files such as
# TLS keys keep their modes.
ensure_bind_mounts_readable() {
    local compose="$1" src
    local -a sources=()
    while read -r src; do
        [[ -n "$src" && -e "$src" ]] && sources+=("$src")
    done < <(sed -nE 's/^[[:space:]]*-[[:space:]]+\.\/([^:[:space:]]+):.*/\1/p' "$compose" | sort -u)
    (( ${#sources[@]} > 0 )) || return 0
    git ls-files -z -- "${sources[@]}" | xargs -0 chmod go+rX 2>/dev/null || true
    find "${sources[@]}" -type d -exec chmod go+rx {} + 2>/dev/null || true
}

# Bring the stack up, then wait for the API through nginx.
#
# On a fresh lake, `up -d` itself can fail: nano-api depends on
# lake-query-worker being healthy, and the worker only turns healthy once its
# bootstrap generation is admitted. Its healthcheck (start_period 300s, then
# 60 retries x 5s) marks it unhealthy after ~10 min, Compose's dependency wait
# gives up with "dependency failed to start", and nano-api/nginx are left
# Created. That is not fatal on the lake profile: the wait below keeps
# re-running `up -d` until the API answers or the health timeout expires.
start_and_wait_for_api() {
    local timeout
    timeout=$(health_timeout_seconds)
    COMPOSE_RETRY_WHILE_WAITING=0
    log "Starting services"
    if ! compose_up loud; then
        if [[ "${ENABLE_LAKE_CONTROL_PLANE:-0}" == "1" ]]; then
            warn "docker compose up -d did not finish (log: $COMPOSE_UP_LOG). On the lake profile this is expected while lake-query-worker waits for its bootstrap generation; retrying about once a minute while waiting."
            COMPOSE_RETRY_WHILE_WAITING=1
        else
            fail "docker compose up -d failed (log: $COMPOSE_UP_LOG). Check 'docker compose -f $COMPOSE_FILE ps' and logs."
        fi
    fi
    if [[ "${ENABLE_LAKE_CONTROL_PLANE:-0}" == "1" && "${REUSE_ENV:-0}" != "1" ]]; then
        log "Waiting for API to become healthy through nginx (up to $((timeout / 60)) min — a fresh lake waits for the query worker's bootstrap generation, often ~10 min)"
    else
        log "Waiting for API to become healthy through nginx (up to $((timeout / 60)) min — first run includes DB migrations)"
    fi
    if ! wait_for_api_health "${API_BASE}/api/health" "$timeout"; then
        fail "API did not become healthy within $((timeout / 60)) min. Check 'docker compose -f $COMPOSE_FILE logs nano-api nano-nginx' (compose up log: ${COMPOSE_UP_LOG:-none}). Re-running this installer is safe and will finish admin setup (raise NANO_HEALTH_TIMEOUT_SECONDS to wait longer)."
    fi
    # The compose profile also starts the dedicated pull-feed worker. Do not
    # report a successful upgrade while its boot/sandbox/database check fails.
    if docker </dev/null compose -f "$COMPOSE_FILE" config --services | grep -qx connector-runner; then
        local connector_id connector_status connector_start
        connector_start=$(date +%s)
        while :; do
            connector_id=$(docker </dev/null compose -f "$COMPOSE_FILE" ps -q connector-runner)
            connector_status=$(docker </dev/null inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$connector_id" 2>/dev/null || true)
            [[ "$connector_status" == healthy ]] && break
            if (( $(date +%s) - connector_start >= 180 )); then
                fail "Connector runner did not become healthy. Check 'docker compose -f $COMPOSE_FILE logs connector-runner'."
            fi
            sleep 5
        done
        ok "Connector runner healthy"
    fi
    [[ "${COMPOSE_UP_LOG:-/dev/null}" == /dev/null ]] || rm -f "$COMPOSE_UP_LOG"
}

# Health wait for the API through nginx. A fresh lake keeps nano-api unhealthy
# until the query worker admits its bootstrap generation (~10 min on a small
# host), so the lake default is generous; NANO_HEALTH_TIMEOUT_SECONDS
# overrides it. Logs progress once a minute so an unattended run is not silent.
health_timeout_seconds() {
    local timeout="${NANO_HEALTH_TIMEOUT_SECONDS:-}"
    if [[ -z "$timeout" ]]; then
        if [[ "${ENABLE_LAKE_CONTROL_PLANE:-0}" == "1" ]]; then timeout=1800; else timeout=300; fi
    fi
    if [[ ! "$timeout" =~ ^[0-9]+$ ]] || (( timeout == 0 )); then
        fail "NANO_HEALTH_TIMEOUT_SECONDS must be a positive integer number of seconds."
    fi
    echo "$timeout"
}

# `docker compose up -d`, output appended to a temp log (container names and
# status lines only; Compose never prints environment values). $1=loud also
# streams it to the terminal. On success, reload nginx: on a re-run/upgrade
# `up -d` recreates the app containers (new IPs) but leaves nginx as-is, and it
# won't have loaded an updated nginx.conf either, so it would proxy dead old
# IPs and 502 until restarted (NAN-1237). Best-effort.
COMPOSE_UP_LOG=""
compose_up() {
    local mode="${1:-quiet}" rc
    if [[ -z "${COMPOSE_UP_LOG:-}" ]]; then
        COMPOSE_UP_LOG=$(mktemp "${TMPDIR:-/tmp}/nano-compose-up.XXXXXX" 2>/dev/null) || COMPOSE_UP_LOG=/dev/null
    fi
    if [[ "$mode" == "loud" ]]; then
        docker </dev/null compose -f "$COMPOSE_FILE" up -d 2>&1 | tee -a "$COMPOSE_UP_LOG"
        rc=${PIPESTATUS[0]}
    else
        docker </dev/null compose -f "$COMPOSE_FILE" up -d >> "$COMPOSE_UP_LOG" 2>&1
        rc=$?
    fi
    (( rc == 0 )) || return "$rc"
    # container_name is gone (one install per compose project): address nginx by service.
    docker </dev/null compose -f "$COMPOSE_FILE" exec -T nginx nginx -s reload >/dev/null 2>&1 || true
}

# While waiting, COMPOSE_RETRY_WHILE_WAITING=1 re-runs the idempotent
# `up -d` about once a minute (COMPOSE_UP_RETRY_SECONDS). Compose does not
# later start dependents it skipped after a failed dependency wait, so without
# this nano-api/nginx would stay Created even once the query worker turns
# healthy.
wait_for_api_health() {
    local url="$1" timeout="$2" start now next_report next_up pending
    local retry_every="${COMPOSE_UP_RETRY_SECONDS:-60}"
    start=$(date +%s)
    next_report=$((start + 60))
    next_up=$((start + retry_every))
    while :; do
        if curl -fsS -o /dev/null --max-time 10 "$url" 2>/dev/null; then
            ok "API healthy after $(( $(date +%s) - start ))s"
            return 0
        fi
        now=$(date +%s)
        if (( now - start >= timeout )); then
            return 1
        fi
        if [[ "${COMPOSE_RETRY_WHILE_WAITING:-0}" == "1" ]] && (( now >= next_up )); then
            if compose_up quiet; then
                log "docker compose up -d completed — every service has started; waiting for the API."
                COMPOSE_RETRY_WHILE_WAITING=0
            fi
            now=$(date +%s)
            next_up=$((now + retry_every))
        fi
        if (( now >= next_report )); then
            pending=$(docker </dev/null compose -f "$COMPOSE_FILE" ps --format '{{.Name}}={{.Health}}' 2>/dev/null \
                | grep -E '=(starting|unhealthy)$' | tr '\n' ' ' || true)
            log "Still waiting for the API ($(( (now - start) / 60 ))m of $(( timeout / 60 ))m)${pending:+ — not yet healthy: $pending}"
            next_report=$((now + 60))
        fi
        sleep 3
    done
}

# GET /api/setup/status → {"initialized":bool,"has_users":bool}. Echoes
# "initialized" when either is true (POST /api/setup/initialize answers 409 in
# both cases), "pending" when the admin still has to be created. Retries a few
# times; an unreachable endpoint is fatal rather than guessed.
setup_state() {
    local body attempt
    for (( attempt = 0; attempt < 10; attempt++ )); do
        if body=$(curl -fsS --max-time 10 "${API_BASE}/api/setup/status" 2>/dev/null); then
            if grep -Eq '"(initialized|has_users)"[[:space:]]*:[[:space:]]*true' <<< "$body"; then
                echo initialized; return 0
            fi
            if grep -Eq '"initialized"[[:space:]]*:[[:space:]]*false' <<< "$body"; then
                echo pending; return 0
            fi
        fi
        sleep "${SETUP_STATE_RETRY_SECONDS:-3}"
    done
    return 1
}

ADMIN_PASSWORD_POLICY_MSG="Admin password must be 12-1024 characters with at least one uppercase letter, one lowercase letter, one digit, and one special character."

# Resolve the admin credentials for a re-run that finds the system not yet
# initialized (a first run timed out before admin creation, NAN-3402):
# env var → the value the first run recorded in .env → prompt. A password
# autogenerated by the first run is reused from .env, never regenerated, so the
# operator is not handed one that differs from the first run's output.
resolve_rerun_admin_credentials() {
    local stored
    if [[ -z "$ADMIN_EMAIL" ]]; then
        ADMIN_EMAIL=$(env_file_value INITIAL_ADMIN_EMAIL)
        [[ -z "$ADMIN_EMAIL" ]] && ADMIN_EMAIL=$(prompt_tty "Admin email")
        [[ -z "$ADMIN_EMAIL" ]] && fail "The admin account has not been created yet and no admin email is known. Set NANO_ADMIN_EMAIL and re-run."
    fi
    if [[ -z "$ADMIN_NAME" ]]; then
        ADMIN_NAME=$(env_file_value INITIAL_ADMIN_NAME)
        [[ -z "$ADMIN_NAME" ]] && ADMIN_NAME=$(prompt_tty "Admin display name" "Admin")
        [[ -z "$ADMIN_NAME" ]] && ADMIN_NAME="Admin"
    fi
    if [[ -z "$ADMIN_PASSWORD" ]]; then
        stored=$(env_file_value INITIAL_ADMIN_PASSWORD)
        if [[ -n "$stored" ]] && ! password_meets_policy "$stored"; then
            # Installers before NAN-3402 generated hex, which the API rejects;
            # that admin was therefore never created, so nobody can be using
            # it. Replace it rather than leave the re-run stuck.
            warn "The stored INITIAL_ADMIN_PASSWORD predates the password policy fix; generating a compliant one."
            stored=""
            ADMIN_PASSWORD=$(gen_admin_password) || fail "Could not generate an admin password."
            GENERATED_PASSWORD=1
            upsert_env_file_value INITIAL_ADMIN_PASSWORD "$ADMIN_PASSWORD"
        elif [[ -n "$stored" ]]; then
            ADMIN_PASSWORD="$stored"
            GENERATED_PASSWORD=1
        else
            ADMIN_PASSWORD=$(prompt_tty "Admin password (blank = autogenerate)" "" secret)
            if [[ -z "$ADMIN_PASSWORD" ]]; then
                ADMIN_PASSWORD=$(gen_admin_password) || fail "Could not generate an admin password."
                GENERATED_PASSWORD=1
                # Persist before use so a failure below cannot lose it.
                upsert_env_file_value INITIAL_ADMIN_PASSWORD "$ADMIN_PASSWORD"
            fi
        fi
    fi
    password_meets_policy "$ADMIN_PASSWORD" || fail "$ADMIN_PASSWORD_POLICY_MSG"
}

# Create the first admin unless the API says it exists. Idempotent: keyed on
# the live setup status, so a re-run after a timed-out first boot finishes the
# job, and a normal upgrade re-run is a no-op.
bootstrap_admin() {
    local state payload code body_file
    ADMIN_CREATED=0
    state=$(setup_state) \
        || fail "Could not read ${API_BASE}/api/setup/status. Check 'docker compose -f $COMPOSE_FILE logs nano-api'."
    if [[ "$state" == "initialized" ]]; then
        ok "Admin account already exists — skipping admin initialization."
        return 0
    fi
    if [[ "${REUSE_ENV:-0}" == "1" ]]; then
        warn "The admin account was never created (a previous run likely timed out) — creating it now."
        resolve_rerun_admin_credentials
    fi

    log "Creating admin user $ADMIN_EMAIL"
    payload=$(printf '{"email":%s,"name":%s,"password":%s}' \
        "$(json_escape "$ADMIN_EMAIL")" \
        "$(json_escape "$ADMIN_NAME")" \
        "$(json_escape "$ADMIN_PASSWORD")")
    body_file=$(mktemp "${TMPDIR:-/tmp}/nano-setup.XXXXXX") \
        || fail "Could not create a temporary file for the setup response."
    # The payload goes on stdin, not argv, so the password is not visible in ps.
    code=$(curl -sS -o "$body_file" -w '%{http_code}' --max-time 60 -X POST \
        -H "Content-Type: application/json" \
        --data-binary @- \
        "${API_BASE}/api/setup/initialize" <<< "$payload" 2>/dev/null) || code=000
    case "$code" in
        200)
            rm -f "$body_file"
            ok "Admin user created"
            ADMIN_CREATED=1
            ;;
        409)
            rm -f "$body_file"
            warn "System was initialized concurrently — skipping admin creation."
            ;;
        *)
            # The response carries an error code and message, never the password.
            warn "POST /api/setup/initialize returned HTTP $code: $(head -c 500 "$body_file" 2>/dev/null)"
            rm -f "$body_file"
            fail "Admin initialization failed. Fix the cause and re-run this installer; it will retry admin creation. Logs: 'docker compose -f $COMPOSE_FILE logs nano-api'."
            ;;
    esac
}

# ----------------------------------------------------------------------------
# 0. Arguments / interactivity
# ----------------------------------------------------------------------------
while (( $# > 0 )); do
    case "$1" in
        --non-interactive|--noninteractive|--yes|-y) NANO_NONINTERACTIVE=1 ;;
        --tenzir) NANO_INGEST_MODE=tenzir ;;
        --add-vector|--with-vector) NANO_INGEST_MODE=vector ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; fail "Unknown argument: $1" ;;
    esac
    shift
done
case "${NANO_INGEST_MODE:-}" in
    ""|tenzir|vector) ;;
    *) fail "NANO_INGEST_MODE must be 'tenzir' or 'vector' (got '${NANO_INGEST_MODE}')." ;;
esac
# NAN-3853: the ClickHouse edition is retired; it can no longer be installed.
if [[ "${NANO_ENABLE_LAKE_CONTROL_PLANE:-1}" == 0 ]] \
    || [[ "$(printf '%s' "${NANO_SCHEMA_PROFILE:-}" | tr '[:upper:]' '[:lower:]')" == udm ]]; then
    fail "The ClickHouse edition (NANO_ENABLE_LAKE_CONTROL_PLANE=0 / NANO_SCHEMA_PROFILE=udm) is retired and can no longer be installed. Unset both: new installs use the OCSF object lake."
fi
if is_truthy "$NANO_NONINTERACTIVE"; then
    NANO_NONINTERACTIVE=1
else
    NANO_NONINTERACTIVE=0
    if ! tty_usable; then
        NANO_NONINTERACTIVE=1
        warn "No usable terminal — running non-interactively (env values and defaults only)."
    fi
fi

# ----------------------------------------------------------------------------
# 1. Prereq check
# ----------------------------------------------------------------------------
log "Checking prerequisites"

require_cmd docker   "Install Docker: https://docs.docker.com/get-docker/"
require_cmd git      "Install git (most package managers)."
require_cmd openssl  "Install openssl (most distros ship it by default)."
require_cmd curl     "Install curl."
require_cmd python3  "Install Python 3 for lean bootstrap validation."

if ! docker </dev/null compose version >/dev/null 2>&1; then
    fail "docker compose v2 is required. Update Docker or install the compose plugin."
fi

if ! docker </dev/null info >/dev/null 2>&1; then
    fail "Docker daemon is not running or this user can't talk to it. Start Docker and retry."
fi

ok "All prerequisites present"

# NAN-3853: refuse the retired ClickHouse edition before the checkout, .env,
# images, or containers are touched.
if LEGACY_CH_REASON=$(legacy_clickhouse_reason "$NANO_INSTALL_DIR"); then
    refuse_legacy_clickhouse_install "$NANO_INSTALL_DIR" "$LEGACY_CH_REASON"
fi

# ----------------------------------------------------------------------------
# 2. Clone or update the repo
# ----------------------------------------------------------------------------
if [[ -d "$NANO_INSTALL_DIR/.git" ]]; then
    if [[ -n "$(git -C "$NANO_INSTALL_DIR" status --porcelain 2>/dev/null)" ]]; then
        warn "$NANO_INSTALL_DIR has local changes — skipping git update so your edits stay intact."
    else
        log "Updating existing checkout at $NANO_INSTALL_DIR"
        git -C "$NANO_INSTALL_DIR" fetch --depth 1 origin "$NANO_BRANCH"
        # The nano-rs/nano mirror is force-regenerated on every sync, so its
        # history diverges from any prior checkout and can never fast-forward.
        # Hard-reset to the fetched remote HEAD instead. Safe: the clean-tree
        # check above already skips this branch (preserving edits) when there
        # are local changes, so this only resets an unmodified checkout — the
        # authoritative state is always the mirror. (NAN-1929: an ff-only merge
        # left a stale images.lock and then failed digest verification against
        # the freshly-pulled :latest images.)
        git -C "$NANO_INSTALL_DIR" reset --hard FETCH_HEAD \
            || fail "Could not update $NANO_INSTALL_DIR to the latest release. Remove it and re-run to reclone."
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
ensure_bind_mounts_readable "$COMPOSE_FILE"

# ----------------------------------------------------------------------------
# 3. Collect admin info (env first, then interactive)
# ----------------------------------------------------------------------------
ADMIN_EMAIL="${NANO_ADMIN_EMAIL:-}"
ADMIN_NAME="${NANO_ADMIN_NAME:-}"
ADMIN_PASSWORD="${NANO_ADMIN_PASSWORD:-}"
BASE_URL="${NANO_BASE_URL:-http://localhost}"

USE_LEAN=1
FRESH_LEAN_CUTOVER=0
if [[ -f .env ]] && ! grep -qE '^COMPOSE_PROFILES=lean$' .env; then
    if [[ "${NANO_FRESH_LEAN_CUTOVER:-0}" != "1" ]]; then
        fail "This install predates lean. Re-run with NANO_FRESH_LEAN_CUTOVER=1 for a fresh UUID tenant without history adoption. Existing data volumes are retained; see docs/deployment/open-lean-install.md."
    fi
    FRESH_LEAN_CUTOVER=1
    # Retain the prior credentials and stop its processes before selecting lean.
    cp -p .env ".env.pre-lean.$(date -u +%Y%m%dT%H%M%SZ)"
fi

# Pin the image release before any .env is written or reused. An explicit
# NANO_VERSION wins, then a non-latest pin kept in an existing lean .env, then the
# "# Release:" of this checkout's images.lock, which must list the lean cell.
resolve_lean_version() {
    local requested="$NANO_VERSION" release
    if [[ "$requested" == "latest" ]]; then
        warn "NANO_VERSION=latest is frozen on the ClickHouse 0.1.703 release; pinning a lean release instead."
        requested=""
    fi
    # A gen1 install's pin names pre-lean images; a cutover never keeps it.
    if [[ -z "$requested" && -f .env && "$FRESH_LEAN_CUTOVER" != "1" ]]; then
        requested=$(env_file_value NANO_VERSION)
        [[ "$requested" == "latest" ]] && requested=""
    fi
    if [[ -n "$requested" ]]; then
        NANO_VERSION="$requested"
        return 0
    fi
    release=$(sed -nE 's/^# Release: v?([0-9][0-9A-Za-z.+-]*).*$/\1/p' images.lock 2>/dev/null | head -1)
    [[ -n "$release" ]] || fail "images.lock names no release. Set NANO_VERSION to a published lean release."
    if ! grep -qE '^ghcr\.io/nano-rs/nano-lake-cell sha256:' images.lock; then
        fail "Release v${release} in images.lock has no lean lake-cell image; no lean release is published on this branch yet. Set NANO_VERSION to a published lean release."
    fi
    NANO_VERSION="$release"
}
resolve_lean_version
ok "Image release: ${NANO_VERSION}"

if [[ -f .env ]]; then
    warn ".env already exists — keeping existing secrets, will only (re)start the stack."
    # Compose reads the tag from .env: never leave a gen1 `latest` behind.
    upsert_env_file_value NANO_VERSION "$NANO_VERSION"
    REUSE_ENV=1
    chmod 600 .env
    # Show the configured URL in the summary, not the localhost default.
    if [[ -z "${NANO_BASE_URL:-}" ]]; then
        BASE_URL=$(env_file_value BASE_URL)
        BASE_URL="${BASE_URL:-http://localhost}"
    fi
    # NAN-835: pick the existing ingest token out of .env so the success
    # block can re-print it on every install run (not just the first one).
    VECTOR_AUTH_TOKEN=$(grep -E '^VECTOR_AUTH_TOKEN=' .env | head -1 | cut -d= -f2- || true)
    # NAN-1604: read the ingest password back too, so the direct-OCSF block can
    # re-print it on every run.
    CLICKHOUSE_INGEST_PASSWORD=$(grep -E '^CLICKHOUSE_INGEST_PASSWORD=' .env | head -1 | cut -d= -f2- || true)
    # Schema profile is fixed at first install (see below); read it back so the
    # summary reflects the live value. Default udm for .env files predating it.
    SCHEMA_PROFILE=$(grep -E '^NANO_SCHEMA_PROFILE=' .env | head -1 | cut -d= -f2- || true)
    SCHEMA_PROFILE="${SCHEMA_PROFILE:-udm}"
    # NAN-1604: did the first install bundle the Tenzir node? (COMPOSE_PROFILES=tenzir)
    BUNDLE_TENZIR=0
    grep -qE '^COMPOSE_PROFILES=.*tenzir' .env 2>/dev/null && BUNDLE_TENZIR=1
    # Never turn the lake on implicitly for an existing UDM/ClickHouse install.
    # If the operator already enabled it, preserve it; otherwise activate the
    # explicit legacy profile required by the mutually-exclusive compose lanes.
    ENABLE_LAKE_CONTROL_PLANE=0
    grep -qE '^COMPOSE_PROFILES=.*(lake|lean)' .env 2>/dev/null && ENABLE_LAKE_CONTROL_PLANE=1

    # NAN-2252: only the maintenance-only legacy profile owns ClickHouse.
    if [[ "$ENABLE_LAKE_CONTROL_PLANE" != "1" ]] && ! grep -qE '^CLICKHOUSE_MEM_LIMIT=' .env; then
        CH_MEM_LIMIT=$(ch_mem_limit)
        log "Sized ClickHouse memory limit to $CH_MEM_LIMIT (Docker RAM − 4G reserve, 2G floor)"
        echo "CLICKHOUSE_MEM_LIMIT=$CH_MEM_LIMIT" >> .env
    fi

    if [[ "$ENABLE_LAKE_CONTROL_PLANE" == "1" && "$BUNDLE_TENZIR" == "1" ]]; then
        fail "The bundled Tenzir-to-ClickHouse profile (ocsf+tenzir) was removed with ClickHouse. Re-run with --tenzir for a Tenzir-direct install: Tenzir writes OCSF files into the object store (tenzir/AGENTS.md)."
    elif [[ "$ENABLE_LAKE_CONTROL_PLANE" == "1" ]]; then
        upsert_env_file_value COMPOSE_PROFILES lake
        upsert_env_file_value NANO_LOG_QUERY_BACKEND lake
    elif [[ "$BUNDLE_TENZIR" == "1" ]]; then
        upsert_env_file_value COMPOSE_PROFILES legacy,tenzir
    else
        upsert_env_file_value COMPOSE_PROFILES legacy
    fi
    if [[ "$ENABLE_LAKE_CONTROL_PLANE" != "1" ]]; then
        # NAN-3491: compose now defaults to lake + OCSF; pin a legacy .env to
        # the values it previously inherited from the compose defaults.
        upsert_env_file_value NANO_LOG_QUERY_BACKEND clickhouse
        upsert_env_file_value NANO_SCHEMA_PROFILE "$SCHEMA_PROFILE"
    fi

    if [[ "$ENABLE_LAKE_CONTROL_PLANE" == "1" ]]; then
        # Backfill secrets introduced after the first lake beta without
        # rotating any established credential. A literal CHANGE_ME is not an
        # installer-generated value and is rejected later by the profile guard.
        lake_secret_keys=(
            NANO_LAKE_ENRICHMENT_TOKEN
            NANO_OTEL_LAKE_INGEST_TOKEN
            NANO_OTEL_LAKE_QUERY_TOKEN
        )
        for key in "${lake_secret_keys[@]}"; do
            if [[ -z "$(env_file_value "$key")" ]]; then
                upsert_env_file_value "$key" "$(gen_secret)"
                log "Generated missing $key for the upgraded lake profile"
            fi
        done
        lake_memory_keys=(
            NANO_LAKE_MAX_MEMORY_BYTES
            NANO_LAKE_QUERY_CONTAINER_MEM_LIMIT
            NANO_LAKE_DURABLE_MEDIUM_MEMORY_BYTES
            NANO_LAKE_DURABLE_LARGE_MEMORY_BYTES
            NANO_LAKE_DURABLE_RUNNER_MEM_LIMIT
        )
        lake_memory_count=0
        for key in "${lake_memory_keys[@]}"; do
            grep -qE "^${key}=" .env && lake_memory_count=$((lake_memory_count + 1))
        done
        lake_memory_mode=$(env_file_value NANO_LAKE_MEMORY_SIZING)

        if (( lake_memory_count != 0 && lake_memory_count != 5 )); then
            fail "Existing .env has a partial lake memory plan. Define all five NANO_LAKE_* memory settings or remove them and rerun for automatic sizing."
        elif [[ "$lake_memory_mode" == auto-v[123] || "$lake_memory_count" == "0" ]]; then
            lake_memory_plan
            write_lake_memory_plan
            log "Lake memory plan: interactive ${LAKE_MAX_MEMORY_BYTES} bytes/${LAKE_QUERY_CONTAINER_MEM_LIMIT} container, durable ${LAKE_DURABLE_MEDIUM_MEMORY_BYTES} → ${LAKE_DURABLE_LARGE_MEMORY_BYTES} bytes/${LAKE_DURABLE_RUNNER_MEM_LIMIT} container (${LAKE_MEMORY_CAPACITY_GIB} GiB Docker capacity)"
        elif [[ -z "$lake_memory_mode" ]]; then
            # Pre-auto-sizing beta installs already have all five values. They
            # may be operator-tuned, so do not silently replace them.
            upsert_env_file_value NANO_LAKE_MEMORY_SIZING manual
            warn "Preserving the existing lake memory limits as manual overrides. Remove the five values plus NANO_LAKE_MEMORY_SIZING to adopt automatic sizing."
        fi
    fi
else
    REUSE_ENV=0
    log "Configuring first-time admin account"

    [[ -z "$ADMIN_EMAIL" ]]    && ADMIN_EMAIL=$(prompt_tty "Admin email")
    [[ -z "$ADMIN_EMAIL" ]]    && fail "Admin email is required (set NANO_ADMIN_EMAIL for unattended installs)."

    [[ -z "$ADMIN_NAME" ]]     && ADMIN_NAME=$(prompt_tty "Admin display name" "Admin")
    [[ -z "$ADMIN_NAME" ]]     && fail "Admin name is required."

    if [[ -z "$ADMIN_PASSWORD" ]]; then
        ADMIN_PASSWORD=$(prompt_tty "Admin password (blank = autogenerate)" "" secret)
        if [[ -z "$ADMIN_PASSWORD" ]]; then
            # NAN-3402: hex never satisfied the API's complexity policy.
            ADMIN_PASSWORD=$(gen_admin_password) || fail "Could not generate an admin password."
            GENERATED_PASSWORD=1
        fi
    fi
    # Same policy the API enforces — fail now, not after the first-boot wait.
    password_meets_policy "$ADMIN_PASSWORD" || fail "$ADMIN_PASSWORD_POLICY_MSG"

    # NAN-3402: an explicit NANO_BASE_URL is the answer; never prompt over it.
    [[ -z "${NANO_BASE_URL:-}" ]] && BASE_URL=$(prompt_tty "Public base URL" "$BASE_URL")

    # Plain-HTTP deployments need NANOSIEM_DEV_MODE=true so the auth refresh
    # cookie is set without the Secure flag — otherwise browsers silently
    # drop it and the user is bounced to /login every ~15 min (NAN-807 bug #12).
    if [[ "$BASE_URL" == http://* ]]; then
        DEV_MODE=true
        warn "BASE_URL is http:// — enabling NANOSIEM_DEV_MODE so login cookies work over plain HTTP."
    else
        DEV_MODE=false
    fi

    # Storage schema profile — OCSF (canonical lake) or, on the unsupported
    # legacy ClickHouse branch only, UDM. This picks the tables, parsers, and
    # field universe the whole stack runs against, so it CANNOT be changed after the first event is ingested
    # (switching repoints search/detection to a different, empty table). Pinned
    # in .env on first install and never re-prompted on later runs.
    # NAN-1604: 'ocsf+tenzir' = the OCSF profile PLUS a bundled Tenzir node
    # (compose `tenzir` profile) pre-wired to the native OCSF entrypoint, for
    # direct ingestion. It resolves to NANO_SCHEMA_PROFILE=ocsf + BUNDLE_TENZIR=1.
    BUNDLE_TENZIR=0
    ENABLE_LAKE_CONTROL_PLANE="${NANO_ENABLE_LAKE_CONTROL_PLANE:-1}"
    case "$ENABLE_LAKE_CONTROL_PLANE" in
        0|1) ;;
        *) fail "NANO_ENABLE_LAKE_CONTROL_PLANE must be 0 or 1." ;;
    esac
    SCHEMA_PROFILE="${NANO_SCHEMA_PROFILE:-}"
    if [[ -z "$SCHEMA_PROFILE" && "$ENABLE_LAKE_CONTROL_PLANE" == "1" ]]; then
        SCHEMA_PROFILE=ocsf
        log "Using the canonical OCSF 1.9 object-lake profile"
    elif [[ -z "$SCHEMA_PROFILE" ]]; then
        while :; do
            SCHEMA_PROFILE=$(prompt_tty \
                "Schema profile — 'ocsf' (recommended) or 'udm' (legacy CIM-style, unsupported)" "ocsf")
            SCHEMA_PROFILE=$(printf '%s' "$SCHEMA_PROFILE" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
            case "$SCHEMA_PROFILE" in
                ""|ocsf)     SCHEMA_PROFILE=ocsf; break ;;
                udm)         break ;;
                ocsf+tenzir) fail "The bundled Tenzir-to-ClickHouse profile (ocsf+tenzir) was removed with ClickHouse. Re-run with --tenzir for a Tenzir-direct install: Tenzir writes OCSF files into the object store (tenzir/AGENTS.md)." ;;
                *) warn "Enter 'ocsf' or 'udm'." ;;
            esac
        done
    else
        SCHEMA_PROFILE=$(printf '%s' "$SCHEMA_PROFILE" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
        case "$SCHEMA_PROFILE" in
            udm|ocsf)    ;;
            ocsf+tenzir) fail "The bundled Tenzir-to-ClickHouse profile (ocsf+tenzir) was removed with ClickHouse. Re-run with --tenzir for a Tenzir-direct install: Tenzir writes OCSF files into the object store (tenzir/AGENTS.md)." ;;
            *) fail "NANO_SCHEMA_PROFILE must be 'udm' or 'ocsf' (got '$SCHEMA_PROFILE')." ;;
        esac
    fi
    if [[ "$ENABLE_LAKE_CONTROL_PLANE" == "1" && "$SCHEMA_PROFILE" != "ocsf" ]]; then
        fail "The canonical object lake requires NANO_SCHEMA_PROFILE=ocsf. UDM is maintenance-only and remains on the legacy ClickHouse profile."
    fi
    if [[ "$ENABLE_LAKE_CONTROL_PLANE" == "1" && "$BUNDLE_TENZIR" == "1" ]]; then
        fail "The bundled Tenzir-to-ClickHouse profile (ocsf+tenzir) was removed with ClickHouse. Re-run with --tenzir for a Tenzir-direct install: Tenzir writes OCSF files into the object store (tenzir/AGENTS.md)."
    fi

    log "Generating secrets and writing .env"
    # NAN-835: bind the ingest token to a shell var so the success block can
    # surface it. (Other secrets stay inline — they aren't user-facing.)
    VECTOR_AUTH_TOKEN=$(gen_secret)
    if [[ "$ENABLE_LAKE_CONTROL_PLANE" == "1" ]]; then
        lake_memory_plan
        log "Lake memory plan: interactive ${LAKE_MAX_MEMORY_BYTES} bytes/${LAKE_QUERY_CONTAINER_MEM_LIMIT} container, durable ${LAKE_DURABLE_MEDIUM_MEMORY_BYTES} → ${LAKE_DURABLE_LARGE_MEMORY_BYTES} bytes/${LAKE_DURABLE_RUNNER_MEM_LIMIT} container (${LAKE_MEMORY_CAPACITY_GIB} GiB Docker capacity)"
    else
        # NAN-1604: surface the native ClickHouse ingest credential only on the
        # maintenance-only legacy profile.
        CLICKHOUSE_INGEST_PASSWORD=$(gen_secret)
        CH_MEM_LIMIT=$(ch_mem_limit)
        log "Sized ClickHouse memory limit to $CH_MEM_LIMIT (Docker RAM − 4G reserve, 2G floor)"
    fi
    # Create .env 0600 before any secret is written (umask is 022 above).
    ( umask 077; : > .env )
    chmod 600 .env
    cat > .env <<EOF
NANO_VERSION=$NANO_VERSION
BASE_URL=$BASE_URL
NANOSIEM_DEV_MODE=$DEV_MODE
NANO_SCHEMA_PROFILE=$SCHEMA_PROFILE
POSTGRES_PASSWORD=$(gen_secret)
JWT_SECRET=$(gen_secret)
NANOSIEM_ENCRYPTION_KEY=$(gen_secret)
VECTOR_AUTH_TOKEN=$VECTOR_AUTH_TOKEN
RUST_LOG=info
EOF
    if [[ "${ENABLE_LAKE_CONTROL_PLANE:-0}" == "1" ]]; then
        cat >> .env <<EOF

# NAN-2361 canonical OCSF 1.9 object-lake runtime. The mutually-exclusive
# The lake compose profile starts no ClickHouse service or migrator.
NANO_LAKE_ACCESS_KEY_ID=$(gen_secret)
NANO_LAKE_SECRET_ACCESS_KEY=$(gen_secret)
NANO_LAKE_ENTITY_HMAC_KEY=$(gen_secret)
NANO_LAKE_QUERY_TOKEN=$(gen_secret)
NANO_LAKE_ENRICHMENT_TOKEN=$(gen_secret)
NANO_OTEL_LAKE_INGEST_TOKEN=$(gen_secret)
NANO_OTEL_LAKE_QUERY_TOKEN=$(gen_secret)
NANO_LAKE_TENANT_ID=default
NANO_LAKE_EVENT_TABLE=default.events
NANO_LAKE_EVENT_TABLE_LOCATION_PREFIX=s3://nano-lake/warehouse/default/events/
NANO_LAKE_WORKER_SOURCE=http://lake-object-store:9000/nano-lake/warehouse/default/events
NANO_LOG_QUERY_BACKEND=lake
NANO_LAKE_BRONZE_BUCKET=nano-lake
NANO_LAKE_OBJECT_ENDPOINT=http://lake-object-store:9000
NANO_LAKE_FORCE_PATH_STYLE=true
NANO_LAKE_MEMORY_SIZING=$LAKE_MEMORY_SIZING
NANO_LAKE_MAX_MEMORY_BYTES=$LAKE_MAX_MEMORY_BYTES
NANO_LAKE_QUERY_CONTAINER_MEM_LIMIT=$LAKE_QUERY_CONTAINER_MEM_LIMIT
NANO_LAKE_DURABLE_MEDIUM_MEMORY_BYTES=$LAKE_DURABLE_MEDIUM_MEMORY_BYTES
NANO_LAKE_DURABLE_LARGE_MEMORY_BYTES=$LAKE_DURABLE_LARGE_MEMORY_BYTES
NANO_LAKE_DURABLE_RUNNER_MEM_LIMIT=$LAKE_DURABLE_RUNNER_MEM_LIMIT
NANO_LAKEKEEPER_DB_PASSWORD=$(gen_secret)
NANO_LAKEKEEPER_OIDC_DB_PASSWORD=$(gen_secret)
NANO_LAKEKEEPER_OPENFGA_DB_PASSWORD=$(gen_secret)
NANO_LAKEKEEPER_ENCRYPTION_KEY=$(gen_secret)
NANO_LAKEKEEPER_OIDC_SYSTEM_SECRET=$(gen_secret)
NANO_LAKEKEEPER_OIDC_PAIRWISE_SALT=$(gen_secret)
NANO_LAKEKEEPER_OPERATOR_CLIENT_SECRET=$(gen_secret)
NANO_LAKEKEEPER_RUNTIME_CLIENT_SECRET=$(gen_secret)
NANO_LAKEKEEPER_OPENFGA_PRESHARED_KEY=$(gen_secret)
EOF
    else
        cat >> .env <<EOF

# Unsupported legacy UDM/ClickHouse runtime.
NANO_LOG_QUERY_BACKEND=clickhouse
CLICKHOUSE_MEM_LIMIT=$CH_MEM_LIMIT
CLICKHOUSE_PASSWORD=$(gen_secret)
CLICKHOUSE_ADMIN_PASSWORD=$(gen_secret)
CLICKHOUSE_INGEST_PASSWORD=$CLICKHOUSE_INGEST_PASSWORD
CLICKHOUSE_RAWSQL_PASSWORD=$(gen_secret)
CLICKHOUSE_RAWSQL_NOAUDIT_PASSWORD=$(gen_secret)
EOF
    fi
    if [[ "${BUNDLE_TENZIR:-0}" == "1" ]]; then
        echo "COMPOSE_PROFILES=legacy,tenzir" >> .env
    elif [[ "${ENABLE_LAKE_CONTROL_PLANE:-0}" == "1" ]]; then
        echo "COMPOSE_PROFILES=lake" >> .env
    else
        echo "COMPOSE_PROFILES=legacy" >> .env
    fi
    chmod 600 .env

    # Persist the autogenerated admin password BEFORE the docker pull so a
    # mid-install failure doesn't lose it (NAN-807 bug #9). User-supplied
    # passwords are already known to the user — only stash the generated ones.
    # NAN-3402: the email/name are recorded too, so a re-run after a first-boot
    # timeout can still create the admin without re-asking. .env is parsed by
    # Compose (unquoted, `$` interpolated, `#` comments), so a value with any
    # other character is not recorded; such a re-run asks for it again.
    printf '\n# Initial admin account, used by install.sh re-runs until the account exists.\n' >> .env
    for kv in "INITIAL_ADMIN_EMAIL=$ADMIN_EMAIL" "INITIAL_ADMIN_NAME=$ADMIN_NAME"; do
        if [[ "${kv#*=}" =~ ^[A-Za-z0-9@._+\ -]+$ ]]; then
            printf '%s\n' "$kv" >> .env
        fi
    done
    if [[ "${GENERATED_PASSWORD:-0}" == "1" ]]; then
        cat >> .env <<EOF
# Autogenerated initial admin password — printed by install.sh on success.
# Safe to delete once you've signed in and confirmed the credentials.
INITIAL_ADMIN_PASSWORD=$ADMIN_PASSWORD
EOF
    fi

    ok "Wrote .env (mode 600)"
fi

if [[ "$USE_LEAN" == "1" ]]; then
    if [[ "$FRESH_LEAN_CUTOVER" == "1" ]]; then
        ENABLE_LAKE_CONTROL_PLANE=1
        BUNDLE_TENZIR=0
    fi
    [[ "${BUNDLE_TENZIR:-0}" == "0" ]] || fail "The bundled Tenzir-to-ClickHouse profile (ocsf+tenzir) was removed with ClickHouse. Re-run with --tenzir for a Tenzir-direct install: Tenzir writes OCSF files into the object store (tenzir/AGENTS.md)."
    [[ "${ENABLE_LAKE_CONTROL_PLANE:-0}" == "1" ]] \
        || fail "Open lean requires OCSF lake storage."
    # NAN-3807: the ingest mode. Vector and the connector runner carry the
    # compose profile ${NANO_VECTOR_PROFILE:-lean}; `none` leaves them out of
    # the lean stack (Tenzir-direct). A re-run without a flag keeps the mode.
    NANO_VECTOR_PROFILE=$(resolve_vector_profile)
    upsert_env_file_value NANO_VECTOR_PROFILE "$NANO_VECTOR_PROFILE"
    if [[ "$NANO_VECTOR_PROFILE" == none ]]; then
        TENZIR_DIRECT=1
        log "Ingest mode: Tenzir-direct (no Vector; OCSF bucket drop only)"
    else
        TENZIR_DIRECT=0
        log "Ingest mode: Vector plus the OCSF bucket drop"
    fi
    for key in NANO_LAKE_ACCESS_KEY_ID NANO_LAKE_SECRET_ACCESS_KEY NANO_LAKE_ENRICHMENT_TOKEN NANO_OTEL_LAKE_INGEST_TOKEN NANO_OTEL_LAKE_QUERY_TOKEN NANO_LOCAL_AUDIT_TOKEN; do
        [[ -n "$(env_file_value "$key")" ]] || upsert_env_file_value "$key" "$(gen_secret)"
    done
    upsert_env_file_value COMPOSE_PROFILES lean
    upsert_env_file_value NANO_SCHEMA_PROFILE ocsf
    upsert_env_file_value NANO_LOG_QUERY_BACKEND lake
    # The dedicated cell route (lake-cell.env) is the only lake backend; an
    # inherited gen1 query URL would be refused alongside it.
    upsert_env_file_value NANO_LAKE_QUERY_URL ''
    upsert_env_file_value NANO_OTEL_LAKE_HOST lean-otel
    upsert_env_file_value NANO_LAKE_ENRICHMENT_HOST lean-enrichment
    upsert_env_file_value NANO_OTEL_LAKE_QUERY_TOKEN_FILE /etc/nano-lake-cell/otel-query.token
    upsert_env_file_value NANO_LAKE_ENRICHMENT_COORDINATOR_TOKEN_FILE /etc/nano-lake-cell/enrichment.token
    upsert_env_file_value NANO_LAKE_BRONZE_BUCKET nano-lake
    upsert_env_file_value NANO_LAKE_OBJECT_ENDPOINT http://lake-object-store:9000
    upsert_env_file_value NANO_LAKE_FORCE_PATH_STYLE true
    # Host-side port/bind overrides given to the installer must survive a
    # later plain `docker compose up`, which reads only .env.
    for key in NANO_LAKE_OBJECT_PORT NANO_LAKE_CONSOLE_PORT NANO_OTLP_BIND_ADDRESS NANO_VECTOR_NATIVE_BIND_ADDRESS NANO_FLUENT_BIND_ADDRESS; do
        if [[ -n "${!key:-}" ]]; then upsert_env_file_value "$key" "${!key}"; fi
    done
    SCHEMA_PROFILE=ocsf
    # The bundled Tenzir node's pipeline (compose profile `tenzir`, started
    # only on request). Seed it with the example once; it is the operator's
    # file afterwards and git-ignored, so updates never touch it.
    if [[ ! -e .nano-tenzir/pipeline.tql && -f tenzir/lean/sysmon-bucket.tql ]]; then
        # The pasted sink carries a key: the directory is private to this
        # user; the file stays readable for the container's own user.
        mkdir -p .nano-tenzir
        chmod 700 .nano-tenzir
        cp tenzir/lean/sysmon-bucket.tql .nano-tenzir/pipeline.tql
        chmod 644 .nano-tenzir/pipeline.tql
    fi
    mkdir -p .nano-tenzir/data
    chmod 755 .nano-tenzir/data
    mkdir -p .nano-lean
    chmod 700 .nano-lean
    if [[ "$FRESH_LEAN_CUTOVER" == "1" ]]; then
        : > .nano-lean/cutover-pending
    elif [[ -f .nano-lean/cutover-pending ]]; then
        FRESH_LEAN_CUTOVER=1
    fi
fi

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
if [[ "${BUNDLE_TENZIR:-0}" == "1" ]]; then
    export COMPOSE_PROFILES=legacy,tenzir
elif [[ "${USE_LEAN:-0}" == "1" ]]; then
    export COMPOSE_PROFILES=lean
    # The shell wins over .env in compose interpolation: export the resolved mode.
    export NANO_VECTOR_PROFILE="${NANO_VECTOR_PROFILE:-lean}"
elif [[ "${ENABLE_LAKE_CONTROL_PLANE:-0}" == "1" ]]; then
    export COMPOSE_PROFILES=lake
else
    export COMPOSE_PROFILES=legacy
fi

# ----------------------------------------------------------------------------
# 3b. PostgreSQL major-version preflight
# ----------------------------------------------------------------------------
# A PostgreSQL server refuses to open a data directory written by a different
# major version. Because `postgres` is restart: unless-stopped, that otherwise
# surfaces five minutes later as "API did not become healthy", pointing at
# nano-api/nginx rather than at the database that never came up. The compose
# `postgres-version-guard` blocks the actual start; this runs the same check
# before the multi-GB pull so an upgrader is not made to wait for it.
if [[ -x ./scripts/preflight-postgres-major.sh ]]; then
    ./scripts/preflight-postgres-major.sh -f "$COMPOSE_FILE" \
        || fail "PostgreSQL major-version mismatch — see the migration command above. Nothing was changed."
else
    warn "scripts/preflight-postgres-major.sh not found — skipping the PostgreSQL major-version preflight."
fi

if [[ "${NANO_SKIP_IMAGE_PULL:-0}" == "1" ]]; then
    # Air-gapped or locally built images (`docker load` / local build) already
    # tagged ${NANO_VERSION}. Digest verification still runs unless
    # NANO_SKIP_IMAGE_VERIFY=1 is set too.
    warn "NANO_SKIP_IMAGE_PULL=1 — using images already present locally."
elif log "Pulling images from ghcr.io/nano-rs (this may take a minute on first run)" \
    && ! docker </dev/null compose -f "$COMPOSE_FILE" pull; then
    fail "docker compose pull failed. A '403 Forbidden' on ghcr.io/token (or '401 Unauthorized') means that GHCR package is not public yet — the error names the repository. Run 'docker login ghcr.io' if you have access, or wait for nano-rs to publish it."
fi

verify_image_digests

if [[ "$USE_LEAN" == "1" ]]; then
    if [[ "$FRESH_LEAN_CUTOVER" == "1" ]]; then
        # Keep prior processes available until every required image is vouched.
        # .env already selects the lean profile, so a plain `down` skips the
        # gen1 legacy/tenzir services (ClickHouse, its migrator, Tenzir): they
        # are still defined, so not orphans, and would keep running beside
        # lean. Stop every profile; volumes are retained for rollback.
        docker </dev/null compose -f "$COMPOSE_FILE" --profile '*' down --remove-orphans
    fi
    log "Initializing the trusted-local UUID tenant using the cell initializer"
    docker </dev/null compose -f "$COMPOSE_FILE" run --rm --no-deps -e NANO_LEAN_FRESH_TENANT="$FRESH_LEAN_CUTOVER" lean-init \
        || fail "Lean initializer failed. No services have started."
    # A retry after initializer completion reuses its UUID rather than rotating again.
    if [[ -f .nano-lean/cutover-pending ]]; then
        python3 -c 'from pathlib import Path; Path(".nano-lean/cutover-pending").unlink()'
    fi
    LEAN_TENANT_ID=$(cat .nano-lean/tenant_id)
    upsert_env_file_value NANO_LAKE_TENANT_ID "$LEAN_TENANT_ID"
    upsert_env_file_value NANO_TENANT_ID "$LEAN_TENANT_ID"
    # Dedicated Redis keys are installation-wide. A fresh tenant must not load
    # the former gen1 job snapshots; keep that prior volume for rollback.
    LEAN_DRAGONFLY_VOLUME="${COMPOSE_PROJECT_NAME:-nano}_lean-dragonfly-${LEAN_TENANT_ID}"
    upsert_env_file_value NANO_DRAGONFLY_DATA_VOLUME "$LEAN_DRAGONFLY_VOLUME"
    upsert_env_file_value NANO_DRAGONFLY_VOLUME nano-lean-dragonfly
    export NANO_LAKE_TENANT_ID="$LEAN_TENANT_ID" NANO_TENANT_ID="$LEAN_TENANT_ID"
    export NANO_DRAGONFLY_DATA_VOLUME="$LEAN_DRAGONFLY_VOLUME" NANO_DRAGONFLY_VOLUME=nano-lean-dragonfly
    # Coarse container backstop for the watchdog-enforced role limits: the
    # memory budget lean-init sized the roles from (query 50 %, ingest 25 %,
    # detect 15 %; the rest is the supervisor and fixed product/maintenance).
    LEAN_CELL_MEM_LIMIT=$(python3 - .nano-lean/cell/placement.json <<'PYMEM'
import json, sys
tenant = json.load(open(sys.argv[1]))['tenants'][0]
roles = sum(tenant[f'{role}_limit_memory_bytes'] for role in ('query', 'ingest', 'detect'))
mib = 1 << 20
print(-(-roles * 10 // 9 // mib) * mib)
PYMEM
) || fail "Could not size the lake cell memory limit from .nano-lean/cell/placement.json."
    upsert_env_file_value NANO_LAKE_CELL_MEM_LIMIT "$LEAN_CELL_MEM_LIMIT"
    export NANO_LAKE_CELL_MEM_LIMIT="$LEAN_CELL_MEM_LIMIT"
    # NAN-3492: nano-jobs decodes each lake rule window in-process (budgeted
    # to 40 % of its own limit), so it scales with the placed detect budget:
    # a quarter of the detect role's limit, 1 GiB floor (512M OOM-killed a
    # clean install), 4 GiB cap. An operator's NANO_JOBS_MEM_LIMIT wins.
    if [[ -n "${NANO_JOBS_MEM_LIMIT:-}" ]]; then
        [[ "$NANO_JOBS_MEM_LIMIT" =~ ^[0-9]+([.][0-9]+)?[KMGT]?[iI]?[bB]?$ ]] \
            || fail "NANO_JOBS_MEM_LIMIT is not a Docker memory value."
        LEAN_JOBS_MEM_LIMIT="$NANO_JOBS_MEM_LIMIT"
    else
        LEAN_JOBS_MEM_LIMIT=$(python3 - .nano-lean/cell/placement.json <<'PYJOBS'
import json, sys
tenant = json.load(open(sys.argv[1]))['tenants'][0]
mib, gib = 1 << 20, 1 << 30
detect = tenant.get('detect_limit_memory_bytes') or 0
print(f'{min(max(detect // 4, gib), 4 * gib) // mib}M')
PYJOBS
) || fail "Could not size the nano-jobs memory limit from .nano-lean/cell/placement.json."
    fi
    upsert_env_file_value NANO_JOBS_MEM_LIMIT "$LEAN_JOBS_MEM_LIMIT"
    export NANO_JOBS_MEM_LIMIT="$LEAN_JOBS_MEM_LIMIT"
    log "Sized nano-jobs memory limit to $LEAN_JOBS_MEM_LIMIT"
    log "Probing cell isolation; missing Landlock warns on trusted-local only"
    LEAN_PROBE_LOG=$(mktemp "${TMPDIR:-/tmp}/nano-lean-probe.XXXXXX")
    if ! docker </dev/null compose -f "$COMPOSE_FILE" run --rm --no-deps --entrypoint nanosiem-lake-cell lake-cell \
        probe --write --config /etc/nano-cell/cell.json > "$LEAN_PROBE_LOG"; then
        rm -f "$LEAN_PROBE_LOG"
        fail "Cell isolation probe failed."
    fi
    if ! python3 - "$LEAN_PROBE_LOG" <<'PYPROBE'
import json, sys
with open(sys.argv[1]) as file:
    report = json.load(file)
if report['identity']['fatal'] or report['selected'].get('mode') is None:
    print('Cell isolation probe refused this host: ' + report['selected']['why'], file=sys.stderr)
    sys.exit(1)
if report['selected'].get('mode') == 'watchdog':
    print('Cell isolation: watchdog limits (add docker-compose.lean-cgroup-limits.yml for kernel cgroup limits)')
else:
    print('Cell isolation: ' + report['selected']['why'])
PYPROBE
    then
        rm -f "$LEAN_PROBE_LOG"
        fail "Cell isolation is unsupported on this host."
    fi
    rm -f "$LEAN_PROBE_LOG"
    ok "Lean tenant initialized; the existing history remains outside the new tenant"
fi

# Existing single-host lake installs need a staged query/compiler rollout.
# The generation manager publishes an immutable config pinned to the pulled
# compiler before the only query worker and its durable runner are replaced.
# Fresh installs have no serving process to preserve and fall through to the
# normal Compose bootstrap below.
if [[ "${USE_LEAN:-0}" != "1" && "${REUSE_ENV:-0}" == "1" && "${ENABLE_LAKE_CONTROL_PLANE:-0}" == "1" ]]; then
    log "Staging the lake query/compiler upgrade"
    if ! ./scripts/rollout-lake-runtime.sh -f "$COMPOSE_FILE"; then
        fail "Lake runtime rollout failed before the general service update. The prior loaded generation remains the recovery target; inspect lake-generation-manager and lake-query-worker logs."
    fi
fi

# ----------------------------------------------------------------------------
# 5. Start services and wait for API health (lake: tolerant of a slow first
#    boot, see start_and_wait_for_api)
# ----------------------------------------------------------------------------
if [[ "${TENZIR_DIRECT:-0}" == "1" ]]; then
    # Switching an existing install to Tenzir-direct: Vector and the connector
    # runner are no longer in the stack, so `up -d` would leave their old
    # containers running. Remove them; their volumes stay for --add-vector.
    docker </dev/null compose -f "$COMPOSE_FILE" --profile '*' rm -sf vector connector-runner >/dev/null 2>&1 || true
fi
start_and_wait_for_api

# ----------------------------------------------------------------------------
# 6. Initialize admin user — keyed on the live setup status, not on .env
# ----------------------------------------------------------------------------
bootstrap_admin

# ----------------------------------------------------------------------------
# 7. Done
# ----------------------------------------------------------------------------
echo
printf "%bnano is up.%b\n" "$c_green$c_bold" "$c_reset"
echo
printf "  Open:     %s\n" "$BASE_URL"
[[ -z "$ADMIN_EMAIL" ]] && ADMIN_EMAIL=$(env_file_value INITIAL_ADMIN_EMAIL)
printf "  Login:    %s\n" "${ADMIN_EMAIL:-(existing user)}"
printf "  Schema:   %s\n" "$(printf '%s' "${SCHEMA_PROFILE:-ocsf}" | tr '[:lower:]' '[:upper:]')"
if [[ "$NANO_NONINTERACTIVE" != "1" && "${GENERATED_PASSWORD:-0}" == "1" && "${ADMIN_CREATED:-0}" == "1" ]]; then
    printf "  Password: %b%s%b  ← autogenerated, save this now (also in %s/.env as INITIAL_ADMIN_PASSWORD)\n" "$c_yellow$c_bold" "$ADMIN_PASSWORD" "$c_reset" "$NANO_INSTALL_DIR"
fi
if [[ "${ADMIN_CREATED:-0}" == "1" ]]; then
    printf "  Password saved in %s/.env as INITIAL_ADMIN_PASSWORD.\n" "$NANO_INSTALL_DIR"
fi
# NAN-835 / NAN-836: surface every ingest endpoint + one-line curl so users
# can point external Vector / HEC forwarders / curl at the new instance
# without spelunking through .env or docker-compose.
if [[ "${TENZIR_DIRECT:-0}" == "1" ]]; then
    # NAN-3807: no Vector, so none of the ingest endpoints below exist. The
    # per-source key is minted by lean-landing-admin and shown only there.
    echo
    printf "  Ingest:   Tenzir-direct (OCSF bucket drop; no Vector, so no HTTP /ingest, HEC, OTLP or pull connectors)\n"
    printf "  Next:     add a source; it prints a write-only key and a ready-to-paste Tenzir to_s3 sink once:\n"
    printf "              docker compose -f %s/%s run --rm lean-landing-admin add --name <name>\n" "$NANO_INSTALL_DIR" "$COMPOSE_FILE"
    printf "            Run Tenzir on this host's compose network (%s_default, endpoint lake-object-store:9000),\n" "${COMPOSE_PROJECT_NAME:-$(basename "$NANO_INSTALL_DIR")}"
    printf "            or use the bundled node: put the pipeline in %s/.nano-tenzir/pipeline.tql and run\n" "$NANO_INSTALL_DIR"
    printf "              docker compose -f %s/%s --profile tenzir up -d tenzir\n" "$NANO_INSTALL_DIR" "$COMPOSE_FILE"
    printf "            Put sysmon.ndjson in %s/.nano-tenzir/data (mounted at /data, read-only).\n" "$NANO_INSTALL_DIR"
    printf "            Example pipeline: %s/tenzir/lean/sysmon-bucket.tql   Guide: %s/tenzir/AGENTS.md\n" "$NANO_INSTALL_DIR" "$NANO_INSTALL_DIR"
    printf "            Status: Ingestion → Credentials → Bucket drop sources.   Add Vector later: install.sh --add-vector\n"
elif [[ "$NANO_NONINTERACTIVE" != "1" && -n "${VECTOR_AUTH_TOKEN:-}" ]]; then
    # Strip scheme + path from BASE_URL to get bare host for host:port endpoints
    INGEST_HOST="${BASE_URL#http://}"
    INGEST_HOST="${INGEST_HOST#https://}"
    INGEST_HOST="${INGEST_HOST%%/*}"
    INGEST_HOST="${INGEST_HOST%%:*}"
    echo
    printf "  Token:    %b%s%b  ← bound to the install source (OpenTelemetry Logs on a fresh install)\n" "$c_yellow$c_bold" "$VECTOR_AUTH_TOKEN" "$c_reset"
    echo
    printf "  Per-source tokens: Ingestion → Credentials. Use a token bound to your intended source.\n"
    printf "  HTTP:     POST %s/ingest\n" "$BASE_URL"
    printf "              curl -X POST %s/ingest \\\\\n" "$BASE_URL"
    printf "                -H 'Authorization: Bearer %s' \\\\\n" "$VECTOR_AUTH_TOKEN"
    printf "                -d '{\"message\":\"hello nano\"}'\n"
    echo
    printf "  HEC:      POST http://%s:8088/services/collector/event\n" "$INGEST_HOST"
    printf "              curl -X POST http://%s:8088/services/collector/event \\\\\n" "$INGEST_HOST"
    printf "                -H 'Authorization: Splunk %s' \\\\\n" "$VECTOR_AUTH_TOKEN"
    printf "                -H 'X-Splunk-Request-Channel: 11111111-1111-4111-8111-111111111111' \\\\\n"
    printf "                -d '{\"event\":\"hello nano\"}'\n"
    echo
    printf "  OTLP/HTTP: %s/otlp  (SDK/collector endpoint; /v1/logs, /v1/traces, /v1/metrics)\n" "$BASE_URL"
    printf "              header 'Authorization: Bearer %s'\n" "$VECTOR_AUTH_TOKEN"
    printf "              Raw OTLP gRPC/HTTP (:4317/:4318) is unauthenticated and bound to\n"
    printf "              127.0.0.1 unless NANO_OTLP_BIND_ADDRESS is set.\n"
    echo
    # NAN-3322: Vector's native `vector` source/sink pair has no auth option, and
    # the :6000 source checks nothing, so the token above does not apply here.
    printf "  Vector:   %s:6000  (Vector → Vector native protocol, v2)\n" "$INGEST_HOST"
    printf '              point on-prem Vector aggregators here with a "vector" sink.\n'
    printf "              UNAUTHENTICATED: the token above is not checked on this port,\n"
    printf "              so it binds 127.0.0.1 unless NANO_VECTOR_NATIVE_BIND_ADDRESS is\n"
    printf "              set. Prefer the authenticated HTTP / HEC endpoints above.\n"
    if [[ "${USE_LEAN:-0}" == "1" ]]; then
        echo
        printf "  Tenzir:   OCSF bucket drop beside Vector (tenzir/AGENTS.md); add a source with\n"
        printf "              docker compose -f %s/%s run --rm lean-landing-admin add --name <name>\n" "$NANO_INSTALL_DIR" "$COMPOSE_FILE"
    fi
    # NAN-1603 / NAN-1604: direct OCSF ingestion (Tenzir / Cribl / custom) writes
    # straight into ClickHouse, bypassing Vector. Only meaningful on the OCSF profile.
    if [[ "$SCHEMA_PROFILE" == "ocsf" && "$ENABLE_LAKE_CONTROL_PLANE" != "1" ]]; then
        echo
        printf "  Direct OCSF ingestion (Tenzir / Cribl / custom)\n"
        printf "            Native sink: clickhouse:9000  (internal docker network)\n"
        printf "            User/Table:  nanosiem_ingest → nanosiem.ocsf_logs_native_raw\n"
        printf "            Password:    %b%s%b\n" "$c_yellow$c_bold" "${CLICKHOUSE_INGEST_PASSWORD:-(see .env)}" "$c_reset"
        printf "            Docs:        https://nano.rs/docs/concepts/ocsf-schema\n"
    fi
fi
echo
echo "  Logs:     docker compose -f $NANO_INSTALL_DIR/$COMPOSE_FILE logs -f"
echo "  Stop:     docker compose -f $NANO_INSTALL_DIR/$COMPOSE_FILE down"
echo "  Reset:    docker compose -f $NANO_INSTALL_DIR/$COMPOSE_FILE down -v   (DELETES ALL DATA)"
echo

}
main "$@"
