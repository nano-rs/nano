#!/usr/bin/env bash
# nano-e2e scenario harness runner (NAN-4920).
#
# Brings up a THROWAWAY stack (compose project nanoe2e-<runid>, free
# 127.0.0.1 ports chosen per run), writes one stack.env, runs the Python/pytest scenarios in
# e2e/ against it black-box over HTTP, collects artifacts and tears it down.
# It never touches the nanoch-* dev stack or any other compose project.
#
#   scripts/e2e.sh up      [--app native|docker|image:<tag>] [--edition enterprise|open]
#                          [--release] [--no-build] [--infra-only]
#                          [--profile mock-vendor|connector-live|ai-stub] [--defer-admin]
#                          (mock-vendor: nano-connector-runner in lab mode pointed at
#                          the harness's vendor mock; connector-live: the runner with
#                          NO test seam, polling the real vendor tenants (NAN-4961);
#                          defer-admin: leave first-run setup to the scenarios, the
#                          UI suite does it in a browser)
#   scripts/e2e.sh run     [suite...|all|fast|ui|otlp|personas|soar|content_acceptance] [--run <id>] [--fresh] [--keep] [--allow-skips]
#                          [-- <pytest args>]  (a selected suite that executes nothing FAILS
#                          unless --allow-skips)
#                          (reuses --run <id>, else the live stack from `up`; with
#                          neither, or --fresh: up + run + down)
#   scripts/e2e.sh down    [--run <id>] [--purge]
#   scripts/e2e.sh env     [--run <id>]          print the stack.env path
#   scripts/e2e.sh doctor                        prerequisites + credential presence
#   scripts/e2e.sh legacy  <lane...|all|list> [--run <id>]   wrapped legacy tests
#   scripts/e2e.sh gc      [--hours N] [--cloud] [--all-local]
#                          stale nanoe2e-* stacks THIS worktree started (owner label
#                          = this checkout, or a run dir under target/e2e); --cloud
#                          touches ONLY cloud stragglers prefixed nano-e2e-;
#                          --all-local also removes other worktrees' local stacks
#   scripts/e2e.sh svc     <restart|stop|start|kill> <api|search|jobs|vector> [--run <id>]
#   scripts/e2e.sh status  [--run <id>]
#   scripts/e2e.sh license-ids [--run <id>]      installation_id + organization_id of a
#                                                kept enterprise stack (to issue a C05 trial)
#   scripts/e2e.sh selftest                      harness safety selftests (no stack, no cloud)
#
# Suites are the files/dirs under e2e/tests: `base` = e2e/tests/test_base.py,
# `pull` = e2e/tests/pull/, `ui` = e2e/tests/ui/ (real Chrome via puppeteer-core),
# ... `fast` = base + ingest. See e2e/README.md.
#
# Secrets: generated per run into the run dir (0600) and never printed. Cloud
# credentials come from `doppler run -p nano-e2e -c dev` when available, else
# ~/.nan2361-secrets/e2e.env (must be 0600), and are only ever placed in the
# environment of the pytest process.
#
# Offline C05 license (enterprise, NAN-5331; see e2e/README.md):
#   NANO_E2E_INSTALLATION_ID + NANO_E2E_INSTALLATION_ORG_ID  pin the installation
#       identity every new stack gets (seeded after the migrator, before the app)
#   NANO_E2E_C05_LICENSE_FILE  a 0600 license file outside the repo, imported as
#       admin once the stack is healthy; `up` fails unless the license is active.
#       Its contents are never printed, logged or copied.
set -euo pipefail
if (( BASH_VERSINFO[0] < 4 )); then
    echo "e2e.sh needs bash >= 4 (macOS: brew install bash, then put it first in PATH)" >&2
    exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/generated-secrets.sh
. "$ROOT/scripts/lib/generated-secrets.sh"
# shellcheck source=scripts/tests/lib/leak-guard.sh
. "$ROOT/scripts/tests/lib/leak-guard.sh"
E2E_HOME="$ROOT/target/e2e"
COMPOSE_BASE="$ROOT/docker-compose.opensource.yml"
COMPOSE_E2E="$ROOT/dev/e2e/compose.e2e.yml"
LANES_FILE="$ROOT/dev/e2e/legacy-lanes.toml"
PY_DIR="$ROOT/e2e"
VENV="$PY_DIR/.venv"
OS="$(uname -s)"
CREDS_FILE="${NANO_E2E_CREDS_FILE:-$HOME/.nan2361-secrets/e2e.env}"
DOPPLER_PROJECT="${NANO_E2E_DOPPLER_PROJECT:-nano-e2e}"
DOPPLER_CONFIG="${NANO_E2E_DOPPLER_CONFIG:-dev}"
INFRA=(postgres clickhouse dragonfly)

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*" >&2; }
ok()   { printf '\033[1;32m ok\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[1;33m !!\033[0m %s\n' "$*" >&2; }
err()  { printf '\033[1;31mERR\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mERR\033[0m %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- arguments
CMD="${1:-}"; [[ $# -gt 0 ]] && shift
# --run selects an EXISTING run. A new run's id is random unless
# E2E_NEW_RUN_ID names it (CI: gh<run_id>-<attempt>). E2E_RUN_ID from a sourced
# stack.env is deliberately ignored, so it can never redirect a command.
# Edition default follows the tree: the open-core mirror strips
# nanosiem-enterprise, so a stripped checkout builds and tests EDITION=open.
if [[ -d "$ROOT/nanosiem-enterprise" ]]; then DEFAULT_EDITION=enterprise; else DEFAULT_EDITION=open; fi
APP_MODE=""; APP_MODE_EXPLICIT=0; EDITION="${E2E_EDITION:-$DEFAULT_EDITION}"; RUN_ID=""; NEW_RUN_ID="${E2E_NEW_RUN_ID:-}"
KEEP=0; FRESH=0; ALLOW_SKIPS="${E2E_ALLOW_SKIPS:-0}"; PURGE=0; NO_BUILD=0; RELEASE=0; GC_HOURS=6; GC_CLOUD=0; GC_ALL_LOCAL=0; INFRA_ONLY=0
DEFER_ADMIN=0; PROFILES=()
POSITIONAL=(); PYTEST_EXTRA=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --app) APP_MODE="${2:?--app needs a value}"; APP_MODE_EXPLICIT=1; shift 2 ;;
        --app=*) APP_MODE="${1#*=}"; APP_MODE_EXPLICIT=1; shift ;;
        --edition) EDITION="${2:?--edition needs a value}"; shift 2 ;;
        --run) RUN_ID="${2:?--run needs a run id}"; shift 2 ;;
        --keep) KEEP=1; shift ;;
        --fresh) FRESH=1; shift ;;
        --allow-skips) ALLOW_SKIPS=1; shift ;;
        --purge) PURGE=1; shift ;;
        --no-build) NO_BUILD=1; shift ;;
        --release) RELEASE=1; shift ;;
        --infra-only) INFRA_ONLY=1; shift ;;
        --hours) GC_HOURS="${2:?--hours needs a value}"; shift 2 ;;
        --cloud) GC_CLOUD=1; shift ;;
        --all-local) GC_ALL_LOCAL=1; shift ;;
        --profile) PROFILES+=("${2:?--profile needs a value}"); shift 2 ;;
        --profile=*) PROFILES+=("${1#*=}"); shift ;;
        --defer-admin) DEFER_ADMIN=1; shift ;;
        --) shift; PYTEST_EXTRA=("$@"); break ;;
        -*) die "unknown option: $1" ;;
        *) POSITIONAL+=("$1"); shift ;;
    esac
done
[[ "$EDITION" =~ ^(enterprise|open)$ ]] || die "--edition must be enterprise or open"
[[ "$EDITION" == open || -d "$ROOT/nanosiem-enterprise" ]] || die "--edition enterprise needs nanosiem-enterprise (open-core tree)"
if [[ ! "$GC_HOURS" =~ ^[0-9]+$ ]] || (( GC_HOURS < 1 )); then die "--hours must be an integer >= 1"; fi
if [[ -z "$APP_MODE" ]]; then
    if [[ "$OS" == Darwin ]]; then APP_MODE=native; else APP_MODE=docker; fi
fi
[[ "$APP_MODE" =~ ^(native|docker|image:[A-Za-z0-9._-]+)$ ]] || die "--app must be native, docker or image:<tag>"
for _p in "${PROFILES[@]}"; do
    [[ "$_p" =~ ^(mock-vendor|connector-live|ai-stub|soar-lab)$ ]] || die "unknown --profile '$_p' (known: mock-vendor, connector-live, ai-stub, soar-lab)"
done
has_profile() { local p; for p in "${PROFILES[@]}"; do [[ "$p" == "$1" ]] && return 0; done; return 1; }
if has_profile mock-vendor && has_profile connector-live; then
    # One runner per stack: lab mode routes EVERY vendor request to the mock.
    die "--profile mock-vendor and connector-live are exclusive (one connector runner per stack)"
fi
for _p in mock-vendor connector-live; do
    if has_profile "$_p" && [[ "$APP_MODE" != native ]]; then
        # Checked before anything is created. The runner's mock seam needs the
        # mock on the runner's own loopback; containerised runner: not wired yet.
        die "--profile $_p needs --app native (docker/image app modes: not wired yet)"
    fi
done

# ---------------------------------------------------------------- run state
new_run_id() {
    local user; user="$(id -un 2>/dev/null || echo e2e)"
    user="$(printf '%s' "$user" | tr -cd 'a-z0-9' | cut -c1-8)"
    printf '%s-%s' "${user:-e2e}" "$(openssl rand -hex 4)"
}

resolve_run() {
    # Sets RUN_ID / RUN_DIR / PROJECT for an existing run (explicit or current).
    if [[ -z "$RUN_ID" ]]; then
        [[ -L "$E2E_HOME/current" ]] || die "no current e2e run (start one with: scripts/e2e.sh up)"
        RUN_ID="$(basename "$(readlink "$E2E_HOME/current")")"
    fi
    validate_run_id "$RUN_ID"
    RUN_DIR="$E2E_HOME/$RUN_ID"
    PROJECT="nanoe2e-$RUN_ID"
    [[ -d "$RUN_DIR" ]] || die "unknown run $RUN_ID ($RUN_DIR missing)"
}

validate_run_id() {
    [[ "$1" =~ ^[a-z0-9]{1,8}-[0-9a-f]{8}$|^gh[0-9]+-[0-9]+$ ]] \
        || die "invalid run id '$1' (expected <user>-<8 hex>)"
}

# Read KEY from an env file without sourcing it (values are data, not code).
env_get() {
    local file="$1" key="$2"
    [[ -f "$file" ]] || return 0
    { grep -E "^${key}=" "$file" || true; } | tail -n1 | cut -d= -f2-
}

load_env_file() {
    local line
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ "$line" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]] && export "${line?}"
    done < "$1"
}

put() { printf '%s=%s\n' "$1" "$2"; }

# ---------------------------------------------------------------- compose
dc() (
    # Literal values from the run's secrets file; compose interpolates them
    # into the template. --env-file /dev/null: never read the checkout's .env.
    nano_backfill_generated_secrets "$RUN_DIR/compose.env" generate \
        || die "could not backfill generated secrets in $RUN_DIR/compose.env"
    load_env_file "$RUN_DIR/compose.env"
    [[ "$PROJECT" == nanoe2e-* ]] || die "refusing to run compose for project '$PROJECT'"
    local profile=()
    [[ "$(env_get "$RUN_DIR/run.env" E2E_APP_MODE)" != native ]] && profile+=(--profile docker-app)
    run_has_profile ai-stub && profile+=(--profile ai-stub)
    run_has_profile soar-lab && profile+=(--profile soar-lab)
    docker compose -p "$PROJECT" --project-directory "$ROOT" --env-file /dev/null \
        -f "$COMPOSE_BASE" -f "$COMPOSE_E2E" "${profile[@]}" "$@"
)


free_port() {
    python3 -I -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
}

wait_http() {
    local url="$1" name="$2" tries="${3:-90}" pidfile="${4:-}"
    for _ in $(seq 1 "$tries"); do
        if curl -fsS -o /dev/null --max-time 5 "$url" 2>/dev/null; then ok "$name healthy"; return 0; fi
        if [[ -n "$pidfile" ]] && ! pid_alive "$pidfile"; then
            tail -n 40 "${pidfile%.pid}.log" >&2 || true
            die "$name exited during startup (log: ${pidfile%.pid}.log)"
        fi
        sleep 2
    done
    die "$name not healthy after $((tries * 2))s ($url)"
}

start_ai_stub() {
    run_has_profile ai-stub || return 0
    dc up -d ai-stub >> "$RUN_DIR/artifacts/compose-up.log" 2>&1 \
        || { tail -n 30 "$RUN_DIR/artifacts/compose-up.log" >&2; die "compose up ai-stub failed"; }
    local identity
    identity="$(docker inspect --format '{{index .Config.Labels "nano.e2e.project"}}|{{index .Config.Labels "nano.e2e.owner"}}|{{.State.Running}}' "${PROJECT}-ai-stub" 2>/dev/null)" \
        || die "ai-stub container is missing after compose up"
    [[ "$identity" == "$PROJECT|$ROOT|true" ]] \
        || die "refusing unowned ai-stub container ${PROJECT}-ai-stub ($identity)"
    wait_http "http://127.0.0.1:$(env_get "$RUN_DIR/run.env" E2E_AI_STUB_PORT)/health" ai-stub 30
}

generate_soar_lab_pki() {
    run_has_profile soar-lab || return 0
    local d="$RUN_DIR/soar-lab"
    mkdir -p "$d"
    chmod 700 "$d"
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 -sha256 \
        -subj "/CN=nano-e2e SOAR CA" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -keyout "$d/ca.key" -out "$d/ca.pem" >/dev/null 2>&1
    openssl req -new -newkey rsa:2048 -nodes -sha256 \
        -subj "/CN=tenant.okta.com" \
        -addext "subjectAltName=DNS:tenant.okta.com,DNS:mail.corp.example" \
        -keyout "$d/key.pem" -out "$d/leaf.csr" >/dev/null 2>&1
    openssl x509 -req -days 2 -sha256 -in "$d/leaf.csr" \
        -CA "$d/ca.pem" -CAkey "$d/ca.key" -CAcreateserial \
        -extfile <(printf '%s\n' \
            'basicConstraints=critical,CA:FALSE' \
            'keyUsage=critical,digitalSignature,keyEncipherment' \
            'extendedKeyUsage=serverAuth' \
            'subjectAltName=DNS:tenant.okta.com,DNS:mail.corp.example') \
        -out "$d/cert.pem" >/dev/null 2>&1
    chmod 600 "$d/ca.key" "$d/key.pem"
}

start_soar_lab() {
    run_has_profile soar-lab || return 0
    dc up -d soar-mailpit >> "$RUN_DIR/artifacts/compose-up.log" 2>&1 \
        || { tail -n 30 "$RUN_DIR/artifacts/compose-up.log" >&2; die "compose up soar-mailpit failed"; }
    local identity
    identity="$(docker inspect --format '{{index .Config.Labels "nano.e2e.project"}}|{{index .Config.Labels "nano.e2e.owner"}}|{{.State.Running}}' "${PROJECT}-soar-mailpit" 2>/dev/null)" \
        || die "soar-mailpit container is missing after compose up"
    [[ "$identity" == "$PROJECT|$ROOT|true" ]] \
        || die "refusing unowned soar-mailpit container ${PROJECT}-soar-mailpit ($identity)"
    wait_http "http://127.0.0.1:$(env_get "$RUN_DIR/run.env" E2E_SOAR_MAILPIT_API_PORT)/api/v1/info" soar-mailpit 30
}

# ---------------------------------------------------------------- secrets
gen_secrets() {
    local f="$RUN_DIR/compose.env"
    (
        umask 077
        {
            put NANO_ADMIN_PASSWORD "E2e-$(openssl rand -hex 16)!"
            put E2E_PROJECT "$PROJECT"
            put E2E_RUN_DIR "$RUN_DIR"
            put E2E_STARTED "$(date +%s)"
            put E2E_OWNER "$ROOT"
            put CLICKHOUSE_MEM_LIMIT "${E2E_CLICKHOUSE_MEM_LIMIT:-8G}"  # 4G/6G hit 241s under the UI suite once feed bundles load (NAN-4937)
            put NANO_SCHEMA_PROFILE "${NANO_SCHEMA_PROFILE:-udm}"
            put NANOSIEM_DEV_MODE true
            put RUST_LOG "${E2E_RUST_LOG:-info}"
            # No floating tag is published: default to this checkout's release.
            put NANO_VERSION "${E2E_IMAGE_TAG:-$(sed -n 's/^# Release: v//p' "$ROOT/images.lock" | head -1)}"
            # NAN-5204: enables POST /api/internal/backup-status (the
            # nano-backup service's report) on every e2e stack.
            put NANO_BACKUP_STATUS_TOKEN "$(openssl rand -hex 32)"
        } > "$f"
        nano_backfill_generated_secrets "$f" generate
    )
}

# Stage the checkout's complete ClickHouse configuration for an owned run.
# Keep this as the single initializer for every e2e path: config.d and users.d
# are both read-only bind mounts, so omitting either turns a missing host path
# into an empty directory that ClickHouse cannot populate at startup.
initialize_e2e_clickhouse_config() {
    local target="$RUN_DIR/clickhouse"
    [[ -d "$ROOT/clickhouse/config.d" ]] || die "clickhouse/config.d is missing"
    [[ -d "$ROOT/clickhouse/users.d" ]] || die "clickhouse/users.d is missing"
    [[ ! -e "$target/config.d" && ! -e "$target/users.d" ]] \
        || die "ClickHouse config is already initialized in $target"
    mkdir -p "$target"
    cp -R "$ROOT/clickhouse/config.d" "$target/config.d"
    cp -R "$ROOT/clickhouse/users.d" "$target/users.d"
}

# Optional NAN-4997 capacity emulation. The normal e2e defaults stay unchanged;
# a sizing regression can set the two variables below to exercise the exact
# installer model and generated ClickHouse XML on a throwaway owned stack.
render_resource_sizing() {
    [[ -n "${E2E_SIZING_CPU_CORES:-}" || -n "${E2E_SIZING_MEMORY_MIB:-}" ]] || return 0
    [[ -n "${E2E_SIZING_CPU_CORES:-}" && -n "${E2E_SIZING_MEMORY_MIB:-}" ]] \
        || die "E2E_SIZING_CPU_CORES and E2E_SIZING_MEMORY_MIB must be set together"
    local output="$RUN_DIR/sizing.env"
    "$ROOT/scripts/lib/resource-sizing.sh" \
        --cpu "$E2E_SIZING_CPU_CORES" \
        --memory-mib "$E2E_SIZING_MEMORY_MIB" \
        --topology single \
        --roles app,ingest,clickhouse,postgres \
        --shards 1 \
        --server-output "$RUN_DIR/clickhouse/config.d/zzzz-nano-sizing.xml" \
        --users-output "$RUN_DIR/clickhouse/users.d/zzzz-nano-sizing.xml" \
        --format env > "$output"
    cat "$output" >> "$RUN_DIR/compose.env"
    log "applied installer sizing for ${E2E_SIZING_CPU_CORES} CPU / ${E2E_SIZING_MEMORY_MIB} MiB"
}

# ---------------------------------------------------------------- native app
# Native process identity. A pid file holds "<pid> <start time> <owner token>":
# the token is minted per start and exported into the process as
# E2E_PROC_OWNER. A pid is trusted (and signalled) only while ALL of these
# still hold: same start time, a command under this checkout's target dir,
# and the token in its environment. A reused pid (another run, or a dev
# nanosiem-api built from the same target dir) fails at least one, so it is
# never signalled. Checked again immediately before every signal.
proc_start() { LC_ALL=C ps -o lstart= -p "$1" 2>/dev/null | tr -s ' ' | sed 's/^ //; s/ $//'; }

proc_has_owner() {
    local pid="$1" token="$2"
    if [[ -r "/proc/$pid/environ" ]]; then
        tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null | grep -qxF "E2E_PROC_OWNER=$token"
    else
        # macOS: ps -E appends the environment of the user's own processes.
        local out; out="$(ps -E -ww -o command= -p "$pid" 2>/dev/null)" || return 1
        [[ " $out " == *" E2E_PROC_OWNER=$token "* ]]
    fi
}

# pid_owned <pidfile>: prints the pid when it is still the process we started.
pid_owned() {
    [[ -s "$1" ]] || return 1
    local pid start token cmd
    pid="$(cut -f1 "$1")"; start="$(cut -f2 "$1")"; token="$(cut -f3 "$1")"
    [[ "$pid" =~ ^[1-9][0-9]*$ && "$token" =~ ^[0-9a-f]{32}$ && -n "$start" ]] || return 1
    [[ "$(proc_start "$pid")" == "$start" ]] || return 1
    cmd="$(ps -o command= -p "$pid" 2>/dev/null)" || return 1
    [[ "$cmd" == "$(target_dir)/"* ]] || return 1
    proc_has_owner "$pid" "$token" || return 1
    printf '%s' "$pid"
}

pid_alive() { pid_owned "$1" >/dev/null; }

# signal_owned <sig> <pidfile>: signal only after re-validating identity.
signal_owned() {
    local pid
    pid="$(pid_owned "$2")" || return 1
    kill "-$1" "$pid" 2>/dev/null
}

cargo_bin() {
    # rustup's proxies honour rust-toolchain.toml (1.95); a non-rustup cargo would not.
    if [[ -n "${E2E_CARGO:-}" ]]; then printf '%s' "$E2E_CARGO"; return; fi
    local brew_rustup
    if command -v brew >/dev/null 2>&1 && brew_rustup="$(brew --prefix rustup 2>/dev/null)" \
        && [[ -x "$brew_rustup/bin/cargo" ]]; then
        printf '%s' "$brew_rustup/bin/cargo"; return
    fi
    [[ -x "$HOME/.cargo/bin/cargo" ]] && { printf '%s' "$HOME/.cargo/bin/cargo"; return; }
    command -v cargo || die "cargo not found (install rustup)"
}

target_dir() { printf '%s' "${CARGO_TARGET_DIR:-$ROOT/target}"; }
profile_dir() { if (( RELEASE )); then echo release; else echo debug; fi; }

native_build() {
    local features=() mode=() acceptance_env=() cargo
    cargo="$(cargo_bin)"
    [[ "$EDITION" == enterprise ]] && features=(--features enterprise)
    if test_trust_composition_selected; then
        features=(--features enterprise)
        acceptance_env=(env NANO_NON_RELEASE_BUILD=1 "RUSTFLAGS=${RUSTFLAGS:-} --cfg nano_content_acceptance")
    fi
    (( RELEASE )) && mode=(--release)
    log "cargo build ($EDITION, $(profile_dir)); log: $RUN_DIR/artifacts/build.log"
    # The rustup proxies (cargo, rustc) live side by side; keep them first.
    (cd "$ROOT" && PATH="$(dirname "$cargo"):$PATH" "${acceptance_env[@]}" \
        nice -n 10 "$cargo" build -p nanosiem-api -p nanosiem-search "${features[@]}" "${mode[@]}") \
        > "$RUN_DIR/artifacts/build.log" 2>&1 \
        || { tail -n 30 "$RUN_DIR/artifacts/build.log" >&2; die "cargo build failed"; }
    if run_has_runner; then
        # Separate invocation: the runner crate has no `enterprise` feature.
        (cd "$ROOT" && PATH="$(dirname "$cargo"):$PATH" nice -n 10 "$cargo" build -p nano-connector --bin nano-connector-runner "${mode[@]}") \
            >> "$RUN_DIR/artifacts/build.log" 2>&1 \
            || { tail -n 30 "$RUN_DIR/artifacts/build.log" >&2; die "cargo build (nano-connector-runner) failed"; }
    fi
    ok "build complete"
}

# run_has_profile <name>: the profile is on for the run (recorded in run.env).
run_has_profile() {
    [[ " $(env_get "$RUN_DIR/run.env" E2E_PROFILES) " == *" $1 "* ]]
}

# run_has_runner: the run starts nano-connector-runner (lab or live).
run_has_runner() { run_has_profile mock-vendor || run_has_profile connector-live; }

write_app_env() {
    # Environment of the native api/search/jobs/migrator. Values are generated
    # hex/URLs only; written %q-quoted so the file is safe to source.
    local f="$RUN_DIR/app.env" pg ch redis vhttp vmet
    load_env_file "$RUN_DIR/compose.env"
    pg="$(env_get "$RUN_DIR/run.env" E2E_PG_PORT)"; ch="$(env_get "$RUN_DIR/run.env" E2E_CH_HTTP_PORT)"
    redis="$(env_get "$RUN_DIR/run.env" E2E_REDIS_PORT)"
    vhttp="$(env_get "$RUN_DIR/run.env" E2E_VECTOR_HTTP_PORT)"; vmet="$(env_get "$RUN_DIR/run.env" E2E_VECTOR_METRICS_PORT)"
    (
        umask 077
        {
            local kv
            for kv in \
                "DATABASE_URL=postgres://nanosiem:${POSTGRES_PASSWORD}@127.0.0.1:${pg}/nanosiem" \
                "CLICKHOUSE_URL=http://127.0.0.1:${ch}" CLICKHOUSE_DATABASE=nanosiem CLICKHOUSE_CLUSTER= \
                CLICKHOUSE_USER=nanosiem "CLICKHOUSE_PASSWORD=$CLICKHOUSE_PASSWORD" \
                CLICKHOUSE_SELF_USER=nanosiem CLICKHOUSE_ADMIN_USER=nanosiem_admin \
                "CLICKHOUSE_ADMIN_PASSWORD=$CLICKHOUSE_ADMIN_PASSWORD" \
                "CLICKHOUSE_VECTOR_PASSWORD=$CLICKHOUSE_VECTOR_PASSWORD" \
                "CLICKHOUSE_RAWSQL_PASSWORD=$CLICKHOUSE_RAWSQL_PASSWORD" \
                "CLICKHOUSE_RAWSQL_NOAUDIT_PASSWORD=$CLICKHOUSE_RAWSQL_NOAUDIT_PASSWORD" \
                POSTGRES_DICT_HOST=postgres "POSTGRES_DICT_PASSWORD=$POSTGRES_PASSWORD" \
                "REDIS_URL=redis://127.0.0.1:${redis}" \
                "JWT_SECRET=$JWT_SECRET" "NANOSIEM_ENCRYPTION_KEY=$NANOSIEM_ENCRYPTION_KEY" \
                AUTH_ENABLED=true NANOSIEM_DEV_MODE=true DEPLOYMENT_MODE=selfhosted \
                "NANOSIEM_ALLOW_PRIVATE_AI_ENDPOINTS=$(env_get "$RUN_DIR/compose.env" E2E_ALLOW_PRIVATE_AI_ENDPOINTS)" \
                "EDITION=$EDITION" "NANO_SCHEMA_PROFILE=$NANO_SCHEMA_PROFILE" AIRGAP_MODE=false \
                "VECTOR_AUTH_TOKEN=$VECTOR_AUTH_TOKEN" "VECTOR_INGEST_URL=http://127.0.0.1:${vhttp}/" \
                "VECTOR_CONTAINER_NAME=${PROJECT}-vector" \
                "VECTOR_CONFIG_DIR=$RUN_DIR/vector-dynamic" VECTOR_SOURCES_RUNTIME_PATH=/etc/vector/dynamic/sources \
                "VECTOR_VALIDATION_DIR=$RUN_DIR/vector-validation" VECTOR_VALIDATION_RUNTIME_PATH=/var/lib/nano-validation \
                "NANO_INGEST_TOKENS_FILE=$RUN_DIR/vector-dynamic/ingest-tokens/tokens.json" \
                NANO_INGEST_TOKENS_DELIVERY=shared_volume \
                "VECTOR_METRICS_URL=http://127.0.0.1:${vmet}/metrics" \
                "NANO_PLATFORM_INGEST_TOKEN=$NANO_PLATFORM_INGEST_TOKEN" "NANO_OTLP_EDGE_KEY=$NANO_OTLP_EDGE_KEY" \
                SKIP_VECTOR_VALIDATION=true "NANOSIEM_DATA_DIR=$RUN_DIR/data" \
                "NANO_INGEST_PUBLIC_BASE_URL=http://127.0.0.1:$(env_get "$RUN_DIR/run.env" E2E_EDGE_PORT)" \
                "NANO_INGEST_HEC_PORT=$(env_get "$RUN_DIR/run.env" E2E_HEC_PORT)" \
                NANO_PIPE_PREVIEW_ENABLED=true \
                "NANO_BACKUP_STATUS_TOKEN=${NANO_BACKUP_STATUS_TOKEN:-}" \
                API_HOST=127.0.0.1 "API_PORT=$(env_get "$RUN_DIR/run.env" E2E_API_PORT)" \
                "SEARCH_PORT=$(env_get "$RUN_DIR/run.env" E2E_SEARCH_PORT)" \
                "JOBS_PORT=$(env_get "$RUN_DIR/run.env" E2E_JOBS_PORT)" \
                "SEARCH_SERVICE_URL=http://127.0.0.1:$(env_get "$RUN_DIR/run.env" E2E_SEARCH_PORT)/health" \
                LEADER_ELECTION_ENABLED=true CORS_ORIGINS=http://localhost \
                "RUST_LOG=$RUST_LOG" NANOSIEM_INVESTIGATION_TOOL_LOOP=false \
                CLOUDFLARE_AI_GATEWAY_URL= CF_AIG_AUTH_TOKEN= DOCS_SEARCH_TOKEN=; do
                printf 'export %s=%q\n' "${kv%%=*}" "${kv#*=}"
            done
            if [[ "$(env_get "$RUN_DIR/run.env" E2E_CONTENT_ACCEPTANCE)" == 1 ]]; then
                local fixture proxy
                fixture="http://127.0.0.1:$(env_get "$RUN_DIR/run.env" E2E_CONTENT_FIXTURE_PORT)"
                proxy="$fixture"
                for kv in \
                    "CONTENT_CHANNELS_URL=$fixture/api/content/v1" \
                    CONTENT_CHANNELS_DEV_INSECURE_HTTP=1 CONTENT_CHANNELS_POLL_SECS=300 \
                    "CONTENT_CHANNELS_LICENSE_FILE=$RUN_DIR/content-acceptance-license" \
                    "CONTENT_CHANNELS_WORK_DIR=$RUN_DIR/data/content-channels" \
                    MITRE_CONTENT_ACCEPTANCE_FIXTURE=1 \
                    "HTTP_PROXY=$proxy" "HTTPS_PROXY=$proxy" "ALL_PROXY=$proxy" \
                    "http_proxy=$proxy" "https_proxy=$proxy" "all_proxy=$proxy" \
                    NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost; do
                    printf 'export %s=%q\n' "${kv%%=*}" "${kv#*=}"
                done
            fi
            # Scenario-specific app env (e.g. NAN-4955's egress sinkhole and
            # content distribution URL): KEY=VALUE lines, appended verbatim
            # as exports. Only read from a regular file the caller names.
            if [[ -n "${E2E_APP_ENV_EXTRA:-}" ]]; then
                [[ -f "$E2E_APP_ENV_EXTRA" ]] || die "E2E_APP_ENV_EXTRA=$E2E_APP_ENV_EXTRA is not a file"
                local line
                while IFS= read -r line || [[ -n "$line" ]]; do
                    [[ -z "$line" || "$line" == \#* ]] && continue
                    [[ "$line" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]] || die "E2E_APP_ENV_EXTRA: bad line"
                    printf 'export %s=%q\n' "${line%%=*}" "${line#*=}"
                done < "$E2E_APP_ENV_EXTRA"
            fi
            if run_has_profile soar-lab; then
                for kv in \
                    SOAR_E2E_LAB=1 \
                    "SOAR_E2E_VENDOR_ADDR=127.0.0.1:$(env_get "$RUN_DIR/run.env" E2E_SOAR_VENDOR_PORT)" \
                    "SOAR_E2E_SMTP_ADDR=127.0.0.1:$(env_get "$RUN_DIR/run.env" E2E_SOAR_SMTP_PORT)" \
                    "SOAR_E2E_CA_PATH=$RUN_DIR/soar-lab/ca.pem"; do
                    printf 'export %s=%q\n' "${kv%%=*}" "${kv#*=}"
                done
            fi
        } > "$f"
    )
}

write_connector_env() {
    # mock-vendor: nano-connector-runner in lab mode. The ONLY relaxation is the
    # runner's own sanctioned seam: CONNECTOR_TEST_MODE=1 +
    # CONNECTOR_TEST_MOCK_URL (a loopback IP literal). Each vendor request still
    # passes the spec's host policy before it is sent to the mock.
    # connector-live (NAN-4961): the runner exactly as shipped, no test seam:
    # vendor requests go to the real tenants. Ingest goes to this stack's
    # Vector HEC with the platform token (in app.env) in both.
    local f="$RUN_DIR/connector.env" hec mock lab=()
    hec="$(env_get "$RUN_DIR/run.env" E2E_HEC_PORT)"; mock="$(env_get "$RUN_DIR/run.env" E2E_MOCK_VENDOR_PORT)"
    if run_has_profile mock-vendor; then
        lab=(CONNECTOR_TEST_MODE=1 "CONNECTOR_TEST_MOCK_URL=http://127.0.0.1:${mock}")
    fi
    (
        umask 077
        {
            local kv
            for kv in \
                "CONNECTOR_HEC_URL=http://127.0.0.1:${hec}" \
                "${lab[@]}" \
                CONNECTOR_POLL_INTERVAL_SECS=3 \
                "CONNECTOR_HEALTH_FILE=$RUN_DIR/pids/connector.health" \
                NANO_CONNECTOR_SECCOMP=prefer NANO_CONNECTOR_CGROUP=prefer \
                "HOSTNAME=${PROJECT}-connector"; do
                printf 'export %s=%q\n' "${kv%%=*}" "${kv#*=}"
            done
        } > "$f"
    )
}

render_edge_conf() {
    # render_edge_conf <out>: the shipped nginx config with only its upstreams
    # pointed at this stack and the SPA served from /srv/web (no nano-web
    # container here). Everything else (/ingest, /otlp auth_request, search
    # routing) is the customer config verbatim.
    local out="$1" api search
    if [[ "$(env_get "$RUN_DIR/run.env" E2E_APP_MODE)" == native ]]; then
        api="host.docker.internal:$(env_get "$RUN_DIR/run.env" E2E_API_PORT)"
        search="host.docker.internal:$(env_get "$RUN_DIR/run.env" E2E_SEARCH_PORT)"
    else
        api="nano-api:3000"; search="nano-search:3002"
    fi
    sed -e "s#http://nano-api:3000#http://${api}#" \
        -e "s#http://nano-search:3002#http://${search}#" \
        -e 's#proxy_pass \$nano_web;#root /srv/web; try_files $uri /index.html;#' \
        "$ROOT/config/nginx/nginx.opensource.conf" > "$out"
    grep -q "root /srv/web" "$out" || die "edge: could not rewrite the SPA location in nginx.opensource.conf"
    if [[ "$api" == host.docker.internal:* ]]; then
        # Native mode: the upstreams are host processes reached through Docker
        # Desktop's host gateway. A fresh connect per request through it has
        # stalled ~25 s mid-run (every /api request hung, the SPA sat on its
        # spinner); pooled keepalive connections avoid the per-request connect.
        # Only the transport to the upstream changes, never the routing.
        local tmp="$out.tmp"
        awk -v api="$api" -v search="$search" '
            /^http \{/ { print; print "    upstream e2e_api { server " api "; keepalive 32; }";
                         print "    upstream e2e_search { server " search "; keepalive 16; }"; next }
            { print }' "$out" \
          | sed -e "s#http://${api}#http://e2e_api#" -e "s#http://${search}#http://e2e_search#" \
                -e "s#^\(        \)'' close;#\1'' '';#" > "$tmp"
        cat "$tmp" > "$out"; rm -f "$tmp"  # in place: the edge bind-mounts this inode
        grep -q "upstream e2e_api" "$out" && grep -q "'' '';" "$out" \
            || die "edge: could not render keepalive upstreams"
    fi
}

start_edge() {
    mkdir -p "$RUN_DIR/edge/web"
    [[ -f "$RUN_DIR/edge/web/index.html" ]] || printf '<!doctype html><title>nano e2e edge</title>\n' > "$RUN_DIR/edge/web/index.html"
    render_edge_conf "$RUN_DIR/edge/nginx.conf"
    dc up -d edge >> "$RUN_DIR/artifacts/compose-up.log" 2>&1 \
        || { tail -n 30 "$RUN_DIR/artifacts/compose-up.log" >&2; die "compose up edge failed"; }
    wait_http "http://127.0.0.1:$(env_get "$RUN_DIR/run.env" E2E_EDGE_PORT)/api/health" "nginx edge" 60
}

wait_connector() {
    # The runner has no HTTP port: it touches CONNECTOR_HEALTH_FILE after every
    # scheduler tick, and runs a sandbox self-test before the first one.
    local health="$RUN_DIR/pids/connector.health"
    for _ in $(seq 1 60); do
        [[ -f "$health" ]] && { ok "nano-connector-runner ticking ($(env_get "$RUN_DIR/run.env" E2E_PROFILES))"; return 0; }
        if ! pid_alive "$RUN_DIR/pids/connector.pid"; then
            tail -n 40 "$RUN_DIR/pids/connector.log" >&2 || true
            die "nano-connector-runner exited during startup (log: $RUN_DIR/pids/connector.log)"
        fi
        sleep 2
    done
    die "nano-connector-runner never ticked (log: $RUN_DIR/pids/connector.log)"
}

native_start() {
    # native_start <svc>: start one app binary in the background, pid + log in the run dir.
    local svc="$1" bin
    case "$svc" in
        api) bin=nanosiem-api ;; search) bin=nanosiem-search ;; jobs) bin=nanosiem-jobs ;;
        connector) bin=nano-connector-runner ;;
        *) die "unknown native service $svc" ;;
    esac
    local exe; exe="$(target_dir)/$(env_get "$RUN_DIR/run.env" E2E_PROFILE_DIR)/$bin"
    [[ -x "$exe" ]] || die "$exe missing (build first, or drop --no-build)"
    pid_alive "$RUN_DIR/pids/$svc.pid" && { ok "$svc already running"; return 0; }
    local token pid start
    token="$(openssl rand -hex 16)"
    (
        # shellcheck disable=SC1091
        . "$RUN_DIR/app.env"
        # shellcheck disable=SC1091
        [[ "$svc" == connector ]] && . "$RUN_DIR/connector.env"
        export E2E_PROC_OWNER="$token"
        cd "$ROOT"
        exec "$exe" >>"$RUN_DIR/pids/$svc.log" 2>&1 </dev/null
    ) &
    pid=$!
    # Not a job of this shell: no "Killed" job-control noise at teardown.
    disown "$pid" 2>/dev/null || true
    start="$(proc_start "$pid")"
    [[ -n "$start" ]] || die "$svc exited immediately (log: $RUN_DIR/pids/$svc.log)"
    printf '%s\t%s\t%s\n' "$pid" "$start" "$token" > "$RUN_DIR/pids/$svc.pid"
}

native_stop() {
    # native_stop <sig> <svc...>: signal all at once, give them 20s, then KILL.
    # Identity is re-validated before every signal, the final KILL included.
    local sig="$1" svc live=(); shift
    for svc in "$@"; do
        if signal_owned "$sig" "$RUN_DIR/pids/$svc.pid"; then
            live+=("$svc")
        else
            rm -f "$RUN_DIR/pids/$svc.pid"
        fi
    done
    (( ${#live[@]} )) || return 0
    local alive
    for _ in $(seq 1 40); do
        alive=0
        for svc in "${live[@]}"; do pid_alive "$RUN_DIR/pids/$svc.pid" && alive=1; done
        (( alive )) || break
        sleep 0.5
    done
    for svc in "${live[@]}"; do
        signal_owned KILL "$RUN_DIR/pids/$svc.pid" || true
        rm -f "$RUN_DIR/pids/$svc.pid"
    done
}

native_health_url() {
    local port
    case "$1" in
        api) port="$(env_get "$RUN_DIR/run.env" E2E_API_PORT)" ;;
        search) port="$(env_get "$RUN_DIR/run.env" E2E_SEARCH_PORT)" ;;
        jobs) port="$(env_get "$RUN_DIR/run.env" E2E_JOBS_PORT)" ;;
    esac
    printf 'http://127.0.0.1:%s/health' "$port"
}

native_migrate() {
    local exe; exe="$(target_dir)/$(env_get "$RUN_DIR/run.env" E2E_PROFILE_DIR)/clickhouse_migrator"
    [[ -x "$exe" ]] || die "$exe missing (build first)"
    log "running clickhouse_migrator (log: $RUN_DIR/artifacts/migrator.log)"
    (
        # shellcheck disable=SC1091
        . "$RUN_DIR/app.env"
        cd "$ROOT"
        "$exe"
    ) > "$RUN_DIR/artifacts/migrator.log" 2>&1 \
        || { tail -n 30 "$RUN_DIR/artifacts/migrator.log" >&2; die "migrator failed"; }
    ok "migrations applied"
}

# ---------------------------------------------------------------- docker app
docker_images() {
    local tag
    case "$APP_MODE" in
        image:*)
            tag="${APP_MODE#image:}"
            # ghcr.io/nano-rs/nano-* are the OPEN-CORE builds (no enterprise
            # routes); an enterprise run needs the enterprise release images.
            local prefix="ghcr.io/nano-rs/nano"
            if [[ "$EDITION" == enterprise ]]; then
                prefix="${E2E_ENTERPRISE_IMAGE_PREFIX:-us-central1-docker.pkg.dev/nano-rs/nanosiem-customer/nanosiem}"
            fi
            put E2E_IMAGE_API "$prefix-api:$tag"
            put E2E_IMAGE_SEARCH "$prefix-search:$tag"
            put E2E_IMAGE_JOBS "$prefix-jobs:$tag"
            ;;
        docker)
            tag="e2e-$(git -C "$ROOT" rev-parse --short=12 HEAD)-$EDITION"
            put E2E_IMAGE_API "nanoe2e/nano-api:$tag"
            put E2E_IMAGE_SEARCH "nanoe2e/nano-search:$tag"
            put E2E_IMAGE_JOBS "nanoe2e/nano-jobs:$tag"
            ;;
    esac
}

docker_build() {
    [[ "$APP_MODE" == docker ]] || return 0
    local t img
    for t in api search jobs; do
        img="$(env_get "$RUN_DIR/compose.env" "E2E_IMAGE_${t^^}")"
        if docker image inspect "$img" >/dev/null 2>&1 && ! git -C "$ROOT" status --porcelain | grep -q .; then
            ok "reusing $img (clean tree at the same SHA)"; continue
        fi
        log "docker build --target $t ($img); log: $RUN_DIR/artifacts/build-$t.log"
        DOCKER_BUILDKIT=1 docker build --target "$t" --build-arg "EDITION=$EDITION" -t "$img" "$ROOT" \
            > "$RUN_DIR/artifacts/build-$t.log" 2>&1 \
            || { tail -n 30 "$RUN_DIR/artifacts/build-$t.log" >&2; die "docker build $t failed"; }
    done
}

# ---------------------------------------------------------------- C05 license (NAN-5331)
# The logic lives in e2e/nano_e2e/c05_license.py (stdlib only, system python3).
license_py() { (cd "$PY_DIR" && python3 -m nano_e2e.c05_license "$@"); }

# Validate the NANO_E2E_* license env before anything is created.
license_env_check() {
    if [[ -z "${NANO_E2E_INSTALLATION_ID:-}${NANO_E2E_INSTALLATION_ORG_ID:-}${NANO_E2E_C05_LICENSE_FILE:-}" ]]; then
        return 0
    fi
    license_py check-env --repo-root "$ROOT" || die "invalid C05 license environment (see e2e/README.md)"
    if [[ "$EDITION" != enterprise ]]; then
        warn "NANO_E2E_INSTALLATION_*/NANO_E2E_C05_LICENSE_FILE ignored: --edition $EDITION has no C05 license"
    fi
}

# Replace the identity the enterprise overlay migration generated with the
# pinned one. Runs after the migrator and before any app process starts, so
# no license, ledger row or ClickHouse witness exists yet; the SQL refuses
# anyway once license state exists, and is a no-op for the same identity.
seed_installation_identity() {
    [[ -n "${NANO_E2E_INSTALLATION_ID:-}" ]] || return 0
    [[ "$EDITION" == enterprise ]] || return 0
    local out
    out="$(license_py seed-sql | dc exec -T postgres psql -X -qAt -U nanosiem -d nanosiem \
        -v "iid=$NANO_E2E_INSTALLATION_ID" -v "oid=$NANO_E2E_INSTALLATION_ORG_ID")" \
        || die "seeding the installation identity failed"
    license_py check-seeded <<<"$out" || die "installation identity not pinned"
    ok "installation identity pinned: $NANO_E2E_INSTALLATION_ID (org $NANO_E2E_INSTALLATION_ORG_ID)"
}

# Import NANO_E2E_C05_LICENSE_FILE as the bootstrapped admin; fail unless the
# license is then active. Never prints the file.
import_c05_license() {
    [[ -n "${NANO_E2E_C05_LICENSE_FILE:-}" ]] || return 0
    [[ "$EDITION" == enterprise ]] || return 0
    if (( DEFER_ADMIN )); then
        # No admin yet: the deferred first-run setup (nano_e2e.firstrun)
        # imports it once the scenarios have created the admin.
        ok "C05 license import deferred to first-run setup (--defer-admin)"
        return 0
    fi
    E2E_API_URL="http://127.0.0.1:$(env_get "$RUN_DIR/run.env" E2E_API_PORT)" \
    E2E_ADMIN_ENV="$RUN_DIR/admin.env" \
        license_py import --repo-root "$ROOT" || die "C05 license import failed (file contents not shown)"
    ok "C05 license imported and active"
}

cmd_license_ids() {
    resolve_run
    [[ "$(env_get "$RUN_DIR/run.env" E2E_EDITION)" == enterprise ]] \
        || die "run $RUN_ID is not an enterprise stack (no installation identity)"
    local out
    out="$(license_py ids-sql | dc exec -T postgres psql -X -qAt -U nanosiem -d nanosiem)" \
        || die "could not read the installation identity (is run $RUN_ID up?)"
    license_py parse-ids <<<"$out" || die "could not read the installation identity"
}

# ---------------------------------------------------------------- up
cmd_up() {
    command -v docker >/dev/null || die "docker not found"
    docker info >/dev/null 2>&1 || die "docker daemon not reachable"
    RUN_ID="${NEW_RUN_ID:-$(new_run_id)}"
    validate_run_id "$RUN_ID"
    RUN_DIR="$E2E_HOME/$RUN_ID"; PROJECT="nanoe2e-$RUN_ID"
    [[ "$PROJECT" != nanoch* ]] || die "refusing project name $PROJECT"
    [[ ! -e "$RUN_DIR" ]] || die "run dir $RUN_DIR already exists"
    license_env_check
    mkdir -p "$RUN_DIR"/{artifacts,pids,data,clickhouse} \
        "$RUN_DIR"/vector-dynamic/{sources/parsers,sources/configs,ingest-tokens} "$RUN_DIR"/vector-validation
    chmod 700 "$RUN_DIR"
    initialize_e2e_clickhouse_config
    ln -sfn "$RUN_ID" "$E2E_HOME/current"
    # A failed bring-up must not leave containers or processes behind
    # (unless --keep, for debugging). Artifacts are kept either way.
    UP_DONE=0
    trap 'up_exit_guard' EXIT
    log "e2e run $RUN_ID (project $PROJECT, app $APP_MODE, edition $EDITION, profiles: ${PROFILES[*]:-none})"

    log "run dir: $RUN_DIR"

    gen_secrets
    render_resource_sizing
    if [[ "$APP_MODE" != native ]]; then docker_images >> "$RUN_DIR/compose.env"; fi
    {
        put E2E_RUN_ID "$RUN_ID"; put E2E_PROJECT "$PROJECT"; put E2E_APP_MODE "${APP_MODE%%:*}"
        put E2E_EDITION "$EDITION"; put E2E_PROFILE_DIR "$(profile_dir)"
        put E2E_PERSONA_AI_MODE "${E2E_PERSONA_AI_MODE:-stub}"
        put E2E_PROFILES "${PROFILES[*]}"; put E2E_ADMIN_DEFERRED "$DEFER_ADMIN"
        if content_acceptance_selected; then put E2E_CONTENT_ACCEPTANCE 1; else put E2E_CONTENT_ACCEPTANCE 0; fi
    } > "$RUN_DIR/run.env"
    # Host ports are chosen here (free 127.0.0.1 ports) and published
    # explicitly: compose's ephemeral `127.0.0.1::<port>` would hand out NEW
    # ports on every container restart, and scenarios restart Vector.
    allocate_ports >> "$RUN_DIR/run.env"
    grep -E '^E2E_[A-Z_]*_PORT=' "$RUN_DIR/run.env" >> "$RUN_DIR/compose.env"
    generate_soar_lab_pki
    if run_has_profile ai-stub; then
        put E2E_ALLOW_PRIVATE_AI_ENDPOINTS true >> "$RUN_DIR/compose.env"
    else
        put E2E_ALLOW_PRIVATE_AI_ENDPOINTS false >> "$RUN_DIR/compose.env"
    fi

    # Build first: a compile error should not leave containers behind.
    if (( ! INFRA_ONLY )); then
        if [[ "$APP_MODE" == native ]] && (( ! NO_BUILD )); then native_build; fi
        docker_build
    fi

    log "starting infra: ${INFRA[*]}"
    dc up -d "${INFRA[@]}" > "$RUN_DIR/artifacts/compose-up.log" 2>&1 \
        || { tail -n 30 "$RUN_DIR/artifacts/compose-up.log" >&2; die "compose up failed"; }
    wait_http "http://127.0.0.1:$(env_get "$RUN_DIR/run.env" E2E_CH_HTTP_PORT)/ping" ClickHouse 90
    # The postgres image answers pg_isready from its temporary init server,
    # then restarts; require three consecutive successes 2s apart.
    local streak=0
    for _ in $(seq 1 90); do
        if dc exec -T postgres pg_isready -U nanosiem -d nanosiem >/dev/null 2>&1; then
            streak=$((streak + 1)); (( streak >= 3 )) && break
        else
            streak=0
        fi
        sleep 2
    done
    (( streak >= 3 )) || die "PostgreSQL not ready"
    ok "PostgreSQL ready"

    start_content_fixture

    # The API must see the provider when it starts: provider configuration is
    # applied by the persona fixture after admin bootstrap.
    start_ai_stub
    start_soar_lab

    if (( INFRA_ONLY )); then
        # Migration / upgrade lanes drive the migrator themselves.
        write_stack_env
        UP_DONE=1; trap - EXIT
        ok "infra up (no app, no migrations): $RUN_ID"
        printf '%s\n' "$RUN_DIR/stack.env"
        return 0
    fi

    if [[ "$APP_MODE" == native ]]; then
        write_app_env
        native_migrate
        seed_installation_identity
        # Vector after the migrator, so its sinks start against the schema.
        dc up -d vector >> "$RUN_DIR/artifacts/compose-up.log" 2>&1 \
            || { tail -n 30 "$RUN_DIR/artifacts/compose-up.log" >&2; die "compose up vector failed"; }
        local svc
        for svc in search jobs api; do native_start "$svc"; done
        for svc in search jobs api; do
            wait_http "$(native_health_url "$svc")" "nano-$svc" 150 "$RUN_DIR/pids/$svc.pid"
        done
        if run_has_runner; then
            write_connector_env
            native_start connector
            wait_connector
        fi
    else
        log "running migrator container"
        dc run --rm clickhouse-migrate > "$RUN_DIR/artifacts/migrator.log" 2>&1 \
            || { tail -n 30 "$RUN_DIR/artifacts/migrator.log" >&2; die "migrator failed"; }
        seed_installation_identity
        dc up -d vector nano-search nano-jobs nano-api >> "$RUN_DIR/artifacts/compose-up.log" 2>&1 \
            || { tail -n 30 "$RUN_DIR/artifacts/compose-up.log" >&2; die "compose up (app) failed"; }
        local p
        for p in API SEARCH JOBS; do
            wait_http "http://127.0.0.1:$(env_get "$RUN_DIR/run.env" "E2E_${p}_PORT")/health" "nano-${p,,}" 150
        done
    fi
    wait_http "http://127.0.0.1:$(env_get "$RUN_DIR/run.env" E2E_HEC_PORT)/services/collector/health" "Vector HEC" 60
    start_edge

    if (( DEFER_ADMIN )); then
        venv_ensure
        ok "first-run setup deferred to the scenarios (--defer-admin)"
    else
        bootstrap_admin
    fi
    import_c05_license
    write_stack_env
    UP_DONE=1; trap - EXIT
    ok "stack up: $RUN_ID"
    printf '%s\n' "$RUN_DIR/stack.env"
}

up_exit_guard() {
    local rc=$? final
    (( UP_DONE )) && return 0
    if (( KEEP )); then
        warn "bring-up failed; stack kept (--keep): scripts/e2e.sh down --run $RUN_ID"
    else
        warn "bring-up failed; tearing down $PROJECT (artifacts kept: $RUN_DIR/artifacts)"
        collect_artifacts >/dev/null 2>&1 || true
        cmd_down >/dev/null 2>&1 || true
    fi
    leak_guard_stop_tracked_pids
    final="$rc"
    if (( LEAK_GUARD_ACTIVE )); then
        leak_guard_finish "$rc" || final=$?
    fi
    trap - EXIT INT TERM
    exit "$final"
}

allocate_ports() {
    # One distinct free port per published endpoint (and the native app).
    local name port seen=" "
    for name in PG CH_HTTP CH_NATIVE REDIS VECTOR_HTTP HEC OTLP_HTTP VECTOR_METRICS API SEARCH JOBS MOCK_VENDOR AI_STUB EDGE CONTENT_FIXTURE SOAR_VENDOR SOAR_SMTP SOAR_MAILPIT_API; do
        while :; do
            port="$(free_port)"
            [[ "$seen" != *" $port "* ]] && break
        done
        seen+="$port "
        put "E2E_${name}_PORT" "$port"
    done
}

bootstrap_admin() {
    # Local admin via the first-run setup endpoint, then an admin API key for
    # the scenarios. Secrets flow through files in the 0700 run dir only.
    venv_ensure
    local api; api="http://127.0.0.1:$(env_get "$RUN_DIR/run.env" E2E_API_PORT)"
    E2E_API_URL="$api" E2E_ADMIN_EMAIL="admin@e2e.nano.local" \
    E2E_ADMIN_PASSWORD="$(env_get "$RUN_DIR/compose.env" NANO_ADMIN_PASSWORD)" \
    E2E_SETUP_TOKEN="$(env_get "$RUN_DIR/compose.env" NANO_SETUP_TOKEN)" \
    E2E_OUT="$RUN_DIR/admin.env" \
        "$VENV/bin/python" -I -m nano_e2e.bootstrap \
        || die "admin bootstrap failed (see $RUN_DIR/pids/api.log)"
    ok "admin + API key created"
}

write_stack_env() {
    # The ONE environment file for scenarios and legacy lanes: every legacy
    # test env var spelling, pointed at this stack.
    local r="$RUN_DIR/run.env" c="$RUN_DIR/compose.env" a="$RUN_DIR/admin.env"
    local pg ch chn redis api search jobs hec vhttp otlp vmet ai_stub pgurl churl
    pg="$(env_get "$r" E2E_PG_PORT)"; ch="$(env_get "$r" E2E_CH_HTTP_PORT)"; chn="$(env_get "$r" E2E_CH_NATIVE_PORT)"
    redis="$(env_get "$r" E2E_REDIS_PORT)"; api="$(env_get "$r" E2E_API_PORT)"; search="$(env_get "$r" E2E_SEARCH_PORT)"
    jobs="$(env_get "$r" E2E_JOBS_PORT)"; hec="$(env_get "$r" E2E_HEC_PORT)"; vhttp="$(env_get "$r" E2E_VECTOR_HTTP_PORT)"
    otlp="$(env_get "$r" E2E_OTLP_HTTP_PORT)"; vmet="$(env_get "$r" E2E_VECTOR_METRICS_PORT)"
    ai_stub="$(env_get "$r" E2E_AI_STUB_PORT)"
    pgurl="postgres://nanosiem:$(env_get "$c" POSTGRES_PASSWORD)@127.0.0.1:${pg}/nanosiem"
    churl="http://127.0.0.1:${ch}"
    local chpw chadm rawsql
    chpw="$(env_get "$c" CLICKHOUSE_PASSWORD)"; chadm="$(env_get "$c" CLICKHOUSE_ADMIN_PASSWORD)"
    rawsql="$(env_get "$c" CLICKHOUSE_RAWSQL_PASSWORD)"
    local vector_image
    vector_image="$(grep -E '^\s+image: ghcr.io/nano-rs/vector' "$COMPOSE_BASE" | head -n1 | awk '{print $2}')"
    (
        umask 077
        {
            echo "# nano-e2e stack.env for run $RUN_ID (generated; contains throwaway secrets)"
            put E2E_RUN_ID "$RUN_ID"; put E2E_PROJECT "$PROJECT"; put E2E_RUN_DIR "$RUN_DIR"
            put E2E_ARTIFACT_DIR "$RUN_DIR/artifacts"; put E2E_APP_MODE "$(env_get "$r" E2E_APP_MODE)"
            put E2E_EDITION "$(env_get "$r" E2E_EDITION)"; put E2E_RUNNER "$ROOT/scripts/e2e.sh"
            put E2E_VECTOR_CONTAINER "${PROJECT}-vector"; put E2E_VECTOR_DYNAMIC_DIR "$RUN_DIR/vector-dynamic"
            # app endpoints
            put NANOSIEM_API_URL "http://127.0.0.1:$api"; put NANOSIEM_SEARCH_URL "http://127.0.0.1:$search"
            put NANOSIEM_JOBS_URL "http://127.0.0.1:$jobs"; put NANOSIEM_HEC_URL "http://127.0.0.1:$hec"
            put NANOSIEM_VECTOR_HTTP_URL "http://127.0.0.1:$vhttp"; put NANOSIEM_OTLP_HTTP_URL "http://127.0.0.1:$otlp"
            put NANOSIEM_VECTOR_METRICS_URL "http://127.0.0.1:$vmet/metrics"
            put NANOSIEM_API_KEY "$(env_get "$a" NANOSIEM_API_KEY)"
            put NANO_ADMIN_EMAIL "admin@e2e.nano.local"; put NANO_ADMIN_PASSWORD "$(env_get "$c" NANO_ADMIN_PASSWORD)"
            # NAN-5237: first-run setup bearer (docker app mode; native has none).
            put NANO_SETUP_TOKEN "$(env_get "$c" NANO_SETUP_TOKEN)"
            # First-run setup left to the scenarios (UI suite: in the browser).
            # The harness writes admin.env + the key back into this file after.
            put E2E_ADMIN_DEFERRED "$(env_get "$r" E2E_ADMIN_DEFERRED)"
            put E2E_PERSONA_AI_MODE "$(env_get "$r" E2E_PERSONA_AI_MODE)"
            put E2E_PROFILES "$(env_get "$r" E2E_PROFILES)"
            put E2E_MOCK_VENDOR_PORT "$(env_get "$r" E2E_MOCK_VENDOR_PORT)"
            put E2E_AI_STUB_URL "http://127.0.0.1:$ai_stub"
            if [[ "$(env_get "$r" E2E_CONTENT_ACCEPTANCE)" == 1 ]]; then
                put E2E_CONTENT_FIXTURE_URL "http://127.0.0.1:$(env_get "$r" E2E_CONTENT_FIXTURE_PORT)"
                put E2E_CONTENT_FIXTURE_JOURNAL "$RUN_DIR/artifacts/content-fixture.jsonl"
            fi
            if [[ "$(env_get "$r" E2E_APP_MODE)" == native ]]; then
                put E2E_AI_PROVIDER_BASE_URL "http://127.0.0.1:$ai_stub/v1"
            else
                put E2E_AI_PROVIDER_BASE_URL "http://ai-stub:8080/v1"
            fi
            put NANOSIEM_EDGE_URL "http://127.0.0.1:$(env_get "$r" E2E_EDGE_PORT)"
            put E2E_SOAR_VENDOR_PORT "$(env_get "$r" E2E_SOAR_VENDOR_PORT)"
            put E2E_SOAR_SMTP_PORT "$(env_get "$r" E2E_SOAR_SMTP_PORT)"
            put E2E_SOAR_MAILPIT_API_URL "http://127.0.0.1:$(env_get "$r" E2E_SOAR_MAILPIT_API_PORT)"
            put E2E_SOAR_CA_PATH "$RUN_DIR/soar-lab/ca.pem"
            put E2E_SOAR_CERT_PATH "$RUN_DIR/soar-lab/cert.pem"
            put E2E_SOAR_KEY_PATH "$RUN_DIR/soar-lab/key.pem"
            put NANOSIEM_ENCRYPTION_KEY "$(env_get "$c" NANOSIEM_ENCRYPTION_KEY)"
            put VECTOR_AUTH_TOKEN "$(env_get "$c" VECTOR_AUTH_TOKEN)"
            # ClickHouse (every legacy spelling)
            for k in NANOSIEM_TEST_CLICKHOUSE_URL CLICKHOUSE_TEST_URL CLICKHOUSE_URL SOAR_TEST_CLICKHOUSE_URL MIGRATOR_BOOTSTRAP_CH_URL; do
                put "$k" "$churl"
            done
            for k in NANOSIEM_TEST_CLICKHOUSE_USER CLICKHOUSE_USER CLICKHOUSE_TEST_USER; do put "$k" nanosiem; done
            for k in NANOSIEM_TEST_CLICKHOUSE_PASSWORD CLICKHOUSE_PASSWORD CLICKHOUSE_TEST_PASSWORD SOAR_TEST_CLICKHOUSE_PASSWORD; do
                put "$k" "$chpw"
            done
            put CLICKHOUSE_DATABASE nanosiem; put CLICKHOUSE_TEST_DB nanosiem
            put CLICKHOUSE_ADMIN_USER nanosiem_admin; put CLICKHOUSE_ADMIN_PASSWORD "$chadm"
            put SOAR_TEST_CLICKHOUSE_ADMIN_PASSWORD "$chadm"
            put MIGRATOR_BOOTSTRAP_CH_USER nanosiem_admin; put MIGRATOR_BOOTSTRAP_CH_PASSWORD "$chadm"
            put CLICKHOUSE_RAWSQL_PASSWORD "$rawsql"; put SOAR_TEST_CLICKHOUSE_RAWSQL_PASSWORD "$rawsql"
            put CLICKHOUSE_RAWSQL_NOAUDIT_PASSWORD "$(env_get "$c" CLICKHOUSE_RAWSQL_NOAUDIT_PASSWORD)"
            put CLICKHOUSE_INGEST_PASSWORD "$(env_get "$c" CLICKHOUSE_INGEST_PASSWORD)"
            put CLICKHOUSE_VECTOR_PASSWORD "$(env_get "$c" CLICKHOUSE_VECTOR_PASSWORD)"
            # CLICKHOUSE_SELF_* is how ClickHouse reaches ITSELF (dictionary
            # sources), so it is the in-container address, not the host port.
            put CLICKHOUSE_SELF_HOST localhost; put CLICKHOUSE_SELF_PORT 9000
            put CLICKHOUSE_SELF_USER nanosiem; put CLICKHOUSE_SELF_PASSWORD "$chpw"
            put E2E_CH_NATIVE_PORT "$chn"
            # PostgreSQL (every legacy spelling)
            for k in DATABASE_URL TEST_DATABASE_URL NANOSIEM_TEST_DATABASE_URL NANO_TEST_DATABASE_URL; do put "$k" "$pgurl"; done
            # Dictionary SOURCE(POSTGRESQL ...) is resolved by ClickHouse over
            # the compose network, so the host is the service name.
            put POSTGRES_DICT_HOST postgres; put POSTGRES_DICT_PASSWORD "$(env_get "$c" POSTGRES_PASSWORD)"
            put NANO_SCHEMA_PROFILE "$(env_get "$c" NANO_SCHEMA_PROFILE)"
            put SKIP_DB_TESTS 0
            # Redis protocol (Valkey)
            put NANOSIEM_TEST_REDIS_URL "redis://127.0.0.1:$redis"; put REDIS_URL "redis://127.0.0.1:$redis"
            # Guards + images
            put NANOSIEM_ALLOW_DESTRUCTIVE_TESTS 1
            put NANOSIEM_TEST_VECTOR_IMAGE "$vector_image"
            [[ -n "${NANO_CONTENT_RULES_DIR:-}" ]] && put NANO_CONTENT_RULES_DIR "$NANO_CONTENT_RULES_DIR"
            true
        } > "$RUN_DIR/stack.env"
    )
}

# ---------------------------------------------------------------- python venv
venv_ensure() {
    local stamp="$VENV/.req-sha" want
    local sha=(shasum -a 256); command -v shasum >/dev/null 2>&1 || sha=(sha256sum)
    want="$(cat "$PY_DIR/requirements.lock" "$PY_DIR/pyproject.toml" | "${sha[@]}" | cut -c1-16)"
    if [[ -x "$VENV/bin/python" && "$(cat "$stamp" 2>/dev/null)" == "$want" ]]; then return 0; fi
    log "bootstrapping e2e/.venv (pinned deps)"
    if command -v uv >/dev/null 2>&1; then
        uv venv -q "$VENV" && uv pip install -q --python "$VENV/bin/python" -r "$PY_DIR/requirements.lock" -e "$PY_DIR"
    else
        python3 -m venv "$VENV" && PIP_DISABLE_PIP_VERSION_CHECK=1 "$VENV/bin/pip" install -q \
            -r "$PY_DIR/requirements.lock" && PIP_DISABLE_PIP_VERSION_CHECK=1 "$VENV/bin/pip" install -q --no-deps -e "$PY_DIR"
    fi || die "venv bootstrap failed"
    printf '%s' "$want" > "$stamp"
}

# ---------------------------------------------------------------- NAN-4955 content acceptance fixture
fixture_pid_owned() {
    local file="$RUN_DIR/pids/content-fixture.pid"
    [[ -s "$file" ]] || return 1
    local pid start token cmd
    pid="$(cut -f1 "$file")"; start="$(cut -f2 "$file")"; token="$(cut -f3 "$file")"
    [[ "$pid" =~ ^[1-9][0-9]*$ && "$token" =~ ^[0-9a-f]{32}$ && -n "$start" ]] || return 1
    [[ "$(proc_start "$pid")" == "$start" ]] || return 1
    cmd="$(ps -o command= -p "$pid" 2>/dev/null)" || return 1
    [[ "$cmd" == *"$ROOT/e2e/nano_e2e/content_fixture.py"* \
        && "$cmd" == *"$RUN_DIR/artifacts/content-fixture.jsonl"* ]] || return 1
    proc_has_owner "$pid" "$token" || return 1
    printf '%s' "$pid"
}

start_content_fixture() {
    [[ "$(env_get "$RUN_DIR/run.env" E2E_CONTENT_ACCEPTANCE)" == 1 ]] || return 0
    venv_ensure
    local port token pid start
    port="$(env_get "$RUN_DIR/run.env" E2E_CONTENT_FIXTURE_PORT)"
    ( umask 077; printf 'NAN-4955 local acceptance license\n' > "$RUN_DIR/content-acceptance-license" )
    token="$(openssl rand -hex 16)"
    (
        export E2E_PROC_OWNER="$token"
        exec "$VENV/bin/python" -I "$ROOT/e2e/nano_e2e/content_fixture.py" \
            --port "$port" --root "$ROOT" --journal "$RUN_DIR/artifacts/content-fixture.jsonl" \
            >>"$RUN_DIR/pids/content-fixture.log" 2>&1 </dev/null
    ) &
    pid=$!
    disown "$pid" 2>/dev/null || true
    start="$(proc_start "$pid")"
    [[ -n "$start" ]] || die "content acceptance fixture exited immediately"
    printf '%s\t%s\t%s\n' "$pid" "$start" "$token" > "$RUN_DIR/pids/content-fixture.pid"
    local healthy=0
    for _ in $(seq 1 40); do
        if curl -fsS -o /dev/null --max-time 2 "http://127.0.0.1:$port/health" 2>/dev/null; then
            healthy=1; break
        fi
        fixture_pid_owned >/dev/null || {
            tail -n 40 "$RUN_DIR/pids/content-fixture.log" >&2 || true
            die "content acceptance fixture exited during startup"
        }
        sleep 0.5
    done
    (( healthy )) || die "content acceptance fixture not healthy on $port"
    ok "NAN-4955 signed publisher + GitHub egress sinkhole healthy"
}

stop_content_fixture() {
    local pid
    pid="$(fixture_pid_owned)" || { rm -f "$RUN_DIR/pids/content-fixture.pid"; return 0; }
    kill -TERM "$pid" 2>/dev/null || true
    for _ in $(seq 1 20); do
        fixture_pid_owned >/dev/null || break
        sleep 0.25
    done
    pid="$(fixture_pid_owned)" && kill -KILL "$pid" 2>/dev/null || true
    rm -f "$RUN_DIR/pids/content-fixture.pid"
}

# ---------------------------------------------------------------- creds
# Prints the credential source: doppler | file | none. Never prints values.
creds_source() {
    if [[ "${NANO_E2E_NO_DOPPLER:-0}" != 1 ]] && command -v doppler >/dev/null 2>&1 \
        && doppler run -p "$DOPPLER_PROJECT" -c "$DOPPLER_CONFIG" -- true >/dev/null 2>&1; then
        echo doppler; return
    fi
    if [[ -f "$CREDS_FILE" ]]; then
        local mode; mode="$(stat -f '%Lp' "$CREDS_FILE" 2>/dev/null || stat -c '%a' "$CREDS_FILE")"
        [[ "$mode" == 600 || "$mode" == 400 ]] || die "$CREDS_FILE must be mode 0600 (is $mode)"
        echo file; return
    fi
    echo none
}

# with_creds <cmd...>: run cmd with cloud credentials in its environment only.
with_creds() {
    local src; src="$(creds_source)"
    (
        export E2E_CREDS_SOURCE="$src"
        case "$src" in
            doppler) doppler run -p "$DOPPLER_PROJECT" -c "$DOPPLER_CONFIG" -- "$@" ;;
            file) load_env_file "$CREDS_FILE"; "$@" ;;
            *) "$@" ;;
        esac
    )
}

# ---------------------------------------------------------------- run
suite_paths() {
    local s out=()
    [[ ${#POSITIONAL[@]} -eq 0 ]] && POSITIONAL=(all)
    for s in "${POSITIONAL[@]}"; do
        case "$s" in
            all) out+=("$PY_DIR/tests") ;;
            fast) out+=("$PY_DIR/tests/test_base.py" "$PY_DIR/tests/test_ingest.py") ;;
            ui)
                out+=("$PY_DIR/tests/ui")
                # Enterprise UI scenarios live under tests/enterprise/ (the
                # mirror strips it). A `+` companion runs with the suite but
                # is not coverage-gated on its own: today it is placeholders.
                [[ -d "$PY_DIR/tests/enterprise/ui" ]] && out+=("+$PY_DIR/tests/enterprise/ui") ;;
            content_acceptance) out+=("$PY_DIR/tests/enterprise/content_acceptance") ;;
            otlp) out+=("$PY_DIR/tests/test_otlp.py" "$PY_DIR/tests/ui/test_otlp_observability.py") ;;
            personas) out+=("$PY_DIR/tests/personas") ;;
            soar)
                [[ -d "$PY_DIR/tests/enterprise/soar" ]] \
                    || die "suite 'soar' needs the enterprise test tree"
                out+=("$PY_DIR/tests/enterprise/soar") ;;
            *)
                if [[ -d "$PY_DIR/tests/$s" ]]; then out+=("$PY_DIR/tests/$s")
                elif [[ -f "$PY_DIR/tests/test_$s.py" ]]; then out+=("$PY_DIR/tests/test_$s.py")
                else die "unknown suite '$s' (see e2e/tests)"; fi ;;
        esac
    done
    printf '%s\n' "${out[@]}"
}

# A live stack from a previous `up` (the `current` run with a stack.env and a
# running Vector). `run` without --run reuses it, so
# `up && run base && down` drives one stack; --fresh forces a new one.
current_live() {
    local id
    [[ -L "$E2E_HOME/current" ]] || return 1
    id="$(basename "$(readlink "$E2E_HOME/current")")"
    [[ -f "$E2E_HOME/$id/stack.env" ]] || return 1
    [[ -n "$(docker ps -q --filter "name=^nanoe2e-$id-vector$" 2>/dev/null)" ]] || return 1
    RUN_ID="$id"
}

# selects_suite <name...>: true when the run selects one of these suites
# (`all`, or no suite at all, selects every suite).
selects_suite() {
    local s w
    [[ ${#POSITIONAL[@]} -eq 0 ]] && return 0
    for s in "${POSITIONAL[@]}"; do
        [[ "$s" == all ]] && return 0
        for w in "$@"; do [[ "$s" == "$w" ]] && return 0; done
    done
    return 1
}

# only_suite <name>: the run selects exactly this suite and nothing else.
only_suite() {
    local s
    [[ ${#POSITIONAL[@]} -gt 0 ]] || return 1
    for s in "${POSITIONAL[@]}"; do [[ "$s" == "$1" ]] || return 1; done
}

# Unlike selects_suite, `all` does not imply this suite's non-production build
# and local publisher. It runs only when explicitly named.
content_acceptance_selected() {
    local s
    for s in "${POSITIONAL[@]}"; do [[ "$s" == content_acceptance ]] && return 0; done
    return 1
}

# The only suites allowed to compile public fixture trust roots. The selected
# cfg is debug-only, requires an explicit opt-in marker, and is rejected by
# release composition before either root can enter an artifact.
soar_lab_selected() {
    [[ "$EDITION" == enterprise ]] \
        && [[ -d "$PY_DIR/tests/enterprise/soar" ]] \
        && selects_suite soar
}

test_trust_composition_selected() {
    content_acceptance_selected || soar_lab_selected
}

CMD_RUN_OWNS_STACK=0
CMD_RUN_FINISHED=0

run_exit_guard() {
    local rc=$? final
    trap - EXIT INT TERM
    (( CMD_RUN_FINISHED )) && exit "$rc"
    if (( CMD_RUN_OWNS_STACK && ! KEEP )); then
        collect_artifacts >/dev/null 2>&1 || true
        cmd_down >/dev/null 2>&1 || true
    fi
    leak_guard_stop_tracked_pids
    final="$rc"
    leak_guard_finish "$rc" || final=$?
    exit "$final"
}

cmd_run() {
    local own_stack=0 web_dist="" final soar_selected=0 soar_explicit=0 suite
    leak_guard_begin "scripts/e2e.sh run"
    CMD_RUN_OWNS_STACK=0
    CMD_RUN_FINISHED=0
    trap 'run_exit_guard' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    if content_acceptance_selected; then
        [[ "$APP_MODE" == native ]] || die "content_acceptance needs --app native"
        [[ "$EDITION" == enterprise ]] || die "content_acceptance needs --edition enterprise"
        [[ -n "$RUN_ID" ]] || FRESH=1
    fi
    for suite in "${POSITIONAL[@]}"; do
        [[ "$suite" == soar ]] && soar_explicit=1
    done
    if (( soar_explicit )) && { [[ "$EDITION" != enterprise ]] || [[ ! -d "$PY_DIR/tests/enterprise/soar" ]]; }; then
        die "the soar suite is enterprise-only"
    fi
    if soar_lab_selected; then
        soar_selected=1
        if [[ "$APP_MODE" != native ]]; then
            (( APP_MODE_EXPLICIT )) && die "the soar suite needs --app native (loopback-only lab transport)"
            APP_MODE=native
        fi
        has_profile soar-lab || PROFILES+=(soar-lab)
        has_profile ai-stub || PROFILES+=(ai-stub)
        # A default/current stack may have been created without the guarded
        # lab transport. Standalone SOAR runs therefore own a fresh stack;
        # explicit --run reuse is allowed only after the checks below.
        [[ -n "$RUN_ID" ]] || FRESH=1
    fi
    # The web build and browser come first: a failure here must not leave a
    # stack behind (cmd_up has already disarmed its own cleanup when it returns).
    # enterprise carries browser scenarios (tests/enterprise/ui, content_acceptance)
    # that need the edition's web build too (NAN-5333).
    if selects_suite ui connectors otlp personas enterprise || content_acceptance_selected; then
        venv_ensure
        # E2E_WEB_DIST: drive a prebuilt UI instead (e.g. another branch's
        # build against this stack); it must contain index.html.
        if [[ -n "${E2E_WEB_DIST:-}" ]]; then
            [[ -f "$E2E_WEB_DIST/index.html" ]] || die "E2E_WEB_DIST=$E2E_WEB_DIST has no index.html"
            web_dist="$E2E_WEB_DIST"; ok "web UI: $web_dist (E2E_WEB_DIST)"
        else
            web_dist="$(web_build "$EDITION")"
        fi
        ui_ensure
    fi
    if [[ -z "$RUN_ID" ]] && { (( FRESH )) || ! current_live; }; then
        own_stack=1
        # A stack this run owns gets what its suites need: the vendor mock +
        # connector runner for pull (connector feeds) and ui, and first-run
        # setup left to the UI suite, which performs it in the browser.
        # connectors (NAN-4961) alone gets the LIVE runner instead: real
        # vendor tenants, no mock (a mixed run keeps the mock; the live
        # scenarios then skip, naming the profile).
        if [[ "$APP_MODE" == native ]] && only_suite connectors && ! has_profile mock-vendor; then
            has_profile connector-live || PROFILES+=(connector-live)
        elif [[ "$APP_MODE" == native ]] && selects_suite pull ui && ! has_profile mock-vendor \
            && ! has_profile connector-live; then
            PROFILES+=(mock-vendor)
        fi
        if selects_suite ui personas; then
            DEFER_ADMIN=1
        fi
        if selects_suite personas && [[ "$EDITION" == enterprise ]] \
            && [[ "${E2E_PERSONA_AI_MODE:-stub}" != real ]] && ! has_profile ai-stub; then
            PROFILES+=(ai-stub)
        fi
        if only_suite ui || only_suite connectors || only_suite otlp || only_suite personas || only_suite content_acceptance; then
            # The OCSF profile is what a new install gets (install.sh); a UI-only
            # run targets it unless the caller pinned a profile. Mixed runs keep
            # the phase-1 default (udm): their parsers are not OCSF-shaped.
            [[ -n "${NANO_SCHEMA_PROFILE:-}" ]] || export NANO_SCHEMA_PROFILE=ocsf
        fi
        cmd_up >/dev/null
        # cmd_up owns (and clears) its bring-up EXIT trap. From this point the
        # run command owns teardown on every exit path, including signals.
        CMD_RUN_OWNS_STACK=1
        trap 'run_exit_guard' EXIT
        trap 'exit 130' INT
        trap 'exit 143' TERM
    else
        resolve_run
        if content_acceptance_selected && [[ "$(env_get "$RUN_DIR/run.env" E2E_CONTENT_ACCEPTANCE)" != 1 ]]; then
            die "run $RUN_ID was not created for content_acceptance; use --fresh"
        fi
        if (( soar_selected )); then
            [[ "$(env_get "$RUN_DIR/run.env" E2E_APP_MODE)" == native ]] \
                || die "the soar suite cannot reuse a non-native stack"
            run_has_profile soar-lab && run_has_profile ai-stub \
                || die "the soar suite needs a stack with soar-lab and ai-stub profiles"
        fi
        log "using live stack $RUN_ID"
        # A kept native stack can outlive one or more app processes (a local
        # crash, laptop sleep, or the parent terminal closing).  `--run`
        # promises to reuse that owned stack, so restore any missing native
        # services and prove their health before handing pytest dead URLs.
        if [[ "$(env_get "$RUN_DIR/run.env" E2E_APP_MODE)" == native ]]; then
            local svc
            for svc in search jobs api; do native_start "$svc"; done
            for svc in search jobs api; do
                wait_http "$(native_health_url "$svc")" "nano-$svc" 150 "$RUN_DIR/pids/$svc.pid"
            done
        fi
    fi
    venv_ensure
    if { selects_suite ui connectors otlp personas || content_acceptance_selected; } \
        && [[ -z "${E2E_WEB_DIST:-}" && "$(env_get "$RUN_DIR/run.env" E2E_EDITION)" != "$EDITION" ]]; then
        # A reused stack decides the edition: build its UI instead.
        web_dist="$(web_build "$(env_get "$RUN_DIR/run.env" E2E_EDITION)")"
    fi
    local paths=() gated=() status=0 listing p
    listing="$(suite_paths)"
    while IFS= read -r p; do
        [[ -n "$p" ]] || continue
        paths+=("${p#+}")
        [[ "$p" == +* ]] || gated+=("$p")
    done <<<"$listing"
    log "running suites: ${POSITIONAL[*]} (credentials: $(creds_source))"
    (
        load_env_file "$RUN_DIR/stack.env"
        cd "$PY_DIR"
        # Each explicitly selected suite must EXECUTE at least one scenario
        # (all-skipped = failure), unless --allow-skips (local exploration).
        export E2E_SUITE_PATHS; E2E_SUITE_PATHS="$(IFS=:; echo "${gated[*]}")"
        export E2E_ALLOW_SKIPS="$ALLOW_SKIPS"
        [[ -n "$web_dist" ]] && export E2E_WEB_DIST="$web_dist"
        with_creds "$VENV/bin/python" -m pytest "${paths[@]}" \
            --junitxml="$RUN_DIR/artifacts/junit-$(date +%s).xml" "${PYTEST_EXTRA[@]}"
    ) || status=$?
    local crc=0; collect_artifacts || crc=$?
    if (( crc == 3 )); then
        err "E2E-SECURITY: a secret remains in $RUN_DIR/artifacts after scrubbing: do NOT upload them"
        (( status != 0 )) || status=3
    elif (( crc != 0 )); then
        warn "artifact collection incomplete"
    fi
    if (( own_stack )); then
        if (( KEEP )); then
            warn "stack kept (--keep): scripts/e2e.sh down --run $RUN_ID"
        else
            cmd_down
        fi
        CMD_RUN_OWNS_STACK=0
    fi
    final="$status"
    leak_guard_stop_tracked_pids
    leak_guard_finish "$status" || final=$?
    CMD_RUN_FINISHED=1
    trap - EXIT INT TERM
    if (( final == 0 )); then ok "e2e passed ($RUN_ID); artifacts: $RUN_DIR/artifacts"
    else warn "e2e FAILED (exit $final); artifacts: $RUN_DIR/artifacts"; fi
    return "$final"
}

# ---------------------------------------------------------------- web UI
# web_build <edition>: build nanosiem-web for the edition once per source tree
# state; prints the dist dir. Cached under target/e2e/web/ by the tree hash of
# nanosiem-web (+ uncommitted changes), so a re-run against the same tree
# reuses it.
web_build() {
    local edition="$1" web="$ROOT/nanosiem-web" key dist log
    command -v npm >/dev/null || die "npm not found (the ui suite builds nanosiem-web)"
    local sha=(shasum -a 256); command -v shasum >/dev/null 2>&1 || sha=(sha256sum)
    key="$( { git -C "$ROOT" rev-parse HEAD:nanosiem-web; git -C "$ROOT" diff HEAD -- nanosiem-web;
              git -C "$ROOT" ls-files -o --exclude-standard -- nanosiem-web | sort \
                  | while IFS= read -r f; do printf '%s\n' "$f"; cat "$ROOT/$f" 2>/dev/null || true; done
            } | "${sha[@]}" | cut -c1-16)"
    dist="$E2E_HOME/web/$edition-$key"
    log="$E2E_HOME/web/$edition-$key.log"
    if [[ -f "$dist/index.html" ]]; then ok "web UI ($edition) cached: $dist"; printf '%s' "$dist"; return 0; fi
    mkdir -p "$E2E_HOME/web"
    log "building nanosiem-web (VITE_EDITION=$edition); log: $log"
    (
        cd "$web"
        # Install only when absent: never reinstall under a checkout whose
        # node_modules a running dev server (:5173) may be using. The build
        # uses the committed src/lib/udm-fields.ts; the generator is skipped
        # because it also writes outside nanosiem-web (docs/, sibling repos).
        [[ -d node_modules ]] || npm ci --no-audit --no-fund
        VITE_EDITION="$edition" npx --no-install vite build --outDir "$dist.tmp" --emptyOutDir
    ) > "$log" 2>&1 || { tail -n 30 "$log" >&2; rm -rf "$dist.tmp"; die "web build failed"; }
    rm -rf "$dist"; mv "$dist.tmp" "$dist" 2>/dev/null || [[ -f "$dist/index.html" ]]
    ok "web UI built: $dist"
    printf '%s' "$dist"
}

ui_ensure() {
    # The UI driver is nanosiem-web/tests/e2e/ui/driver.mjs on puppeteer-core
    # (already a nanosiem-web devDependency, used by crawl-404.mjs) and a local
    # Chrome/Chromium (CHROME_PATH, else the usual install paths).
    command -v node >/dev/null || die "node not found (the ui suite's browser driver runs under Node.js)"
    [[ -d "$ROOT/nanosiem-web/node_modules/puppeteer-core" ]] \
        || (cd "$ROOT/nanosiem-web" && npm ci --no-audit --no-fund >/dev/null) \
        || die "npm ci failed (nanosiem-web)"
    local c found=""
    for c in "${CHROME_PATH:-}" "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
             /Applications/Chromium.app/Contents/MacOS/Chromium /usr/bin/google-chrome \
             /usr/bin/google-chrome-stable /usr/bin/chromium /usr/bin/chromium-browser; do
        [[ -n "$c" && -x "$c" ]] && { found="$c"; break; }
    done
    [[ -n "$found" ]] || die "no Chrome/Chromium found for the ui suite: install one or set CHROME_PATH"
}

collect_artifacts() {
    local a="$RUN_DIR/artifacts" svc
    mkdir -p "$a/logs"
    for svc in postgres clickhouse dragonfly vector nano-api nano-search nano-jobs ai-stub soar-mailpit edge; do
        dc logs --no-color "$svc" > "$a/logs/$svc.log" 2>/dev/null || rm -f "$a/logs/$svc.log"
    done
    for svc in api search jobs connector content-fixture; do
        [[ -f "$RUN_DIR/pids/$svc.log" ]] && cp "$RUN_DIR/pids/$svc.log" "$a/logs/native-$svc.log"
    done
    # Rendered Vector config, through the structured redactor: pull source
    # configs carry cloud credentials (AWS secret keys, Azure client secrets /
    # connection strings), so they are never copied verbatim (NAN-4937 review).
    rm -rf "$a/vector-rendered"
    if [[ -d "$RUN_DIR/vector-dynamic/sources" ]]; then
        guard redact-rendered "$RUN_DIR/vector-dynamic/sources" "$a/vector-rendered" >/dev/null \
            || { rm -rf "$a/vector-rendered"; warn "rendered Vector config not collected (redactor failed)"; }
    fi
    local metrics; metrics="$(env_get "$RUN_DIR/run.env" E2E_VECTOR_METRICS_PORT)"
    [[ -n "$metrics" ]] && curl -fsS --max-time 5 "http://127.0.0.1:$metrics/metrics" > "$a/vector-metrics-end.prom" 2>/dev/null || true
    # ClickHouse diagnostics for the run window (query_log is the first place
    # to look when an assertion saw the wrong rows).
    local started; started="$(env_get "$RUN_DIR/compose.env" E2E_STARTED)"
    ch_admin "SELECT event_time, query_duration_ms, read_rows, result_rows, exception_code, substring(query, 1, 2000) AS query FROM system.query_log WHERE event_time >= toDateTime($started) AND type != 'QueryStart' AND (exception_code != 0 OR query_duration_ms > 1000 OR query ILIKE '%nano-e2e%') ORDER BY event_time FORMAT TSVWithNames" \
        > "$a/ch-query-log.tsv" 2>/dev/null || true
    ch_admin "SELECT name, code, value, last_error_time, last_error_message FROM system.errors WHERE last_error_time >= toDateTime($started) ORDER BY value DESC FORMAT TSVWithNames" \
        > "$a/ch-errors.tsv" 2>/dev/null || true
    # Redacted copy of stack.env (structure only).
    [[ -f "$RUN_DIR/stack.env" ]] && sed -E 's/^([A-Z0-9_]*(PASSWORD|SECRET|KEY|TOKEN|DATABASE_URL)[A-Z0-9_]*)=.*/\1=<redacted>/' \
        "$RUN_DIR/stack.env" > "$a/stack.env.redacted"
    # Belt-and-braces: no generated secret may appear in an artifact.
    scrub_artifacts
}

guard() {
    # The artifact secret guard (e2e/nano_e2e/artifact_guard.py; stdlib only).
    (cd "$PY_DIR" && python3 -m nano_e2e.artifact_guard "$@")
}

scrub_artifacts() {
    # Every known secret (the stack's generated ones, the cloud credentials
    # pytest recorded in the run's 0600 registry, tokens scenarios learned) is
    # replaced in every artifact; any value left anywhere (text or binary)
    # fails with 3. Cleanup succeeding is never the boundary.
    # The C05 license is scrubbed by reading the operator's file in place
    # (never copied into the run dir).
    local extra=()
    [[ -n "${NANO_E2E_C05_LICENSE_FILE:-}" ]] && extra+=(--secret-file "$NANO_E2E_C05_LICENSE_FILE")
    guard scrub "$RUN_DIR/artifacts" --run-dir "$RUN_DIR" \
        --env-file "$RUN_DIR/compose.env" --env-file "$RUN_DIR/admin.env" "${extra[@]}"
}

ch_admin() {
    # The admin password goes through a 0600 curl config in the run dir, never
    # argv (readable in the process list on a shared runner). Removed by down.
    local port cfg="$RUN_DIR/ch-admin.curlrc"
    port="$(env_get "$RUN_DIR/run.env" E2E_CH_HTTP_PORT)"
    [[ -n "$port" ]] || return 1
    if [[ ! -f "$cfg" ]]; then
        ( umask 077; printf 'user = "nanosiem_admin:%s"\n' "$(env_get "$RUN_DIR/compose.env" CLICKHOUSE_ADMIN_PASSWORD)" > "$cfg" )
    fi
    curl -fsS --max-time 20 -K "$cfg" "http://127.0.0.1:$port/" --data-binary "$1"
}

# ---------------------------------------------------------------- down
cmd_down() {
    [[ -n "${RUN_DIR:-}" ]] || resolve_run
    log "tearing down $PROJECT"
    [[ -f "$RUN_DIR/compose.env" ]] && { collect_artifacts >/dev/null 2>&1 || true; }
    stop_content_fixture
    native_stop TERM connector api jobs search
    leak_guard_capture_compose_project "$PROJECT"
    dc down -v --remove-orphans > "$RUN_DIR/artifacts/compose-down.log" 2>&1 || warn "compose down reported errors"
    # Compose can fail partway through daemon shutdown. Remove only resources
    # whose exact project label matches this unique run, including anonymous
    # container volumes (`docker rm -v`) and the project network.
    leak_guard_cleanup_compose_project "$PROJECT"
    # Files written by containers can be root-owned on Linux.
    rm -rf "$RUN_DIR/vector-dynamic" "$RUN_DIR/vector-validation" "$RUN_DIR/data" "$RUN_DIR/clickhouse" "$RUN_DIR/soar-lab" 2>/dev/null \
        || docker run --rm -v "$RUN_DIR:/w" --entrypoint sh alpine:3.20 -c 'rm -rf /w/vector-dynamic /w/vector-validation /w/data /w/clickhouse /w/soar-lab' >/dev/null 2>&1 || true
    rm -f "$RUN_DIR/compose.env" "$RUN_DIR/app.env" "$RUN_DIR/admin.env" "$RUN_DIR/stack.env" "$RUN_DIR/ch-admin.curlrc" \
        "$RUN_DIR/connector.env" "$RUN_DIR/pids/connector.health" "$RUN_DIR/content-acceptance-license" "$RUN_DIR/.secrets.jsonl"
    [[ "$(readlink "$E2E_HOME/current" 2>/dev/null)" == "$RUN_ID" ]] && rm -f "$E2E_HOME/current"
    if (( PURGE )); then rm -rf "$RUN_DIR"; ok "purged $RUN_DIR"; else ok "down; artifacts kept in $RUN_DIR/artifacts"; fi
}

# ---------------------------------------------------------------- svc
cmd_svc() {
    local action="${POSITIONAL[0]:-}" svc="${POSITIONAL[1]:-}"
    [[ "$action" =~ ^(restart|stop|start|kill)$ ]] || die "usage: svc <restart|stop|start|kill> <api|search|jobs|connector|vector>"
    resolve_run
    if [[ "$svc" == vector || "$(env_get "$RUN_DIR/run.env" E2E_APP_MODE)" != native ]]; then
        local csvc="$svc"; [[ "$svc" != vector ]] && csvc="nano-$svc"
        case "$action" in
            restart) dc restart "$csvc" ;; stop) dc stop "$csvc" ;; start) dc start "$csvc" ;;
            kill) dc kill -s KILL "$csvc" ;;
        esac >/dev/null 2>&1 || die "svc $action $svc failed"
        if [[ "$svc" == vector && "$action" =~ ^(restart|start)$ ]]; then
            wait_http "http://127.0.0.1:$(env_get "$RUN_DIR/run.env" E2E_HEC_PORT)/services/collector/health" "Vector HEC" 60
        fi
        return 0
    fi
    [[ "$svc" =~ ^(api|search|jobs|connector)$ ]] || die "unknown service $svc"
    [[ "$svc" != connector ]] || run_has_runner || die "connector runs only with --profile mock-vendor or connector-live"
    case "$action" in
        stop) native_stop TERM "$svc" ;;
        kill) native_stop KILL "$svc" ;;
        start|restart)
            [[ "$action" == restart ]] && native_stop TERM "$svc"
            if [[ "$svc" == connector ]]; then
                rm -f "$RUN_DIR/pids/connector.health"; native_start connector; wait_connector
            else
                native_start "$svc"
                wait_http "$(native_health_url "$svc")" "nano-$svc" 150 "$RUN_DIR/pids/$svc.pid"
            fi ;;
    esac
}

# ---------------------------------------------------------------- env/status
cmd_env() { resolve_run; [[ -f "$RUN_DIR/stack.env" ]] || die "stack.env missing (run is down)"; printf '%s\n' "$RUN_DIR/stack.env"; }

cmd_status() {
    resolve_run
    dc ps --format 'table {{.Service}}\t{{.State}}\t{{.Status}}' || true
    local svc
    for svc in api search jobs connector; do
        [[ "$svc" == connector ]] && ! run_has_runner && continue
        if [[ "$(env_get "$RUN_DIR/run.env" E2E_APP_MODE)" == native ]]; then
            if pid_alive "$RUN_DIR/pids/$svc.pid"; then ok "$svc pid $(cut -f1 "$RUN_DIR/pids/$svc.pid") $(native_health_url "$svc")"
            else warn "$svc not running"; fi
        fi
    done
    printf 'stack.env: %s\n' "$RUN_DIR/stack.env"
}

# ---------------------------------------------------------------- doctor
cmd_doctor() {
    local bad=0
    check() { if eval "$2" >/dev/null 2>&1; then ok "$1"; else warn "$1: $3"; bad=1; fi; }
    ok "edition: $EDITION (default for this tree: $DEFAULT_EDITION), app mode: $APP_MODE"
    check "bash >= 4" "(( BASH_VERSINFO[0] >= 4 ))" "upgrade bash"
    check "docker CLI" "command -v docker" "install Docker"
    check "docker daemon" "docker info" "start Docker"
    check "docker compose v2" "docker compose version" "install the compose plugin"
    local mem; mem="$(docker info --format '{{.MemTotal}}' 2>/dev/null || echo 0)"
    if (( mem >= 8000000000 )); then ok "docker memory $((mem / 1024 / 1024 / 1024)) GiB"
    else warn "docker memory $((mem / 1024 / 1024 / 1024)) GiB (< 8 GiB; ClickHouse may wedge)"; bad=1; fi
    check "python3 >= 3.11" "python3 -c 'import sys; assert sys.version_info >= (3, 11)'" "install Python 3.11+"
    check "openssl" "command -v openssl" "install openssl"
    check "curl" "command -v curl" "install curl"
    if command -v uv >/dev/null 2>&1; then ok "uv (optional) found"; else ok "uv not found (falls back to python -m venv)"; fi
    if [[ "$APP_MODE" == native ]]; then
        local cargo; cargo="$(cargo_bin 2>/dev/null || true)"
        check "cargo (rustup proxy)" "[[ -x '$cargo' ]]" "install rustup"
        check "toolchain from rust-toolchain.toml" "(cd '$ROOT' && PATH='$(dirname "$cargo")':\$PATH '$cargo' --version)" "rustup toolchain install"
    fi
    if command -v shellcheck >/dev/null 2>&1; then ok "shellcheck (optional) found"; else ok "shellcheck not found (optional)"; fi
    check "node + npm (ui suite builds nanosiem-web, runs its puppeteer driver)" "command -v node && command -v npm" "install Node.js 20+"
    check "Chrome/Chromium for the ui suite" "[[ -x \"\${CHROME_PATH:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}\" ]] || command -v google-chrome || command -v chromium" "install Chrome or set CHROME_PATH"
    if [[ "$APP_MODE" == native ]]; then ok "mock-vendor profile available (native app mode)"
    else ok "mock-vendor profile: native app mode only (connector feed scenarios will SKIP)"; fi
    local free_gb; free_gb="$(df -Pk "$ROOT" | awk 'NR==2 {print int($4/1024/1024)}')"
    if (( free_gb >= 20 )); then ok "disk free ${free_gb} GiB"; else warn "disk free ${free_gb} GiB (< 20)"; bad=1; fi
    # Isolation: list (never touch) other stacks so collisions are obvious.
    local others; others="$(docker ps --format '{{.Names}}' 2>/dev/null | grep -c '^nanoch-' || true)"
    ok "nanoch-* containers running: ${others:-0} (never touched by e2e)"
    # Credentials: presence only, never values.
    local src; src="$(creds_source)"
    ok "cloud credential source: $src"
    if [[ "$src" != none ]]; then
        with_creds python3 -I - <<'PY'
import os
groups = {
    "aws (S3+SQS)": ["NANO_E2E_AWS_ACCESS_KEY_ID", "NANO_E2E_AWS_SECRET_ACCESS_KEY", "NANO_E2E_AWS_REGION"],
    "gcp (Pub/Sub, SA key)": ["NANO_E2E_GCP_PROJECT", "NANO_E2E_GCP_SA_JSON"],
    "gcp (Pub/Sub, ADC)": ["NANO_E2E_GCP_PROJECT", "NANO_E2E_GCP_ADC"],
    "azure (Event Hubs, SP)": ["NANO_E2E_AZURE_TENANT_ID", "NANO_E2E_AZURE_CLIENT_ID",
                               "NANO_E2E_AZURE_CLIENT_SECRET", "NANO_E2E_AZURE_EVENTHUBS_NAMESPACE"],
    "azure (Event Hubs, conn string)": ["NANO_E2E_AZURE_EVENTHUB_CONNECTION_STRING"],
    # NAN-4961 real-tenant connector feeds (suite `connectors`).
    "entra_directory (app registration)": ["NANO_E2E_ENTRA_TENANT_ID", "NANO_E2E_ENTRA_CLIENT_ID",
                                           "NANO_E2E_ENTRA_CLIENT_SECRET"],
    "okta (system log + users)": ["OKTA_ORG_URL", "OKTA_API_TOKEN"],
    "google_workspace (SA + delegation)": ["NANO_E2E_GWS_SA_JSON", "NANO_E2E_GWS_ADMIN_EMAIL"],
    "slack (access logs, admin user token)": ["NANO_E2E_SLACK_USER_TOKEN"],
}
for name, keys in groups.items():
    missing = [k for k in keys if not os.environ.get(k)]
    state = "present" if not missing else "missing " + ", ".join(missing)
    print(f"     {name}: {state}")
PY
    else
        warn "no cloud credentials: cloud pull scenarios will SKIP (see e2e/README.md)"
    fi
    # C05 license env (NAN-5331): presence + validity, never contents.
    if [[ -n "${NANO_E2E_INSTALLATION_ID:-}${NANO_E2E_INSTALLATION_ORG_ID:-}${NANO_E2E_C05_LICENSE_FILE:-}" ]]; then
        if license_py check-env --repo-root "$ROOT"; then
            ok "C05 license env: identity ${NANO_E2E_INSTALLATION_ID:-unpinned}, license file ${NANO_E2E_C05_LICENSE_FILE:+present}"
        else
            bad=1
        fi
    else
        ok "C05 license env: unset (enterprise stacks start license-locked)"
    fi
    if (( bad == 0 )); then ok "doctor: ready"; else warn "doctor: fix the items above"; fi
    return "$bad"
}

# ---------------------------------------------------------------- legacy
CMD_LEGACY_OWNS_STACK=0
CMD_LEGACY_FINISHED=0

legacy_exit_guard() {
    local rc=$? final
    trap - EXIT INT TERM
    (( CMD_LEGACY_FINISHED )) && exit "$rc"
    if (( CMD_LEGACY_OWNS_STACK && ! KEEP )); then
        collect_artifacts >/dev/null 2>&1 || true
        cmd_down >/dev/null 2>&1 || true
    fi
    leak_guard_stop_tracked_pids
    final="$rc"
    leak_guard_finish "$rc" || final=$?
    exit "$final"
}

cmd_legacy() {
    venv_ensure
    [[ ${#POSITIONAL[@]} -gt 0 ]] || POSITIONAL=(list)
    if [[ "${POSITIONAL[0]}" == list ]]; then
        "$VENV/bin/python" -I -m nano_e2e.legacy --manifest "$LANES_FILE" --list; return
    fi
    local own_stack=0 status=0 final
    leak_guard_begin "scripts/e2e.sh legacy"
    CMD_LEGACY_OWNS_STACK=0
    CMD_LEGACY_FINISHED=0
    trap 'legacy_exit_guard' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    # Lanes that need the e2e stack get its stack.env; self-contained lanes
    # (they start their own containers) run without one.
    if "$VENV/bin/python" -I -m nano_e2e.legacy --manifest "$LANES_FILE" --needs-stack "${POSITIONAL[@]}"; then
        # Never auto-reuse the live stack here: several lanes TRUNCATE shared
        # tables. Only an explicit --run points legacy at an existing stack.
        if [[ -z "$RUN_ID" ]]; then
            own_stack=1
            cmd_up >/dev/null
            CMD_LEGACY_OWNS_STACK=1
            trap 'legacy_exit_guard' EXIT
            trap 'exit 130' INT
            trap 'exit 143' TERM
        else
            resolve_run
        fi
    fi
    (
        [[ -n "${RUN_DIR:-}" && -f "$RUN_DIR/stack.env" ]] && load_env_file "$RUN_DIR/stack.env"
        export E2E_ROOT="$ROOT" E2E_CARGO; E2E_CARGO="$(cargo_bin)"
        PATH="$(dirname "$E2E_CARGO"):$PATH"; export PATH
        export E2E_LEGACY_ARTIFACTS="${RUN_DIR:-$E2E_HOME/legacy-$(date +%s)}/artifacts/legacy"
        local allow=(); (( ALLOW_SKIPS )) && allow=(--allow-skips)
        "$VENV/bin/python" -I -m nano_e2e.legacy --manifest "$LANES_FILE" --root "$ROOT" "${allow[@]}" "${POSITIONAL[@]}"
    ) || status=$?
    if (( own_stack )) && (( ! KEEP )); then cmd_down; fi
    CMD_LEGACY_OWNS_STACK=0
    final="$status"
    leak_guard_stop_tracked_pids
    leak_guard_finish "$status" || final=$?
    CMD_LEGACY_FINISHED=1
    trap - EXIT INT TERM
    return "$final"
}

# ---------------------------------------------------------------- gc
gc_local_targets() {
    # gc_local_targets <cutoff epoch>: reads "project started owner" lines
    # (docker labels) and prints the projects gc may remove: started before the
    # cutoff AND owned by this checkout (owner label == $ROOT; a stack from
    # before the owner label counts only if its run dir is in this checkout's
    # $E2E_HOME). Another worktree's live stack is never selected unless
    # --all-local (NAN-4937: gc destroyed another lane's stack).
    local cutoff="$1" project started owner
    while read -r project started owner; do
        [[ "$project" =~ ^nanoe2e-[a-z0-9-]+$ ]] || continue
        [[ "$started" =~ ^[0-9]+$ ]] || continue
        (( started < cutoff )) || continue
        if (( ! GC_ALL_LOCAL )); then
            if [[ -n "$owner" ]]; then
                [[ "$owner" == "$ROOT" ]] || continue
            else
                [[ -d "$E2E_HOME/${project#nanoe2e-}" ]] || continue
            fi
        fi
        printf '%s\n' "$project"
    done
}

cmd_gc() {
    local cutoff=$(( $(date +%s) - GC_HOURS * 3600 )) project
    if (( GC_CLOUD )); then
        # Cloud only: --cloud never touches a local stack.
        venv_ensure
        log "removing cloud resources prefixed nano-e2e- older than ${GC_HOURS}h"
        # Runs with a live local stack are excluded even past the cutoff.
        local active=() d
        for d in "$E2E_HOME"/*/; do
            d="$(basename "$d")"
            [[ -f "$E2E_HOME/$d/stack.env" ]] && active+=(--exclude-run "$d")
        done
        with_creds "$VENV/bin/python" -I -m nano_e2e.cloud.gc --older-than-hours "$GC_HOURS" "${active[@]}"
        ok "gc done (cloud only)"
        return 0
    fi
    if (( GC_ALL_LOCAL )); then
        log "removing EVERY nanoe2e-* stack started more than ${GC_HOURS}h ago (--all-local)"
    else
        log "removing nanoe2e-* stacks this checkout started more than ${GC_HOURS}h ago"
    fi
    while read -r project; do
        log "gc $project"
        leak_guard_capture_compose_project "$project"
        local cid label
        while IFS= read -r cid; do
            [[ -n "$cid" ]] || continue
            label="$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "$cid" 2>/dev/null || true)"
            [[ "$label" == "$project" ]] || continue
            docker rm -fv "$cid" >/dev/null 2>&1 || true
        done < <(docker ps -aq --filter "label=com.docker.compose.project=$project")
        leak_guard_cleanup_compose_project "$project"
        local id="${project#nanoe2e-}"
        local pidf
        for pidf in "$E2E_HOME/$id"/pids/*.pid; do
            [[ -f "$pidf" ]] && { signal_owned TERM "$pidf" || true; }
        done
        rm -rf "${E2E_HOME:?}/$id/vector-dynamic" "${E2E_HOME:?}/$id/vector-validation" "${E2E_HOME:?}/$id/data" 2>/dev/null || true
    done < <(docker ps -a --filter 'label=nano.e2e.project' \
                --format '{{.Label "nano.e2e.project"}} {{.Label "nano.e2e.started"}} {{.Label "nano.e2e.owner"}}' \
                | sort -u | gc_local_targets "$cutoff")
    ok "gc done"
}

# Sourcing (selftests) defines the functions without dispatching.
[[ "${BASH_SOURCE[0]}" == "$0" ]] || return 0
case "$CMD" in
    up) cmd_up ;;
    run) cmd_run ;;
    down) resolve_run; cmd_down ;;
    env) cmd_env ;;
    status) cmd_status ;;
    doctor) cmd_doctor ;;
    legacy) cmd_legacy ;;
    gc) cmd_gc ;;
    svc) cmd_svc ;;
    license-ids) cmd_license_ids ;;
    selftest)
        # Harness safety properties; no stack and no cloud credentials needed.
        venv_ensure
        (cd "$PY_DIR" && "$VENV/bin/python" -m pytest selftest -q "${PYTEST_EXTRA[@]}") ;;
    *) awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "${BASH_SOURCE[0]}"; exit 1 ;;
esac
