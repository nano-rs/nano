#!/usr/bin/env bash
#
# nano — one-line installer for the open-source edition.
#
# Designed to be piped from curl:
#
#   curl -fsSL https://get.nano.rs | bash
#
# What it does:
#   1. Validates prerequisites (bash 4.4+, docker, docker compose v2, openssl,
#      curl, python3; git only for a git checkout). On macOS, stock /bin/bash
#      is 3.2: brew install bash and run the installer with that bash.
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
# Interactive runs (NAN-5508) ask every question first, then show a numbered
# review screen: Enter installs, a number changes that answer, q quits with
# nothing written. `back` (or `<`) at any prompt re-asks the previous one.
# Nothing (no .env, secret, docker login or container) happens before Enter.
# (A prepared .env whose admin account is not created yet still asks for the
# admin after start, as before.)
# A re-run that moves to a newer release says so and asks first.
#
# Non-interactive use: set the prompt values as env vars before running.
#   --non-interactive (or --yes, or NANO_NONINTERACTIVE=1) never reads the
#   terminal even when one is attached; every question takes its variable or
#   default, a missing required value stops the run before any change (all
#   named at once), and a destructive confirmation needs its NANO_CONFIRM_*
#   variable. NANO_PROMPT_TIMEOUT=<seconds> bounds the time to answer each prompt. See
#   --help and docs/getting-started/non-interactive-install.md.
#   NANO_ADMIN_EMAIL, NANO_ADMIN_NAME, NANO_ADMIN_PASSWORD, NANO_BASE_URL
#   NANO_HTTPS_PROXY (http://host:port), NANO_PROXY_USERNAME / NANO_PROXY_PASSWORD
#   (raw; the installer percent-encodes them) and NANO_NO_PROXY — outbound proxy for
#   nano's own calls; asked once, kept in .env as HTTPS_PROXY/HTTP_PROXY/NO_PROXY.
#   Enterprise license (NAN-5172), asked once on a TTY and kept in .env:
#   LICENSE_URL, LICENSE_TOKEN (or the older DEPLOYMENT_TOKEN) and
#   NANO_DEPLOYMENT_ID from the deployment's page in app.nano.rs, or
#   NANO_LICENSE_MODE=offline with an optional NANO_LICENSE_FILE (imported
#   after install), or AIRGAP_MODE=true. An unattended first install without
#   any of these fails closed. A new LICENSE_TOKEN given to a re-run replaces
#   the recorded one. NANO_ADMIN_EMAIL / NANO_ADMIN_NAME are kept in .env (the
#   password never is), so a prepare-then-install second run needs neither.
#   Single-node in one command:
#     LICENSE_URL=… LICENSE_TOKEN=… NANO_DEPLOYMENT_ID=… ./install.sh
#   Enterprise images (NAN-5505): the bundle's images.enterprise.customer.lock
#   is the default lock (NANO_IMAGES_LOCK overrides it). With an online
#   license, right before the pull the installer logs docker in to the private
#   registry with a one-hour credential from the license API, unless the
#   images are already local or this host's own docker login works. Offline
#   and air-gapped installs never call the API: load the image bundle
#   (scripts/nano bundle load) or docker login yourself first.
#   NANO_ALLOW_PRIVATE_AI_ENDPOINTS (true | false, default false) — allow AI
#   providers on private addresses (a local LLM); asked once, kept in .env.
#   NANO_EGRESS_PROXY_REQUIRED (true | false) — refuse every direct public
#   connection (NAN-5441); NANO_DESTINATION_PROXY_URL (http://host:port) and
#   NANO_DESTINATION_PROXY_MODE (pinned_ip | hostname) — proxy for user-set
#   destinations (webhooks, AI provider URLs, lookup url=, scheduled fetches,
#   synthetic checks). Recorded in .env when given; never asked.
#   NANO_SCHEMA_PROFILE (ocsf | udm | ocsf+tenzir, default ocsf) — chosen at
#   first install and immutable afterward; see the prompt below. New installs
#   are OCSF-first (NAN-4903); an existing install keeps the profile recorded in
#   its .env (a .env without one predates the choice and is pinned to udm).
#   NANO_INGEST_ACK_DURABILITY (fsync | page_cache, default fsync) — when HEC,
#   HTTP and OTLP acknowledge: after the disk buffer fsyncs, or once the record
#   is in the page cache (faster; a host failure loses acknowledged events).
#   Recorded in .env; one value for every ingest host.
#   NANO_PLANNED_GB_PER_DAY (whole GB/day, 0 = not declared) and NANO_INGEST_PATH
#   (raw | preshaped) — NAN-5345 planned-volume sizing. Unset keeps host-only
#   sizing; ~300 GB/day and up select the large-deployment ClickHouse and
#   Vector settings. Asked once on a fresh interactive install, kept in .env.
#   NANO_AVG_EVENT_BYTES (default 1000; ~300 firewall/flow, ~2000 EDR) turns
#   the planned volume into events/s for the Vector CPU estimate (NAN-5372).
#   NANO_RETENTION_DAYS (1-3650; unset keeps 365) — event retention, the
#   ClickHouse TTL (NAN-5449). Asked once on a fresh interactive install, kept
#   in .env, applied by the migrator. With a planned volume the installer
#   checks the disk against it (plan.py's model, scripts/lib/retention-sizing.sh):
#   it warns when the disk holds fewer days, and a fresh install refuses a
#   disk that holds under 7 days unless NANO_ALLOW_UNDERSIZED_DISK=true.
#   DETECTION_MAX_MATCHES_PER_RUN (1-999999; unset keeps the binary default of
#   2000) - maximum events a raw-event detection rule fetches in one run before
#   switching to per-entity representatives (NAN-5736 / NAN-5746). Recorded in
#   .env when given; never asked.
#   Host size (NAN-5506, scripts/lib/host-minimums.sh): before any prompt the
#   installer refuses a host under 2 vCPU, 8 GB RAM (16 GB with the enrichment
#   feeds on; PLATFORM_FEEDS_AUTO_UPDATE=false for a lab install) or 40 GB free
#   on Docker's data filesystem; role-split hosts without ClickHouse have lower
#   floors. A host that already runs nano only gets a warning, and so does a
#   planned volume above the recommended size. NANO_SKIP_HOST_MINIMUMS=1
#   installs anyway with a loud warning (unsupported).
#   Before any prompt (NAN-5509), the TLS overlay (docker-compose.tls.yml in
#   NANO_COMPOSE_OVERLAYS) needs config/nginx/ssl/fullchain.pem and privkey.pem:
#   present, matching and unexpired. Before the pull, every port the graph
#   publishes must be free (NANO_SKIP_PORT_CHECK=1 skips that check).
#   NAN-5521: on an existing install a certificate problem is a loud warning,
#   not a refusal; NANO_SKIP_TLS_PREFLIGHT=1 skips the certificate check. A
#   re-run without NANO_COMPOSE_OVERLAYS in the environment records in .env any
#   overlay the running stack uses that .env lacks (so HTTPS stays on).
#   NAN-5566: when the running single-node Vector predates the ingest gate
#   (nano 2.0.31 or older), senders that post to its ports directly (:8080,
#   :8088, OTLP, :6000) cannot be closed before it stops: pause them first. The
#   installer warns and, before it fetches, pulls or writes anything, asks on a
#   terminal (type y). Unattended it refuses (exit 1, nothing changed) unless
#   NANO_CONFIRM_SENDERS_PAUSED=1, NANO_CONFIRM_UPGRADE=1 or
#   NANO_CONFIRM_LEGACY_UPGRADE=1 is set.
#   NANO_CONFIRM_UPGRADE=1 answers the "Upgrade to X now? [Y/n]" question
#   (asked on a terminal when a re-run moves to another release) with yes.
#   Enter upgrades (NAN-5529). Declining exits 3 (answered n) or 4 (no answer:
#   end of input); nothing is changed.
#   NAN-5559: a 0.1.x install (.env NANO_VERSION=latest or 0.x, or no
#   NANO_EDITION/NANO_IMAGE_PREFIX; a 0.x images.lock; a nano-api image tagged
#   latest or 0.x) is upgraded to 2.x only on purpose, and the installer says
#   so before it fetches or writes anything. On a terminal it asks (type y)
#   and offers a backup (pg_dump + a copy of .env, in a new 0700 directory
#   outside the install). Unattended it refuses unless
#   NANO_CONFIRM_LEGACY_UPGRADE=1, and then takes that backup itself unless
#   NANO_LEGACY_UPGRADE_SKIP_BACKUP=1. NANO_LEGACY_BACKUP_DIR picks the backup
#   directory (default ~/nano-legacy-backup-<UTC time>).
#   Vector-to-Vector senders (:6000 was plaintext on 0.1.x, mutual TLS on 2.x):
#   the guard reads the running Vector's counters and peers (read only). When
#   :6000 is in use, or NANO_VECTOR_NATIVE_SENDERS=edge-1,edge-2 names the
#   senders (a terminal asks when it is unset), one client certificate bundle
#   per sender is issued into <install>/vector-client-bundles/<name>/ before
#   the stack starts, with a ready sink config (vector-sink.toml). Unattended
#   without names it warns and says what to run; it never fails for it.
#   Enterprise: NANO_TIERING (on | off, default off; or --tiering) and NANO_TIERING_PROVIDER (s3 |
#   s3-compatible | gcs | azure), NANO_TIERING_BUCKET, NANO_TIERING_REGION,
#   NANO_TIERING_ENDPOINT, NANO_TIERING_PREFIX (default nano),
#   NANO_TIERING_MOVE_FACTOR (default 0.3; 0 pauses), NANO_TIERING_CACHE_SIZE
#   (default 10Gi), NANO_TIERING_USE_ENVIRONMENT_CREDENTIALS, and the secrets
#   NANO_TIERING_ACCESS_KEY_ID / NANO_TIERING_SECRET_ACCESS_KEY (or
#   NANO_TIERING_AZURE_ACCOUNT_URL / _CONTAINER / _ACCOUNT_NAME /
#   _ACCOUNT_KEY): NAN-5445 ClickHouse hot/cold storage tiering on a single
#   host. Asked once on a TTY, kept in .env; a later run that passes any of
#   them updates .env. Role-split clusters use the inventory `tiering:` block.
#   Once on, a changed provider, bucket, prefix, region, endpoint, Azure
#   account or container (or a role-split host rename) is refused unless
#   NANO_TIERING_ALLOW_RELOCATE=1: cold parts point at the old location.
#   See docs/administration/storage-tiering.md and `scripts/nano tiering`.
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
# fails closed; an install never changes edition on a re-run, except the
# deliberate open -> enterprise conversion (`scripts/nano convert --to
# enterprise`, NANO_CONVERT_EDITION=enterprise, NAN-5558). Enterprise uses
# images.enterprise.lock (enterprise bundle only; needs a registry login),
# open core uses images.lock (ghcr.io).
# NANO_INSTALL_DIR may also be an extracted release bundle (a directory with a
# .nano-bundle marker) instead of a git checkout.
# NANO_CHECK_ONLY=1 validates the inputs, prints the resolved edition, release
# and image source, and exits before writing .env, pulling or starting anything.
# Set NANO_SKIP_IMAGE_VERIFY=1 to skip the image digest supply-chain check.
# Unauthenticated ingest ports (raw OTLP :4317/:4318, Fluent :24224, bundled
# Tenzir :9095) bind 127.0.0.1. Opt in to exposing them with
# NANO_OTLP_BIND_ADDRESS / NANO_FLUENT_BIND_ADDRESS / NANO_TENZIR_BIND_ADDRESS
# (persisted to .env).
# Vector native :6000 (NAN-5515) is published on the host's ingest interface
# like HEC and HTTP ingest, and ALWAYS requires mutual TLS: the installer
# creates this install's Vector-native listener CA and anchor store
# (.nano-pki/vector-native, mode 0700) and the listener files
# (config/vector-native), and senders need a client certificate from
# `scripts/nano vector-client-cert <name>`.
# NANO_VECTOR_NATIVE_BIND_ADDRESS narrows the bind to one address;
# NANO_VECTOR_NATIVE_SANS (comma separated) adds names/addresses senders use
# that the host cannot see (a NAT or cloud public address, a load balancer);
# NANO_VECTOR_NATIVE_PUBLIC_HOST is the address printed in sender configs.

main() {
# NAN-5750: bash 4.4 or newer, checked before anything is read, written or
# pulled. Older bash (stock macOS /bin/bash is 3.2) treats an empty array
# expanded under `set -u` as unbound, and scripts/nano, which this install runs
# for automatic backups and which every later upgrade, backup and restore uses,
# needs bash 4 (mapfile, coproc, named file descriptors).
# NANO_INSTALLER_TEST_BASH_VERSION (installer tests only) stands in for it.
local bash_major="${BASH_VERSINFO[0]:-0}" bash_minor="${BASH_VERSINFO[1]:-0}" bash_shown="${BASH_VERSION:-unknown}"
if [[ "${NANO_INSTALLER_TEST_MODE:-0}" == 1 && "${NANO_INSTALLER_TEST_BASH_VERSION:-}" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]]; then
    bash_shown=$NANO_INSTALLER_TEST_BASH_VERSION
    bash_major=${bash_shown%%.*} bash_minor=${bash_shown#*.}
    bash_minor=${bash_minor%%.*}
fi
if (( bash_major < 4 || (bash_major == 4 && bash_minor < 4) )); then
    # shellcheck disable=SC2016 # the $(brew --prefix) is for the user to run
    printf 'nano install needs bash 4.4+ (this is bash %s); on macOS: brew install bash, then run the installer with it: curl -fsSL https://get.nano.rs | "$(brew --prefix)/bin/bash" (or "$(brew --prefix)/bin/bash" ./install.sh). Nothing was changed.\n' "$bash_shown" >&2
    exit 1
fi
unset bash_major bash_minor bash_shown
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
RECORD_PG_HA_IDENTITY_ONLY=0
ENV_TEMP_FILE=""
# NAN-5237: 0600 files holding the setup-token header / initialize response.
SETUP_HEADER_FILE=""
SETUP_RESPONSE_FILE=""
cleanup_env_temp() {
    # NAN-5251: on every exit (success, prepare-only, or a failure after .env
    # was written) say so when this run changed the shared .env.
    if declare -F report_shared_env_change >/dev/null 2>&1; then
        report_shared_env_change || true
    fi
    # NAN-5749: a secret prompt interrupted by Ctrl-C leaves echo off.
    if declare -F tty_restore_state >/dev/null 2>&1; then
        tty_restore_state
    fi
    [[ -z "$ENV_TEMP_FILE" ]] || rm -f -- "$ENV_TEMP_FILE"
    [[ -z "$SETUP_HEADER_FILE" ]] || rm -f -- "$SETUP_HEADER_FILE"
    [[ -z "$SETUP_RESPONSE_FILE" ]] || rm -f -- "$SETUP_RESPONSE_FILE"
    # NAN-5524: the private docker config holding a license-API pull
    # credential (scripts/lib/image-pull.sh), on success, failure and
    # interrupt alike. bash runs this trap on SIGINT/SIGTERM too.
    if declare -F nano_registry_cleanup >/dev/null 2>&1; then
        nano_registry_cleanup || true
    fi
    # NAN-5566: never leave ingest closed (nginx marker, Vector's gate) on any
    # exit after the Vector stop below; defined only once that code ran.
    if declare -F nano_vq_reopen >/dev/null 2>&1 && [[ "${NANO_VQ_ENGAGED:-0}" == 1 ]]; then
        nano_vq_reopen 30 || true
    fi
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
        --record-pg-ha-identity)
            RECORD_PG_HA_IDENTITY_ONLY=1; shift ;;
        # Never read the terminal: env vars and defaults answer every
        # question, and a missing required value fails before any change.
        --non-interactive|--yes)
            NANO_NONINTERACTIVE=1; shift ;;
        # NAN-5445 (enterprise): storage tiering, single host. Each flag sets
        # the matching NANO_TIERING* key (kept in .env). Secrets are never
        # flags: pass NANO_TIERING_ACCESS_KEY_ID / _SECRET_ACCESS_KEY (or
        # _AZURE_ACCOUNT_KEY) in the environment, or answer the hidden prompt.
        --tiering)
            [[ $# -ge 2 ]] || { printf '%s
' "--tiering requires off, s3, s3-compatible, gcs or azure" >&2; exit 2; }
            case "$2" in
                off) export NANO_TIERING=off ;;
                s3|s3-compatible|gcs|azure) export NANO_TIERING=on NANO_TIERING_PROVIDER="$2" ;;
                *) printf '%s
' "--tiering requires off, s3, s3-compatible, gcs or azure (got $2)" >&2; exit 2 ;;
            esac
            shift 2 ;;
        --tiering-bucket|--tiering-region|--tiering-endpoint|--tiering-prefix|--tiering-move-factor|--tiering-cache-size|--tiering-azure-account-url|--tiering-azure-container|--tiering-azure-account-name)
            [[ $# -ge 2 ]] || { printf '%s
' "$1 requires a value" >&2; exit 2; }
            tiering_key="NANO_TIERING_$(printf '%s' "${1#--tiering-}" | tr 'a-z-' 'A-Z_')"
            export "$tiering_key=$2"
            shift 2 ;;
        --tiering-use-environment-credentials)
            export NANO_TIERING_USE_ENVIRONMENT_CREDENTIALS=true; shift ;;
        -h|--help)
            cat <<'EOF'
Usage: install.sh [--non-interactive | --yes]
                  [--role app,ingest,clickhouse,keeper,postgres,monitoring --inventory inventory.yaml]
                  [--accept-topology-migration CURRENT_IDENTITY_SHA256]
                  [--tiering off|s3|s3-compatible|gcs|azure [--tiering-bucket B] [--tiering-region R]
                   [--tiering-endpoint URL] [--tiering-prefix P] [--tiering-move-factor F]
                   [--tiering-cache-size 10Gi] [--tiering-use-environment-credentials]
                   [--tiering-azure-account-url URL --tiering-azure-container C
                    --tiering-azure-account-name A]]
       install.sh --record-pg-ha-identity

Without role/inventory arguments, installs the unchanged single-node stack.
Enterprise bundles may select one or more roles from a shared host inventory.
The migration acknowledgement is valid only for a role-split install after its
data-movement runbook has completed; the exact recorded identity is required.

--tiering (enterprise, single host) turns on ClickHouse cold storage tiering to
object storage; without it an interactive install asks once ("Enable cold
storage tiering? [y/N]", default no). Secrets come from the environment
(NANO_TIERING_ACCESS_KEY_ID, NANO_TIERING_SECRET_ACCESS_KEY, or
NANO_TIERING_AZURE_ACCOUNT_KEY) or a hidden prompt, never from flags.
Role-split clusters use the inventory `tiering:` block. See
docs/administration/storage-tiering.md.

--record-pg-ha-identity (first postgres host of a PostgreSQL HA cluster, after
the other postgres hosts are installed) only records the cluster's identity
(NANO_PG_HA_SYSTEM_ID) in .env. It renders, pulls and restarts nothing.

Non-interactive installs
------------------------
--non-interactive (alias --yes), or NANO_NONINTERACTIVE=1: never read the
terminal, even when one is attached (ssh -t, expect, a CI pty). Every question
takes its environment variable, or its default below. Values with no safe
default are required: a run without them stops before it changes anything and
names every missing one at once. A run with no terminal at all behaves the
same way, except that it still takes a release-to-release upgrade by default.

Every prompt first logs "waiting for input: <question> (set VAR to skip)" on
stderr. NANO_PROMPT_TIMEOUT=<seconds> stops a prompt that is not answered
(Enter pressed) within that long (exit 4). It is off by default.

  Question                          Variable                          Default
  Admin email                       NANO_ADMIN_EMAIL                  REQUIRED (first install)
  Admin display name                NANO_ADMIN_NAME                   Admin
  Admin password                    NANO_ADMIN_PASSWORD               REQUIRED (first install; not with
                                                                      NANO_PREPARE_ONLY=1)
  Public base URL                   NANO_BASE_URL                     REQUIRED (first install)
  Schema profile                    NANO_SCHEMA_PROFILE               ocsf
  License (enterprise)              LICENSE_TOKEN + NANO_DEPLOYMENT_ID REQUIRED (first install), or
                                    (LICENSE_URL optional)            NANO_LICENSE_MODE=offline
                                                                      [NANO_LICENSE_FILE] or AIRGAP_MODE=true
  Outbound proxy                    NANO_HTTPS_PROXY, NANO_NO_PROXY,  no proxy
                                    NANO_PROXY_USERNAME/_PASSWORD
  AI on your own network            NANO_ALLOW_PRIVATE_AI_ENDPOINTS   false
  Automatic backups                 NANO_BACKUP_ENABLED (+ NANO_BACKUP_*) off
  Planned log volume (GB/day)       NANO_PLANNED_GB_PER_DAY           not declared (host-sized)
  Raw or pre-shaped events          NANO_INGEST_PATH                  raw
  Event retention (days)            NANO_RETENTION_DAYS               365
  Cold storage tiering (enterprise) NANO_TIERING / --tiering          off
  Vector senders on :6000 (0.1.x)   NANO_VECTOR_NATIVE_SENDERS        none (warns with the commands)

  Confirmation                      Variable                          Without it (non-interactive)
  Upgrade to another release        NANO_CONFIRM_UPGRADE=1            DESTRUCTIVE: refuses
  Upgrade a 0.1.x install to 2.x    NANO_CONFIRM_LEGACY_UPGRADE=1     DESTRUCTIVE: refuses
  Senders to Vector paused (<=2.0.31) NANO_CONFIRM_SENDERS_PAUSED=1   DESTRUCTIVE: refuses
  Back up before the 0.1.x upgrade  NANO_LEGACY_UPGRADE_SKIP_BACKUP=1 backs up (the safe default)

The full table, with every NANO_BACKUP_* and NANO_TIERING_* setting:
docs/getting-started/non-interactive-install.md
EOF
            exit 0 ;;
        *) printf 'Unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done
if [[ -n "$ROLE_ARG" && -z "$INVENTORY_ARG" ]] || [[ -z "$ROLE_ARG" && -n "$INVENTORY_ARG" ]]; then
    printf '%s\n' "--role and --inventory must be provided together" >&2
    exit 2
fi
if [[ "$RECORD_PG_HA_IDENTITY_ONLY" == "1" && ( -n "$ROLE_ARG" || -n "$TOPOLOGY_MIGRATION_SHA" ) ]]; then
    printf '%s\n' "--record-pg-ha-identity takes no other argument: it reads this host's recorded roles" >&2
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
# Non-interactive mode (--non-interactive / --yes / NANO_NONINTERACTIVE=1):
# install.sh never reads /dev/tty, even with a terminal attached (ssh -t,
# expect, a CI pty). Exported so the helpers it runs (nano-tiering.py,
# nano-backup-scheduler.py, vector-quiesce.sh) never prompt either.
case "$(printf '%s' "${NANO_NONINTERACTIVE:-}" | tr '[:upper:]' '[:lower:]')" in
    "" | 0 | false | no | off) NANO_NONINTERACTIVE=0 ;;
    1 | true | yes | on) NANO_NONINTERACTIVE=1 ;;
    *) printf 'NANO_NONINTERACTIVE must be 1 or 0 (got %s)\n' "$NANO_NONINTERACTIVE" >&2; exit 2 ;;
esac
export NANO_NONINTERACTIVE
# git (a checkout update) must not ask for credentials on the terminal either.
[[ "$NANO_NONINTERACTIVE" != 1 ]] || export GIT_TERMINAL_PROMPT=0
# NANO_PROMPT_TIMEOUT (seconds, off by default): a prompt left unanswered
# that long stops the installer instead of waiting forever.
if [[ -n "${NANO_PROMPT_TIMEOUT:-}" && ! "$NANO_PROMPT_TIMEOUT" =~ ^[1-9][0-9]{0,5}$ ]]; then
    printf 'NANO_PROMPT_TIMEOUT must be a whole number of seconds from 1 to 999999 (got %s)\n' "$NANO_PROMPT_TIMEOUT" >&2
    exit 2
fi
# NAN-5172: license inputs from the invoking environment, captured before
# anything else can reuse these names. The role-split renderer later exports
# NANO_DEPLOYMENT_ID as cluster.deployment_id (volume/project identity); the
# app.nano.rs-issued id given here is the license id and never that.
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
# NAN-5558: set only by `scripts/nano convert --to enterprise` (see the
# edition checks below for the exact conditions it is honoured under).
CONVERT_EDITION_INPUT="${NANO_CONVERT_EDITION:-}"
case "$CONVERT_EDITION_INPUT" in
    "" | enterprise) ;;
    *) printf 'NANO_CONVERT_EDITION must be enterprise (got %s)\n' "$CONVERT_EDITION_INPUT" >&2; exit 1 ;;
esac
# All traffic goes through the nginx reverse proxy on port 80. The internal
# nano-api / nano-search ports are not exposed to the host by default.
HOST_PORT="${NANO_HOST_PORT:-80}"

# The host the installer's own health/readiness probes reach the published
# edges on. A role-split host publishes its edges on the inventory's
# `bind_address` (NANO_CLUSTER_BIND_ADDRESS). A wildcard (0.0.0.0 / ::) or no
# bind address listens on loopback too, so the probes keep using localhost; a
# specific private address does not, so the probes must use that address.
# Usage: edge_probe_host [bind-address]; prints a URL host (IPv6 bracketed).
edge_probe_host() {
    case "${1:-}" in
        "" | 0.0.0.0 | "::" | "[::]" | "*") printf 'localhost' ;;
        \[*\]) printf '%s' "$1" ;;
        *:*) printf '[%s]' "$1" ;;
        *) printf '%s' "$1" ;;
    esac
}
EDGE_PROBE_HOST=localhost
API_BASE="http://${EDGE_PROBE_HOST}:${HOST_PORT}"
# Extra curl flags for installer -> edge calls (see the TLS overlay below).
API_CURL_ARGS=()

# NAN-5124: an installer -> edge call succeeds only on a 2xx. `curl -f` fails
# only on 4xx/5xx, so a redirect (the TLS overlay's :80 -> https 301) used to
# read as success and the installer printed "Admin user created" with no admin.
# Usage: api_call <body-file|/dev/null> <curl args...>; prints the HTTP status.
api_call() {
    local out="$1" code
    shift
    # --noproxy: these calls go to this host's own edge (loopback or the
    # private bind_address), never through an operator HTTP(S)_PROXY.
    code=$(curl -sS --noproxy '*' --max-redirs 0 -o "$out" -w '%{http_code}' \
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
    # NAN-5509: usually left by an earlier `sudo ./install.sh`.
    if [[ "$owner" != "$(id -u)" ]]; then
        [[ "$(id -u)" != 0 ]] \
            || fail "$path belongs to uid $owner, not root. Run install.sh as the user that owns the install (without sudo). No secrets were read."
        fail "$path is owned by uid $owner, not by you ($(id -un), uid $(id -u)); an earlier run probably used sudo. Take the install back: sudo chown -R $(id -un): $(dirname "$target"), then re-run install.sh without sudo. No secrets were read."
    fi
    [[ "$mode" == "600" ]] \
        || fail "$path has mode $mode; run 'chmod 600 $path' before retrying. No secrets were read."
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "$1 is required but not installed. $2"
}

prompt_tty() {
    # $1 = prompt, $2 = default value (optional), $3 = "secret" to suppress
    # echo, $4 = the environment variable that answers it (for the messages)
    local prompt="$1" default="${2:-}" secret="${3:-}" skip="${4:-}" answer="" rc=0
    local display_prompt="$prompt"
    [[ -n "$default" ]] && display_prompt="$prompt [$default]"

    if ! have_controlling_tty; then
        # `/dev/tty` commonly exists in noninteractive services but open(2)
        # returns ENXIO because the process has no controlling terminal.
        # Unattended runs check every required value up front
        # (unattended_inputs_check); this is the backstop.
        fail "Cannot ask '$prompt' ($(noninteractive_reason)). Set ${skip:-the value via its environment variable} and re-run; see install.sh --help."
    fi

    prompt_wait_log "$prompt" "$skip"
    printf "%s: " "$display_prompt" > /dev/tty
    if [[ -n "$secret" ]]; then
        # read -s, not tty_read_line: this runs in $(...), where a Ctrl-C
        # would leave tty_read_line's stty -echo behind.
        IFS= read -rs ${NANO_PROMPT_TIMEOUT:+-t "$NANO_PROMPT_TIMEOUT"} answer < /dev/tty || rc=$?
        printf "\n" > /dev/tty
        (( rc <= 128 )) || prompt_timed_out
    else
        tty_read_line answer || rc=$?
    fi
    # End of input (a closed terminal, Ctrl-D) is no answer: never a blank
    # one (that would autogenerate a password) and never asked again forever.
    if (( rc != 0 )); then
        printf '\n' > /dev/tty 2>/dev/null || true
        printf 'install.sh: input ended at: %s. Stopped (exit 4).\n' "$prompt" >&2
        exit 4
    fi
    [[ -z "$answer" && -n "$default" ]] && answer="$default"
    printf "%s" "$answer"
}

# A terminal this run may read: never in non-interactive mode.
have_controlling_tty() {
    [[ "${NANO_NONINTERACTIVE:-0}" != 1 ]] || return 1
    (exec 9<>/dev/tty) 2>/dev/null
}

# Why nothing is asked, for the messages.
noninteractive_reason() {
    if [[ "${NANO_NONINTERACTIVE:-0}" == 1 ]]; then
        printf '%s' "non-interactive mode: --non-interactive or NANO_NONINTERACTIVE=1"
    else
        printf '%s' "no terminal to ask on"
    fi
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
# Called as $(ask_yes_no ...): the re-ask hint goes to stderr, or it would be
# captured into the answer (NAN-5495: "maybe" then "y" read as no).
ask_yes_no() {
    local answer hint="[y/N]"
    [[ "$2" == "Y" ]] && hint="[Y/n]"
    while :; do
        answer=$(prompt_tty "$1 $hint")
        [[ -z "$answer" ]] && answer="$2"
        answer=$(normalize_bool "$answer")
        [[ -n "$answer" ]] && { printf '%s' "$answer"; return 0; }
        warn "Answer y or n." >&2
    done
}

# Extra NO_PROXY entries: comma-separated host / domain / IP / CIDR tokens.
valid_no_proxy() {
    [[ "${1:-}" =~ ^[A-Za-z0-9.*:/_-]+(,[A-Za-z0-9.*:/_-]+)*$ ]]
}

# Corporate egress proxy for nano's own outbound calls (license check-in,
# feeds, content, OIDC/identity sync, S3 tiering). Asked once, only while
# .env has neither HTTPS_PROXY nor a recorded answer; a re-run or upgrade
# never asks again. Unattended installs pass NANO_HTTPS_PROXY (and
# NANO_NO_PROXY). No TTY and no input means no proxy. A proxy already
# exported in the installer's shell is offered as the default.
configure_outbound_proxy() {
    local url extra user="" pass=""
    if [[ -n "$(env_value HTTPS_PROXY)" || -n "$(env_value NANO_OUTBOUND_PROXY_ASKED)" ]]; then
        return 0
    fi
    url="" extra=""
    if [[ -n "${NANO_HTTPS_PROXY:-}" ]]; then
        url="$NANO_HTTPS_PROXY" extra="${NANO_NO_PROXY:-}"
        user="${NANO_PROXY_USERNAME:-}" pass="${NANO_PROXY_PASSWORD:-}"
    else
        # NAN-5508: asked by collect_answers before anything was written; a
        # direct call on a terminal asks just these questions.
        [[ "${WANT_proxy:-0}" == 1 ]] || ! have_controlling_tty || answer_ask_group proxy
        if [[ "${WANT_proxy:-0}" == 1 && "${ANS_PROXY:-false}" == true ]]; then
            url="$ANS_PROXY_URL" extra="${ANS_NO_PROXY:-}"
            if [[ "${ANS_PROXY_AUTH:-false}" == true ]]; then
                user="$ANS_PROXY_USER" pass="$ANS_PROXY_PASS"
            fi
        fi
    fi
    if [[ -n "$url" && -n "$user" ]]; then
        # RFC 3986 userinfo: everything outside the unreserved set is
        # percent-encoded (DOMAIN\user, p@ss:w/rd!# ...). reqwest decodes it.
        url="${url%%://*}://$(pct_encode "$user"):$(pct_encode "$pass")@${url#*://}"
    fi
    user="" pass="" ANS_PROXY_PASS=""
    # Set in place (NAN-5251): a symlinked .env stays a link and keeps its
    # 0600 mode, and no key is ever duplicated.
    if [[ -n "$url" ]]; then
        nano_env_set_keys .env "HTTPS_PROXY=$url" "HTTP_PROXY=$url" \
            || fail "Could not record the outbound proxy in .env."
        if [[ -n "$extra" ]]; then
            nano_env_set_keys .env "NO_PROXY=$extra" || fail "Could not record NO_PROXY in .env."
        fi
        log "nano's outbound calls use the proxy $(redact_proxy_url "$url") (HTTPS_PROXY in .env; internal services and private ranges bypass it)"
        log "Docker image pulls use the Docker daemon's own proxy settings (a systemd drop-in for docker.service), not nano's: https://nano.rs/docs/getting-started/self-run#corporate-proxy"
    fi
    nano_env_set_keys .env "NANO_OUTBOUND_PROXY_ASKED=true" \
        || fail "Could not record NANO_OUTBOUND_PROXY_ASKED in .env."
}

# Egress proxy policy (NAN-5441), unattended only: recorded in .env when the
# installer is given the values, and left alone otherwise (a re-run without
# them keeps what .env has). See docs/getting-started/docker-deployment.md.
# Refuse invalid unattended egress input before anything is written.
validate_egress_policy_input() {
    if [[ -n "${NANO_EGRESS_PROXY_REQUIRED:-}" ]]; then
        case "$NANO_EGRESS_PROXY_REQUIRED" in
            true|false) ;;
            *) fail "NANO_EGRESS_PROXY_REQUIRED must be true or false (got '$NANO_EGRESS_PROXY_REQUIRED')." ;;
        esac
    fi
    if [[ -n "${NANO_DESTINATION_PROXY_URL:-}" ]]; then
        [[ "$NANO_DESTINATION_PROXY_URL" =~ ^http://([^/@[:space:]]+@)?([A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\]):[0-9]{1,5}/?$ ]] \
            || fail "NANO_DESTINATION_PROXY_URL must look like http://[user:password@]host:port (got '$(redact_proxy_url "$NANO_DESTINATION_PROXY_URL")')."
    fi
    if [[ -n "${NANO_DESTINATION_PROXY_MODE:-}" ]]; then
        case "$NANO_DESTINATION_PROXY_MODE" in
            pinned_ip|hostname) ;;
            *) fail "NANO_DESTINATION_PROXY_MODE must be pinned_ip or hostname (got '$NANO_DESTINATION_PROXY_MODE')." ;;
        esac
    fi
}

configure_egress_policy() {
    validate_egress_policy_input
    if [[ -n "${NANO_EGRESS_PROXY_REQUIRED:-}" ]]; then
        nano_env_set_keys .env "NANO_EGRESS_PROXY_REQUIRED=$NANO_EGRESS_PROXY_REQUIRED" \
            || fail "Could not record NANO_EGRESS_PROXY_REQUIRED in .env."
    fi
    if [[ -n "${NANO_DESTINATION_PROXY_URL:-}" ]]; then
        nano_env_set_keys .env "DESTINATION_EGRESS_PROXY_URL=$NANO_DESTINATION_PROXY_URL" \
            || fail "Could not record DESTINATION_EGRESS_PROXY_URL in .env."
    fi
    if [[ -n "${NANO_DESTINATION_PROXY_MODE:-}" ]]; then
        nano_env_set_keys .env "DESTINATION_EGRESS_PROXY_MODE=$NANO_DESTINATION_PROXY_MODE" \
            || fail "Could not record DESTINATION_EGRESS_PROXY_MODE in .env."
    fi
    if [[ "$(env_value NANO_EGRESS_PROXY_REQUIRED)" == "true" ]]; then
        log "Egress proxy required: services refuse direct public connections; every path needs its proxy (HTTPS_PROXY, CONNECTOR_/SOAR_/ENRICHMENT_/DESTINATION_EGRESS_PROXY_URL)."
    fi
}

# Private-address AI providers (a BYO local LLM on 10.x / 192.168.x). The AI
# base-URL validator refuses private addresses unless
# NANOSIEM_ALLOW_PRIVATE_AI_ENDPOINTS is on (cloud-metadata stays blocked
# either way). Asked once, only while .env has no value; the answer is kept in
# .env so a re-run or upgrade never asks again. Unattended installs pass
# NANO_ALLOW_PRIVATE_AI_ENDPOINTS=true|false; with no TTY the default is false.
configure_private_ai_endpoints() {
    local recorded
    recorded=$(env_value NANOSIEM_ALLOW_PRIVATE_AI_ENDPOINTS)
    if [[ -n "$recorded" ]]; then
        PRIVATE_AI_ENDPOINTS="$recorded"
        return 0
    fi
    if [[ -n "${NANO_ALLOW_PRIVATE_AI_ENDPOINTS:-}" ]]; then
        PRIVATE_AI_ENDPOINTS=$(normalize_bool "$NANO_ALLOW_PRIVATE_AI_ENDPOINTS")
    elif [[ "${WANT_ai:-0}" == 1 ]] || have_controlling_tty; then
        # NAN-5508: asked by collect_answers before anything was written.
        [[ "${WANT_ai:-0}" == 1 ]] || answer_ask_group ai
        PRIVATE_AI_ENDPOINTS="${ANS_AI:-false}"
    else
        PRIVATE_AI_ENDPOINTS=false
    fi
    # Set in place (NAN-5251); a symlinked .env stays a link.
    nano_env_set_keys .env "NANOSIEM_ALLOW_PRIVATE_AI_ENDPOINTS=$PRIVATE_AI_ENDPOINTS" \
        || fail "Could not record NANOSIEM_ALLOW_PRIVATE_AI_ENDPOINTS in .env."
    if [[ "$PRIVATE_AI_ENDPOINTS" == "true" ]]; then
        log "AI providers on private addresses are allowed (NANOSIEM_ALLOW_PRIVATE_AI_ENDPOINTS=true in .env)"
    fi
}

# NAN-5287: disk-buffer acknowledgement durability for every ingest host.
# fsync (the default) syncs each buffered record to disk before HEC, HTTP or
# OTLP answers 2xx, so an acknowledged event survives a power or host failure.
# page_cache acknowledges once the record is in the page cache: about 1.7-2.2x
# the request rate per Vector, but a host failure can lose up to ~500 ms of
# acknowledged events. nano-api renders NANO_INGEST_ACK_DURABILITY from the
# shared .env into the generated Vector config every ingest host installs, so
# all of them run one mode; a role-split host other than the app host refuses
# a value that differs from its .env (change it in the app host's .env and copy
# that .env to every host).
valid_ingest_ack_durability() {
    [[ "$1" == "fsync" || "$1" == "page_cache" ]]
}

validate_ingest_ack_durability_input() {
    local input="${NANO_INGEST_ACK_DURABILITY:-}" recorded
    if [[ -n "$input" ]] && ! valid_ingest_ack_durability "$input"; then
        fail "NANO_INGEST_ACK_DURABILITY must be fsync or page_cache (got '$input')."
    fi
    recorded=$(env_value NANO_INGEST_ACK_DURABILITY)
    if [[ -n "$recorded" ]] && ! valid_ingest_ack_durability "$recorded"; then
        fail "NANO_INGEST_ACK_DURABILITY in .env must be fsync or page_cache (got '$recorded'). Fix .env; Vector refuses to start with any other value."
    fi
    return 0
}

configure_ingest_ack_durability() {
    local input="${NANO_INGEST_ACK_DURABILITY:-}" recorded effective
    validate_ingest_ack_durability_input
    recorded=$(env_value NANO_INGEST_ACK_DURABILITY)
    effective="${recorded:-fsync}"
    if [[ -n "$input" && "$input" != "$effective" ]]; then
        if [[ "${MULTI_NODE:-0}" == "1" && ",${ROLE_ARG:-}," != *,app,* ]]; then
            fail "NANO_INGEST_ACK_DURABILITY=$input differs from this host's .env ($effective). Every ingest host must run the same mode: set it in the app host's .env, copy that .env to every host, then re-run install.sh here."
        fi
        nano_env_set_keys .env "NANO_INGEST_ACK_DURABILITY=$input" \
            || fail "Could not record NANO_INGEST_ACK_DURABILITY in .env."
        effective="$input"
        log "Recorded NANO_INGEST_ACK_DURABILITY=$effective in .env"
    fi
    if [[ "$effective" == "page_cache" ]]; then
        warn "Ingest acknowledgement durability is page_cache: HEC, HTTP and OTLP answer 2xx before the record is fsynced, so a power or host failure can lose up to ~500 ms of acknowledged events. Set NANO_INGEST_ACK_DURABILITY=fsync to restore the default."
    fi
    # Compose gives the shell environment precedence over .env.
    export NANO_INGEST_ACK_DURABILITY="$effective"
}

# NAN-5345: planned daily volume and ingest path. Large-deployment ClickHouse
# and Vector settings apply only when the operator declares a planned volume
# that needs them; host size still caps every number. An existing install
# never gains a planned volume (or a prompt) on upgrade: it is asked only on
# a fresh interactive install, or set with NANO_PLANNED_GB_PER_DAY.
valid_planned_gb_per_day() {
    [[ "${1:-}" =~ ^[0-9]{1,7}$ ]]
}

valid_avg_event_bytes() {
    [[ "${1:-}" =~ ^[0-9]{2,6}$ ]] && (( 10#$1 >= 50 ))
}

validate_planned_volume_input() {
    local input="${NANO_PLANNED_GB_PER_DAY:-}" path="${NANO_INGEST_PATH:-}"
    if [[ -n "$input" ]] && ! valid_planned_gb_per_day "$input"; then
        fail "NANO_PLANNED_GB_PER_DAY must be a whole number of GB per day, 0 for none (got '$input')."
    fi
    if [[ -n "$path" && "$path" != raw && "$path" != preshaped ]]; then
        fail "NANO_INGEST_PATH must be raw or preshaped (got '$path')."
    fi
    if [[ -n "${NANO_AVG_EVENT_BYTES:-}" ]] && ! valid_avg_event_bytes "$NANO_AVG_EVENT_BYTES"; then
        fail "NANO_AVG_EVENT_BYTES must be a whole number of bytes, 50-999999 (got '$NANO_AVG_EVENT_BYTES')."
    fi
    return 0
}

configure_planned_volume() {
    local input="${NANO_PLANNED_GB_PER_DAY:-}" path_input="${NANO_INGEST_PATH:-}"
    local bytes_input="${NANO_AVG_EVENT_BYTES:-}"
    local recorded recorded_path recorded_bytes default_path=raw
    validate_planned_volume_input
    [[ "${BUNDLE_TENZIR:-0}" == "1" ]] && default_path=preshaped
    recorded=$(env_value NANO_PLANNED_GB_PER_DAY)
    recorded_path=$(env_value NANO_INGEST_PATH)
    recorded_bytes=$(env_value NANO_AVG_EVENT_BYTES)
    if [[ -n "$recorded" ]] && ! valid_planned_gb_per_day "$recorded"; then
        fail "NANO_PLANNED_GB_PER_DAY in .env must be a whole number of GB per day (got '$recorded'). Fix .env and re-run."
    fi
    if [[ -n "$recorded_path" && "$recorded_path" != raw && "$recorded_path" != preshaped ]]; then
        fail "NANO_INGEST_PATH in .env must be raw or preshaped (got '$recorded_path'). Fix .env and re-run."
    fi
    if [[ -n "$recorded_bytes" ]] && ! valid_avg_event_bytes "$recorded_bytes"; then
        fail "NANO_AVG_EVENT_BYTES in .env must be a whole number of bytes, 50-999999 (got '$recorded_bytes'). Fix .env and re-run."
    fi
    # NAN-5508: asked by collect_answers (whenever nothing is recorded and
    # this host has never started nano), before anything was written.
    if [[ -z "$input" && -z "$recorded" && "${WANT_volume:-0}" == 1 ]]; then
        input="${ANS_VOLUME:-}"
        if [[ -n "$input" && "$input" != 0 && -z "$path_input" && -z "$recorded_path" ]]; then
            path_input="${ANS_INGEST_PATH:-$default_path}"
        fi
    fi
    [[ -n "$input" ]] && input=$(( 10#$input ))
    [[ -n "$bytes_input" ]] && bytes_input=$(( 10#$bytes_input ))
    # Role-split: the shared .env is the one source, edited on the app host
    # and copied to every host (same rule as NANO_INGEST_ACK_DURABILITY).
    if [[ "${MULTI_NODE:-0}" == "1" && ",${ROLE_ARG:-}," != *,app,* ]] \
        && { [[ -n "$input" && "$input" != "$recorded" ]] \
            || [[ -n "$path_input" && "$path_input" != "$recorded_path" ]] \
            || [[ -n "$bytes_input" && "$bytes_input" != "$recorded_bytes" ]]; }; then
        fail "NANO_PLANNED_GB_PER_DAY / NANO_INGEST_PATH / NANO_AVG_EVENT_BYTES differ from this host's .env. Every host must size from the same planned volume: set them in the app host's .env, copy that .env to every host, then re-run install.sh here."
    fi
    if [[ -n "$input" && "$input" != "$recorded" ]]; then
        nano_env_set_keys .env "NANO_PLANNED_GB_PER_DAY=$input" \
            || fail "Could not record NANO_PLANNED_GB_PER_DAY in .env."
        recorded=$input
        log "Recorded NANO_PLANNED_GB_PER_DAY=$input in .env"
    fi
    if [[ -n "$path_input" && "$path_input" != "$recorded_path" ]]; then
        nano_env_set_keys .env "NANO_INGEST_PATH=$path_input" \
            || fail "Could not record NANO_INGEST_PATH in .env."
        recorded_path=$path_input
        log "Recorded NANO_INGEST_PATH=$path_input in .env"
    fi
    if [[ -n "$bytes_input" && "$bytes_input" != "$recorded_bytes" ]]; then
        nano_env_set_keys .env "NANO_AVG_EVENT_BYTES=$bytes_input" \
            || fail "Could not record NANO_AVG_EVENT_BYTES in .env."
        recorded_bytes=$bytes_input
        log "Recorded NANO_AVG_EVENT_BYTES=$bytes_input in .env"
    fi
    PLANNED_GB_PER_DAY="${recorded:-0}"
    PLANNED_INGEST_PATH="${recorded_path:-$default_path}"
    PLANNED_AVG_EVENT_BYTES="${recorded_bytes:-1000}"
}

# One KEY's value from a generated KEY=VALUE file; empty when absent.
sizing_file_value() {
    awk -F= -v k="$2" '$1 == k { v = substr($0, length(k) + 2) } END { print v }' "$1"
}

# Prints the warning when this host's Vector cannot carry the planned volume.
report_planned_ingest_capacity() {
    local env_file="$1" needed hosts per_host path planned tier bytes
    [[ -f "$env_file" ]] || return 0
    planned=$(sizing_file_value "$env_file" NANO_SIZING_PLANNED_GB_PER_DAY)
    [[ -n "$planned" ]] || return 0
    needed=$(sizing_file_value "$env_file" NANO_SIZING_VECTOR_VCPU_NEEDED)
    hosts=$(sizing_file_value "$env_file" NANO_SIZING_INGEST_HOSTS_NEEDED)
    per_host=$(sizing_file_value "$env_file" NANO_SIZING_VECTOR_VCPU_PER_HOST)
    path=$(sizing_file_value "$env_file" NANO_SIZING_INGEST_PATH)
    tier=$(sizing_file_value "$env_file" NANO_SIZING_TIER)
    bytes=$(sizing_file_value "$env_file" NANO_SIZING_AVG_EVENT_BYTES)
    log "Planned volume: ${planned} GB/day (${path} ingest, sizing tier ${tier})"
    if [[ "$hosts" =~ ^[0-9]+$ ]] && (( hosts > 1 )); then
        warn "One host cannot carry ${planned} GB/day of ${path} ingest: Vector needs about ${needed} vCPU (at ~${bytes:-1000} B/event) and this host gives it ${per_host}. Plan ${hosts} ingest hosts of this size (about ${needed} vCPU of Vector in total) with a role-split install; see docs/getting-started/self-hosting-multi-node.md. nano will still install and run here."
    fi
    return 0
}

# NAN-5449: event retention (the ClickHouse TTL), NANO_RETENTION_DAYS. Asked
# once on a fresh interactive single-host install; otherwise taken from the
# environment. Recorded in .env, where the migrator reads it. Unset keeps the
# shipped 365 days (or what Settings -> Storage set).
valid_retention_days() {
    [[ "${1:-}" =~ ^[0-9]{1,4}$ ]] && (( 10#$1 >= 1 && 10#$1 <= 3650 ))
}

validate_retention_input() {
    local input="${NANO_RETENTION_DAYS:-}"
    if [[ -n "$input" ]] && ! valid_retention_days "$input"; then
        fail "NANO_RETENTION_DAYS must be a whole number of days, 1-3650 (got '$input')."
    fi
    case "$(normalize_bool "${NANO_ALLOW_UNDERSIZED_DISK:-false}")" in
        true|false) ;;
        *) fail "NANO_ALLOW_UNDERSIZED_DISK must be true or false (got '${NANO_ALLOW_UNDERSIZED_DISK}')." ;;
    esac
    return 0
}

configure_retention_days() {
    local input="${NANO_RETENTION_DAYS:-}" recorded
    validate_retention_input
    recorded=$(env_value NANO_RETENTION_DAYS)
    if [[ -n "$recorded" ]] && ! valid_retention_days "$recorded"; then
        fail "NANO_RETENTION_DAYS in .env must be a whole number of days, 1-3650 (got '$recorded'). Fix .env and re-run."
    fi
    # NAN-5508: asked by collect_answers, like the planned volume.
    if [[ -z "$input" && -z "$recorded" && "${WANT_retention:-0}" == 1 ]]; then
        input="${ANS_RETENTION:-}"
    fi
    [[ -n "$input" ]] && input=$(( 10#$input ))
    # Role-split: one shared .env, edited on the app host (see above).
    if [[ "${MULTI_NODE:-0}" == "1" && ",${ROLE_ARG:-}," != *,app,* \
        && -n "$input" && "$input" != "$recorded" ]]; then
        fail "NANO_RETENTION_DAYS differs from this host's .env. Set it in the app host's .env, copy that .env to every host, then re-run install.sh here."
    fi
    if [[ -n "$input" && "$input" != "$recorded" ]]; then
        nano_env_set_keys .env "NANO_RETENTION_DAYS=$input" \
            || fail "Could not record NANO_RETENTION_DAYS in .env."
        recorded=$input
        log "Recorded NANO_RETENTION_DAYS=$input in .env"
    fi
    RETENTION_DAYS="${recorded:-365}"
}

# NAN-5736 / NAN-5746: per-run match cap for raw-event detection rules
# (DETECTION_MAX_MATCHES_PER_RUN, 1-999999; unset keeps the binary default of
# 2000). Never asked interactively; recorded in .env when supplied so it
# survives restarts and upgrades.
valid_detection_max_matches_per_run() {
    [[ "${1:-}" =~ ^[0-9]{1,6}$ ]] && (( 10#$1 >= 1 && 10#$1 <= 999999 ))
}

validate_detection_max_matches_input() {
    local input="${DETECTION_MAX_MATCHES_PER_RUN:-}" recorded
    if [[ -n "$input" ]] && ! valid_detection_max_matches_per_run "$input"; then
        fail "DETECTION_MAX_MATCHES_PER_RUN must be a whole number between 1 and 999999 (got '$input')."
    fi
    recorded=$(env_value DETECTION_MAX_MATCHES_PER_RUN)
    if [[ -n "$recorded" ]] && ! valid_detection_max_matches_per_run "$recorded"; then
        fail "DETECTION_MAX_MATCHES_PER_RUN in .env must be a whole number between 1 and 999999 (got '$recorded'). Fix .env and re-run."
    fi
    return 0
}

configure_detection_max_matches() {
    local input="${DETECTION_MAX_MATCHES_PER_RUN:-}" recorded
    validate_detection_max_matches_input
    recorded=$(env_value DETECTION_MAX_MATCHES_PER_RUN)
    [[ -n "$input" ]] && input=$(( 10#$input ))
    if [[ "${MULTI_NODE:-0}" == "1" && ",${ROLE_ARG:-}," != *,app,* \
        && -n "$input" && "$input" != "$recorded" ]]; then
        fail "DETECTION_MAX_MATCHES_PER_RUN differs from this host's .env. Set it in the app host's .env, copy that .env to every host, then re-run install.sh here."
    fi
    if [[ -n "$input" && "$input" != "$recorded" ]]; then
        nano_env_set_keys .env "DETECTION_MAX_MATCHES_PER_RUN=$input" \
            || fail "Could not record DETECTION_MAX_MATCHES_PER_RUN in .env."
        log "Recorded DETECTION_MAX_MATCHES_PER_RUN=$input in .env"
    fi
}

# NAN-5449: compare the planned volume x retention with this host's disk,
# using the capacity the resource sizer already probed (the Docker volume
# filesystem that holds ClickHouse, PostgreSQL and the Vector buffers).
# Overhead beside ClickHouse: the Vector buffer budget, the sizer's Docker
# reserve (10 %, at least 4 GiB) and 10 GiB for PostgreSQL and images.
# Warns when the disk holds fewer days than the retention; refuses a fresh
# install that holds under 7 days unless NANO_ALLOW_UNDERSIZED_DISK=true. An
# existing install (retention_existing_install) is only warned, never blocked
# on upgrade (a refused install started nothing, so a re-run is refused again).
# NAN-5449: whether this host already runs (or ran) nano, so the 7-day disk
# refusal must only warn: a ClickHouse container of this compose project, a
# re-run that reuses the recorded .env (REUSE_ENV=1), or a ClickHouse data
# volume left by an earlier install (`docker compose down` removes the
# containers but keeps the volume and its data).
retention_existing_install() {
    [[ "${REUSE_ENV:-0}" == "1" ]] && return 0
    [[ -n "$(docker compose "${sizing_compose_args[@]}" ps -a -q clickhouse </dev/null 2>/dev/null)" ]] && return 0
    [[ -n "$(docker volume ls -q --filter label=com.docker.compose.volume=nano-clickhouse-data </dev/null 2>/dev/null)" ]] && return 0
    return 1
}

report_retention_fit() {
    local env_file="$1" planned capacity buffers docker_reserve overhead sizing
    local supported needed verdict min_days need_gib cap_gib tiering=0 check_days
    [[ -f "$env_file" && -f scripts/lib/retention-sizing.sh ]] || return 0
    planned="${PLANNED_GB_PER_DAY:-0}"
    [[ "$planned" =~ ^[0-9]+$ ]] && (( planned > 0 )) || return 0
    # Cold tier on (NAN-5445): object storage holds the older days, so the
    # local disk does not cap retention (Helm skips the check the same way).
    # NAN-5509: but every event lands on the local disk first and moves only
    # once that disk passes the move threshold, so the local disk must still
    # hold the 7-day minimum; only the full-retention warning is dropped.
    case "$(printf '%s' "${NANO_TIERING:-$(env_value NANO_TIERING 2>/dev/null)}" | tr 'A-Z' 'a-z')" in
        on|true|yes|1) tiering=1 ;;
    esac
    check_days="${RETENTION_DAYS:-365}"
    if (( tiering )) && [[ "$check_days" =~ ^[0-9]+$ ]] && (( check_days > 7 )); then
        check_days=7
    fi
    # Bind/external Vector storage: the probed capacity is not ClickHouse's disk.
    [[ "${NANO_VECTOR_DATA_STORAGE_MODE:-named}" == named ]] || return 0
    capacity=$(sizing_file_value "$env_file" VECTOR_DATA_CAPACITY_BYTES)
    buffers=$(sizing_file_value "$env_file" VECTOR_DISK_BUFFER_TOTAL_BUDGET_BYTES)
    [[ "$capacity" =~ ^[1-9][0-9]*$ ]] || return 0
    [[ "$buffers" =~ ^[0-9]+$ ]] || buffers=0
    docker_reserve=$(( capacity / 10 ))
    (( docker_reserve >= 4294967296 )) || docker_reserve=4294967296
    overhead=$(( buffers + docker_reserve + 10737418240 ))
    sizing=$(bash scripts/lib/retention-sizing.sh \
        --gb-per-day "$planned" \
        --retention-days "$check_days" \
        --disk-bytes "$capacity" \
        --overhead-bytes "$overhead") || { warn "Could not check the disk against the planned volume and retention."; return 0; }
    supported=$(printf '%s\n' "$sizing" | awk -F= '$1 == "NANO_RETENTION_SUPPORTED_DAYS" { print $2 }')
    needed=$(printf '%s\n' "$sizing" | awk -F= '$1 == "NANO_RETENTION_NEEDED_BYTES" { print $2 }')
    verdict=$(printf '%s\n' "$sizing" | awk -F= '$1 == "NANO_RETENTION_VERDICT" { print $2 }')
    min_days=$(printf '%s\n' "$sizing" | awk -F= '$1 == "NANO_RETENTION_MIN_DAYS" { print $2 }')
    need_gib=$(( (needed + 1073741823) / 1073741824 ))
    cap_gib=$(( capacity / 1073741824 ))
    local retention_what=retention
    (( tiering )) && retention_what="local hot window (storage tiering moves older data to object storage)"
    if (( tiering )) && [[ "$verdict" != refuse ]]; then
        log "Disk: ${cap_gib} GiB holds about ${supported} days at ${planned} GB/day locally; storage tiering moves older data to object storage"
        return 0
    fi
    case "$verdict" in
        ok)
            log "Disk: ${cap_gib} GiB holds about ${supported} days at ${planned} GB/day (retention ${RETENTION_DAYS:-365} days)"
            ;;
        warn)
            warn "This host's disk (${cap_gib} GiB) holds about ${supported} days of events at ${planned} GB/day, less than the ${RETENTION_DAYS:-365}-day retention (that needs about ${need_gib} GiB at 5:1 compression). The estimate is conservative (measured compression is often 10x or more). When ClickHouse passes 80 % of the disk, nano drops the oldest days first. Grow the disk if it turns out short."
            ;;
        refuse)
            if [[ "$(normalize_bool "${NANO_ALLOW_UNDERSIZED_DISK:-false}")" == "true" ]] \
                || retention_existing_install; then
                warn "This host's disk (${cap_gib} GiB) holds only about ${supported} days of events at ${planned} GB/day (under the ${min_days}-day minimum; the ${check_days}-day ${retention_what} needs about ${need_gib} GiB). nano drops the oldest days whenever ClickHouse passes 80 % of the disk. Grow the disk."
            else
                fail "This host's disk (${cap_gib} GiB) holds only about ${supported} days of events at ${planned} GB/day, under the ${min_days}-day minimum (the ${check_days}-day ${retention_what} needs about ${need_gib} GiB at 5:1 compression). Nothing was started. Grow the disk, lower NANO_PLANNED_GB_PER_DAY if it overstates the volume, or set NANO_ALLOW_UNDERSIZED_DISK=true to install anyway."
            fi
            ;;
    esac
    return 0
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
    if [[ "${WANT_backup:-0}" != 1 && -z "${NANO_BACKUP_ENABLED+set}" ]] && have_controlling_tty; then
        answer_ask_group backup
    fi
    if [[ "${WANT_backup:-0}" != 1 ]]; then
        python3 -I scripts/nano-backup-scheduler.py --install-dir "$PWD" configure --from-installer \
            || fail "Automatic backup setup failed (see above). Fix the destination, or set NANO_BACKUP_ENABLED=false, and re-run."
        return 0
    fi
    # NAN-5508: answered before anything was written. The destination check
    # (a test write) runs now; a rejected destination asks the backup
    # questions again instead of ending the install.
    while ! backup_apply_answers; do
        [[ "${ANS_BACKUP:-false}" == true ]] \
            || fail "Automatic backup setup failed (see above). Run scripts/nano backup-schedule --configure after install."
        answer_yes_no "Change the backup answers? (n leaves automatic backups off for now)" true || ANSWER_REPLY=true
        if [[ "$ANSWER_REPLY" == true ]]; then
            answer_ask_group backup
        else
            ANS_BACKUP=false
        fi
    done
}

# The collected backup answers, handed to the scheduler through its
# NANO_BACKUP_* environment (never argv). Non-interactive there: it probes
# the destination, writes the keys and records .env, or fails with a reason.
backup_apply_answers() {
    (
        if [[ "${ANS_BACKUP:-false}" != true ]]; then
            export NANO_BACKUP_ENABLED=false
        else
            export NANO_BACKUP_ENABLED=true NANO_BACKUP_DESTINATION="$ANS_BACKUP_DEST" \
                NANO_BACKUP_SCHEDULE="$ANS_BACKUP_SCHEDULE" NANO_BACKUP_KEEP="$ANS_BACKUP_KEEP"
            if [[ "$ANS_BACKUP_DEST" == path ]]; then
                export NANO_BACKUP_PATH="$ANS_BACKUP_PATH"
            else
                export NANO_BACKUP_S3_ENDPOINT="$ANS_BACKUP_S3_ENDPOINT" NANO_BACKUP_S3_BUCKET="$ANS_BACKUP_S3_BUCKET" \
                    NANO_BACKUP_S3_REGION="$ANS_BACKUP_S3_REGION" NANO_BACKUP_S3_PREFIX="$ANS_BACKUP_S3_PREFIX" \
                    NANO_BACKUP_S3_ACCESS_KEY="$ANS_BACKUP_S3_ACCESS" NANO_BACKUP_S3_SECRET_KEY="$ANS_BACKUP_S3_SECRET"
            fi
        fi
        python3 -I scripts/nano-backup-scheduler.py --install-dir "$PWD" configure --from-installer </dev/null
    )
}

# NAN-5445: ClickHouse hot/cold storage tiering (single host). Asked once on
# a TTY while .env has no NANO_TIERING; unattended installs pass the
# NANO_TIERING* keys (a later run that passes any of them updates .env). The
# answers and the object-store secrets are kept in the 0600 .env; the rendered
# ClickHouse config holds only from_env references to them. Role-split
# clusters take the settings from the inventory `tiering:` block instead.
configure_storage_tiering() {
    [[ "$MULTI_NODE" == "1" ]] && return 0
    # Enterprise feature: the open bundle has no tiering tooling, and an open
    # install that asks for tiering fails loudly instead of ignoring it.
    if [[ "$NANO_EDITION" != enterprise || ! -f scripts/nano-tiering.py || ! -f scripts/lib/clickhouse_tiering.py ]]; then
        case "$(printf '%s' "${NANO_TIERING:-$(env_value NANO_TIERING)}" | tr 'A-Z' 'a-z')" in
            on|true|yes|1) fail "Storage tiering (NANO_TIERING / --tiering) is an enterprise feature and this install is the $NANO_EDITION edition. Remove it, or use the enterprise bundle." ;;
        esac
        return 0
    fi
    if ! command -v python3 >/dev/null 2>&1; then
        [[ -z "${NANO_TIERING:-}" ]] || fail "Storage tiering needs python3 on this host."
        return 0
    fi
    if [[ "${WANT_tiering:-0}" != 1 ]] && have_controlling_tty && tiering_question_applies; then
        answer_ask_group tiering
    fi
    if [[ "${WANT_tiering:-0}" != 1 ]]; then
        python3 -I scripts/nano-tiering.py --install-dir "$PWD" configure --from-installer \
            || fail "Storage tiering settings are invalid (see above). Fix the NANO_TIERING* values, or set NANO_TIERING=off, and re-run."
        return 0
    fi
    # NAN-5508: answered (and checked) before anything was written. Record
    # them, then check the object store from this host now: a store this
    # host cannot write to asks the tiering questions again.
    while :; do
        tiering_apply_answers \
            || fail "Storage tiering settings are invalid (see above). Fix them with scripts/nano tiering configure, or re-run with NANO_TIERING=off."
        [[ "${ANS_TIERING:-false}" == true && "${NANO_TIERING_SKIP_PROBE:-}" != "1" ]] || return 0
        TIERING_PROBED=1
        if tiering_probe=$(python3 -I scripts/lib/clickhouse_tiering.py probe --env-file .env </dev/null 2>&1); then
            ok "Object store check from this host: $tiering_probe"
            return 0
        fi
        tiering_probe="${tiering_probe#tiering: }"
        warn "Object store check from this host failed: ${tiering_probe}.$(tiering_probe_cause "$tiering_probe" "$ANS_TIER_PROVIDER")"
        # NAN-5509: new settings whose store refuses a test write are never
        # installed; here the answers can be fixed instead of re-running.
        answer_yes_no "Change the object store answers? (n stops here; nothing has started)" true \
            || ANSWER_REPLY=true
        if [[ "$ANSWER_REPLY" != true ]]; then
            fail "Storage tiering is on, but writing a test object to the bucket from this host failed. Without a working store the local disk fills up later instead of moving old data. Fix the credentials or bucket and re-run, set NANO_TIERING=off, or (for a store only the Compose network can reach) re-run with NANO_TIERING_SKIP_PROBE=1."
        fi
        # Nothing has started yet: forget the recorded store, so another
        # provider's answers are checked without the old one's keys.
        nano_env_set_keys .env NANO_TIERING= NANO_TIERING_PROVIDER= NANO_TIERING_BUCKET= NANO_TIERING_REGION= \
            NANO_TIERING_ENDPOINT= NANO_TIERING_PREFIX= NANO_TIERING_MOVE_FACTOR= NANO_TIERING_CACHE_SIZE= \
            NANO_TIERING_USE_ENVIRONMENT_CREDENTIALS= NANO_TIERING_AZURE_ACCOUNT_URL= NANO_TIERING_AZURE_CONTAINER= \
            NANO_TIERING_AZURE_ACCOUNT_NAME= NANO_TIERING_ACCESS_KEY_ID= NANO_TIERING_SECRET_ACCESS_KEY= \
            NANO_TIERING_AZURE_ACCOUNT_KEY= || fail "Could not reset the tiering settings in .env."
        answer_ask_group tiering
    done
}

# A likely cause for a failed object-store probe ($1 = probe output, $2 =
# provider), as a sentence with a leading space; empty when none is known.
tiering_probe_cause() {
    if [[ "${2:-}" == gcs ]]; then
        case "$1" in
            *403* | *AccessDenied* | *"Access denied"* | *insufficient* | *Forbidden*)
                printf '%s' " On Google Cloud this is usually a VM whose service account has the read-only storage scope (the default): use an HMAC key (NANO_TIERING_ACCESS_KEY_ID / NANO_TIERING_SECRET_ACCESS_KEY) with Storage Object Admin on the bucket, or stop the VM and give it the storage read-write scope." ;;
        esac
    fi
    return 0
}

# The collected tiering answers, handed to nano-tiering.py through its
# NANO_TIERING* environment (secrets never on argv).
tiering_apply_answers() {
    (
        local assignment
        while IFS= read -r assignment; do
            export "${assignment?}"
        done < <(answer_tiering_env)
        python3 -I scripts/nano-tiering.py --install-dir "$PWD" configure --from-installer </dev/null
    )
}

# ----------------------------------------------------------------------------
# License (NAN-5172): asked once on first install, recorded in .env.
# ----------------------------------------------------------------------------
# Enterprise api/jobs either check in online with the three values from the
# deployment's page in app.nano.rs (LICENSE_URL, LICENSE_TOKEN,
# NANO_DEPLOYMENT_ID) or are admitted by an offline C05 license file imported
# after install. NANO_LICENSE_MODE in .env records the choice
# (online | offline | airgap) so a re-run or upgrade never asks again;
# "pending" marks a prepared .env whose values are still to be added.
LICENSE_DEFAULT_URL="https://api.nano.rs/api/license/status"
LICENSE_PAGE_HINT="https://app.nano.rs → Deployments → your Self-run deployment → License"
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

# Offline license file to import after install: a readable regular file of
# 1..OFFLINE_LICENSE_MAX_BYTES bytes holding a JSON object. Prints the
# absolute path. The signature is verified by nano-api at import. Called as
# $(...), so its warnings go to stderr (on stdout they were swallowed).
resolve_offline_license_file() {
    local path="$1" size first
    [[ -f "$path" && -r "$path" ]] || { warn "Offline license file not found or not readable: $path" >&2; return 1; }
    size=$(wc -c < "$path" | tr -d '[:space:]')
    if (( size < 1 || size > OFFLINE_LICENSE_MAX_BYTES )); then
        warn "Offline license file must be 1 to $OFFLINE_LICENSE_MAX_BYTES bytes (got $size): $path" >&2
        return 1
    fi
    first=$(tr -d ' \t\r\n' < "$path")
    first=${first:0:1}
    [[ "$first" == "{" ]] || { warn "Offline license file is not a signed license JSON file: $path" >&2; return 1; }
    printf '%s/%s' "$(cd "$(dirname "$path")" && pwd -P)" "$(basename "$path")"
}

# Validate the license values given in the environment. Runs before anything
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
    # NAN-5509: a new token alone ("re-run with LICENSE_TOKEN=<new token>",
    # after Regenerate on app.nano.rs) belongs to the deployment this install
    # already checks in for: take its recorded LICENSE_URL and ID.
    if [[ -n "$LICENSE_TOKEN_INPUT" && -z "$LICENSE_DEPLOYMENT_ID_INPUT" ]] \
        && valid_deployment_id "$(env_value NANO_DEPLOYMENT_ID)" \
        && [[ -n "$(env_value LICENSE_URL)" ]]; then
        LICENSE_DEPLOYMENT_ID_INPUT=$(env_value NANO_DEPLOYMENT_ID)
        log "Using the deployment ID recorded in .env ($LICENSE_DEPLOYMENT_ID_INPUT) with the new LICENSE_TOKEN"
    fi
    # NANO_DEPLOYMENT_ID alone is not a license input: older role-split
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
            || fail "Choose one license: the online values (LICENSE_TOKEN, NANO_DEPLOYMENT_ID) or an offline license (NANO_LICENSE_MODE=offline / NANO_LICENSE_FILE), not both."
        is_truthy "${AIRGAP_MODE:-}" \
            && fail "AIRGAP_MODE=true never checks in online; leave out LICENSE_URL/LICENSE_TOKEN and import an offline license after install."
    fi
    if [[ -n "$LICENSE_FILE_INPUT" ]]; then
        resolve_offline_license_file "$LICENSE_FILE_INPUT" >/dev/null \
            || fail "NANO_LICENSE_FILE is not usable; nothing was written."
    fi
    return 0
}

# Decide the license for this install. Sets LICENSE_ENV_LINES (assignments to
# set in .env, possibly empty), LICENSE_MODE and LICENSE_IMPORT_FILE. $1 is
# 1 on first install (no .env yet), 0 when an .env is reused.
# Prompts at most once, only with a controlling TTY.
LICENSE_ENV_LINES="" LICENSE_MODE="" LICENSE_IMPORT_FILE="" LICENSE_DEPLOYMENT_ID=""
resolve_license() {
    local first_install="$1" recorded_mode recorded_url recorded_token recorded_id url
    LICENSE_ENV_LINES="" LICENSE_MODE="" LICENSE_IMPORT_FILE="" LICENSE_DEPLOYMENT_ID=""
    if [[ "$NANO_EDITION" != "enterprise" ]]; then
        if [[ -n "$LICENSE_TOKEN_INPUT$LICENSE_FILE_INPUT" ]]; then
            warn "Open edition has no license check; LICENSE_TOKEN / NANO_LICENSE_FILE are ignored."
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
    #    token after "Regenerate license token" on the deployment page).
    if [[ -n "$LICENSE_TOKEN_INPUT" ]]; then
        url="${LICENSE_URL_INPUT:-${recorded_url:-$LICENSE_DEFAULT_URL}}"
        LICENSE_MODE=online LICENSE_DEPLOYMENT_ID="$LICENSE_DEPLOYMENT_ID_INPUT"
        [[ "$url" == "$recorded_url" ]] || LICENSE_ENV_LINES+="LICENSE_URL=$url"$'\n'
        [[ "$LICENSE_TOKEN_INPUT" == "$recorded_token" ]] || LICENSE_ENV_LINES+="LICENSE_TOKEN=$LICENSE_TOKEN_INPUT"$'\n'
        [[ "$LICENSE_DEPLOYMENT_ID_INPUT" == "$recorded_id" ]] || LICENSE_ENV_LINES+="NANO_DEPLOYMENT_ID=$LICENSE_DEPLOYMENT_ID_INPUT"$'\n'
        if [[ "$first_install" == "0" && -n "$recorded_token" && "$LICENSE_TOKEN_INPUT" != "$recorded_token" ]]; then
            log "Replacing the license token recorded in .env with the one given to this run (value not shown)"
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
    elif [[ "${WANT_license:-0}" == 1 ]] || have_controlling_tty; then
        # NAN-5508: asked by collect_answers before anything was written (a
        # direct call on a terminal asks just these questions). A pre-2.0.5
        # install that reaches here was admitted by an offline license
        # imported in the UI (or not licensed yet): offline is its default.
        if [[ "${WANT_license:-0}" != 1 ]]; then
            ANSWER_LICENSE_DEFAULT=online
            [[ "$first_install" == "0" && -z "$recorded_mode" ]] && ANSWER_LICENSE_DEFAULT=offline
            answer_ask_group license
        fi
        if [[ "$ANS_LIC_MODE" == "online" ]]; then
            LICENSE_MODE=online LICENSE_DEPLOYMENT_ID="$ANS_LIC_ID"
            LICENSE_ENV_LINES="LICENSE_URL=$ANS_LIC_URL"$'\n'"LICENSE_TOKEN=$ANS_LIC_TOKEN"$'\n'"NANO_DEPLOYMENT_ID=$ANS_LIC_ID"$'\n'
        else
            LICENSE_MODE=offline LICENSE_IMPORT_FILE="${ANS_LIC_FILE:-}"
        fi
    elif [[ "$first_install" == "0" && -z "$recorded_mode" ]]; then
        # Unattended upgrade of an install from before this choice existed:
        # it runs on the offline (C05) license it already has. Don't block it.
        LICENSE_MODE=offline
    elif [[ "${NANO_PREPARE_ONLY:-0}" == "1" ]]; then
        LICENSE_MODE=pending
        [[ "$recorded_mode" == "pending" ]] || LICENSE_ENV_LINES="NANO_LICENSE_MODE=pending"$'\n'
        warn "No license values yet. Before running ./install.sh, add LICENSE_URL, LICENSE_TOKEN and NANO_DEPLOYMENT_ID to .env (from $LICENSE_PAGE_HINT), or pass them to ./install.sh, or set NANO_LICENSE_MODE=offline."
        return 0
    else
        fail "No license for this unattended enterprise install (no TTY to ask). Pass LICENSE_URL, LICENSE_TOKEN and NANO_DEPLOYMENT_ID from $LICENSE_PAGE_HINT, for example: LICENSE_URL=$LICENSE_DEFAULT_URL LICENSE_TOKEN=<token> NANO_DEPLOYMENT_ID=<deployment id> ./install.sh. Without access to api.nano.rs, set NANO_LICENSE_MODE=offline (import the license file after install) or AIRGAP_MODE=true. Nothing was started."
    fi
    [[ "$LICENSE_MODE" == "$recorded_mode" ]] || LICENSE_ENV_LINES+="NANO_LICENSE_MODE=$LICENSE_MODE"$'\n'
    return 0
}

# Set LICENSE_ENV_LINES in $1 and say what was decided (token redacted).
# NAN-5251: each key is replaced in place (pending -> online keeps one
# NANO_LICENSE_MODE line where it was); appending left two.
record_license() {
    local target="$1" license_line
    local -a license_kvs=()
    while IFS= read -r license_line; do
        [[ -n "$license_line" ]] && license_kvs+=("$license_line")
    done <<< "$LICENSE_ENV_LINES"
    if ((${#license_kvs[@]} > 0)); then
        # The first-install temp file locks on its eventual .env path, as the
        # secret backfill does, so no lock file is left beside the temp file.
        nano_env_atomic_rewrite_locked "$target" "$PWD/.env" nano_env_set_keys_writer "${license_kvs[@]}" \
            || fail "Could not record the license values in $target."
    fi
    license_kvs=()
    LICENSE_ENV_LINES=""
    case "$LICENSE_MODE" in
        online)
            ok "License: online check-in for deployment $LICENSE_DEPLOYMENT_ID (LICENSE_TOKEN ******** in .env)" ;;
        offline)
            if [[ -n "$LICENSE_IMPORT_FILE" ]]; then
                ok "License: offline; $LICENSE_IMPORT_FILE is imported after the admin account is created"
            else
                ok "License: offline; import the license file after install under Settings → License"
            fi ;;
        airgap) ok "License: air-gapped (AIRGAP_MODE); import the offline license after install" ;;
    esac
}

# Admin email / display name are kept in .env so a re-run (prepare, then
# install; or a retry after a failed start) can still create the account.
# Single-quoted for Compose, which would otherwise interpolate '$'. A value
# that cannot be single-quoted safely is not persisted. Never the password.
persistable_env_value() {
    [[ -n "${1:-}" && "$1" != *[\'\"\\\`\$]* && "$1" != *[[:cntrl:]]* ]]
}

# Import the offline license file chosen at install (NANO_LICENSE_FILE or the
# prompt) as the admin, once the account exists. Best effort: nano is already
# up, so a refusal is reported with the manual path instead of failing.
# Secrets go to curl through 0600 files, never its command line.
import_offline_license() {
    [[ -n "${LICENSE_IMPORT_FILE:-}" ]] || return 0
    local manual="Import $LICENSE_IMPORT_FILE under Settings → License ($BASE_URL/settings/license)."
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
        warn "Could not sign in as $ADMIN_EMAIL to import the offline license (HTTP $code). $manual"
        return 0
    fi
    access_token=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tokens"]["access_token"])' "$scratch/session" </dev/null 2>/dev/null \
        || node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).tokens.access_token)' -- "$scratch/session" </dev/null 2>/dev/null) \
        || access_token=""
    if [[ -z "$access_token" ]]; then
        rm -rf "$scratch"
        warn "Could not read the sign-in response to import the offline license. $manual"
        return 0
    fi
    printf 'Authorization: Bearer %s\n' "$access_token" > "$scratch/auth"
    access_token=""
    if code=$(api_call /dev/null -X POST -H "@$scratch/auth" -H "Content-Type: application/json" \
        --data-binary "@$LICENSE_IMPORT_FILE" "${API_BASE}/api/license/import"); then
        ok "Offline license imported from $LICENSE_IMPORT_FILE"
    elif [[ "$code" == "409" ]]; then
        warn "The offline license was refused (HTTP 409): it is bound to another installation, superseded or out of term. On your deployment's page in app.nano.rs, enter this install's installation and organization IDs (Settings → License) and download a new file. $manual"
    else
        warn "The offline license was not imported (HTTP $code). $manual"
    fi
    rm -rf "$scratch"
}

gen_secret() { openssl rand -hex 32 </dev/null; }

# Keep first-run validation identical to nanosiem-core's authoritative policy.
# This runs before .env is written or any image is pulled/started, so a weak
# non-interactive password cannot leave a distributed install half-mutated.
ADMIN_PASSWORD_RULE="Admin password must be 12 to 1024 bytes and contain uppercase, lowercase, a digit, and a special character."

# 0 when $1 meets nano-api's admin password policy (no output).
admin_password_ok() {
    local password="$1" byte_length i char
    local has_upper=0 has_lower=0 has_digit=0 has_special=0
    local LC_ALL=C
    byte_length=${#password}
    (( byte_length >= 12 && byte_length <= 1024 )) || return 1
    for ((i = 0; i < byte_length; i++)); do
        char=${password:i:1}
        case "$char" in
            [A-Z]) has_upper=1 ;;
            [a-z]) has_lower=1 ;;
            [0-9]) has_digit=1 ;;
            '!'|'@'|'#'|'$'|'%'|'^'|'&'|'*'|'('|')'|'-'|'_'|'='|'+'|'['|']'|'{'|'}'|'|'|'\'|';'|':'|"'"|'"'|','|'.'|'<'|'>'|'/'|'?'|'`'|'~') has_special=1 ;;
        esac
    done
    (( has_upper && has_lower && has_digit && has_special ))
}

validate_admin_password() {
    admin_password_ok "$1" || fail "$ADMIN_PASSWORD_RULE"
}

# NAN-5495: interactive admin password; blank autogenerates one (and sets
# GENERATED_PASSWORD=1), anything that misses the policy is asked again
# instead of ending the install.
prompt_admin_password() {
    local answer
    while :; do
        # `|| exit` (its status: 4 on NANO_PROMPT_TIMEOUT): prompt_tty's no-TTY failure ends only its subshell; a
        # caller in a condition (set -e off) would otherwise re-ask forever.
        answer=$(prompt_tty "Admin password (blank = autogenerate)" "" secret NANO_ADMIN_PASSWORD) || exit
        if [[ -z "$answer" ]]; then
            ADMIN_PASSWORD="N!a1$(gen_secret | cut -c1-20)"
            GENERATED_PASSWORD=1
            return 0
        fi
        admin_password_ok "$answer" && { ADMIN_PASSWORD=$answer; return 0; }
        warn "$ADMIN_PASSWORD_RULE"
    done
}

# An address the first admin can sign in with: local@domain, no spaces.
valid_admin_email() {
    [[ "${1:-}" =~ ^[^[:space:]@]+@[^[:space:]@]+$ ]]
}

# Sets ADMIN_EMAIL (not a $(...) helper: warn writes to stdout).
prompt_admin_email() {
    local answer
    while :; do
        answer=$(prompt_tty "Admin email" "" "" NANO_ADMIN_EMAIL) || exit
        # Trim the ends only: "john smith@x" is refused, never "johnsmith@x".
        answer=$(trim_space "$answer")
        valid_admin_email "$answer" && { ADMIN_EMAIL=$answer; return 0; }
        warn "Enter the admin's email address (name@domain, no spaces)."
    done
}

# Leading and trailing whitespace removed; nothing inside is touched.
trim_space() {
    local value="${1:-}"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    printf '%s' "$value"
}

# NAN-5495: the public base URL is http(s)://host[:port][/path] (v2.0.28
# accepted "N"). Prints it normalized: scheme lowercased, trailing slashes and
# one trailing dot on the host removed, port 1-65535 in decimal.
normalize_base_url() {
    local url="${1:-}" scheme host port url_path
    while [[ "$url" == */ ]]; do url="${url%/}"; done
    if [[ "$url" == *://* ]]; then
        scheme=$(printf '%s' "${url%%://*}" | tr '[:upper:]' '[:lower:]')
        url="$scheme://${url#*://}"
    fi
    [[ "$url" =~ ^(https?)://([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?|\[[0-9A-Fa-f:.]+\])\.?(:([0-9]{1,5}))?(/[A-Za-z0-9._~%/-]*)?$ ]] || return 1
    scheme=${BASH_REMATCH[1]} host=${BASH_REMATCH[2]} port=${BASH_REMATCH[5]} url_path=${BASH_REMATCH[6]}
    if [[ -n "$port" ]]; then
        (( 10#$port >= 1 && 10#$port <= 65535 )) || return 1
        port=":$(( 10#$port ))"
    fi
    printf '%s://%s%s%s' "$scheme" "$host" "$port" "$url_path"
}

# Sets BASE_URL; $1 is the default.
prompt_base_url() {
    local answer url
    while :; do
        answer=$(prompt_tty "Public base URL" "$1" "" NANO_BASE_URL) || exit
        answer=$(trim_space "$answer")
        url=$(normalize_base_url "$answer") && { BASE_URL=$url; return 0; }
        warn "Enter the URL users open nano at, as http(s)://host[:port] (for example https://nano.example.com)."
    done
}

# NAN-5495: a reused .env can hold a BASE_URL v2.0.28 accepted unchecked
# ("N"). With a TTY (and this host owning .env: single node or the app role)
# it is asked again and recorded; otherwise warned about, never fatal, so an
# existing install keeps upgrading. A valid value is left exactly as it is.
revalidate_recorded_base_url() {
    local recorded dev default=""
    [[ -z "${NANO_BASE_URL:-}" ]] || return 0
    recorded=$(env_value BASE_URL)
    [[ -n "$recorded" ]] || return 0
    normalize_base_url "$recorded" >/dev/null && return 0
    if have_controlling_tty && [[ "${MULTI_NODE:-0}" != "1" || ",${ROLE_ARG:-}," == *,app,* ]]; then
        [[ -n "${ANS_BASE_URL:-}" ]] \
            || warn "This install's .env has BASE_URL='$recorded', which is not a URL users can open nano at."
        # Enter must never silently record http://localhost (and dev mode): a
        # bare host name or IP (a dotted name, an IPv4 address or a bracketed
        # IPv6 address, optionally with :port) is offered back as
        # https://<recorded>; anything else, "N" included, has no default and
        # is asked until a valid URL is typed.
        # NAN-5508: asked with the other questions, before anything is written.
        if [[ -n "${ANS_BASE_URL:-}" ]]; then
            BASE_URL=$ANS_BASE_URL
        else
            default=$(base_url_reask_default)
            prompt_base_url "$default"
        fi
        dev=false
        [[ "$BASE_URL" == http://* ]] && dev=true
        nano_env_set_keys .env "BASE_URL=$BASE_URL" "NANOSIEM_DEV_MODE=$dev" \
            || fail "Could not record BASE_URL in .env."
        log "Recorded BASE_URL=$BASE_URL in .env"
    else
        warn "This install's .env has BASE_URL='$recorded', which is not a valid http(s)://host[:port] URL; sign-in links and the ingest examples use it. Set BASE_URL=https://<host> in $PWD/.env (role-split: on the app host, then copy .env to every host), or re-run with NANO_BASE_URL=https://<host> ./install.sh."
    fi
}
# >>> interactive answers (NAN-5508) >>>
# ----------------------------------------------------------------------------
# Every interactive question is asked here, before anything is written: no
# .env, no generated secret on disk, no docker login, no container. The run
# then shows a numbered review screen: Enter installs, a number asks that
# answer (and the answers that depend on it) again, q quits with nothing
# written. `back` (or `<`) at any prompt asks the previous question again.
# Without a controlling terminal nothing is asked and nothing changes: the
# configure_* functions take their values from the environment as before.
#
# Each question is a step (ANSWER_STEPS). answer_step_applies decides whether
# a step is asked this run; answer_ask_step asks it and returns 0 (answered),
# 2 (back) or 3 (go to ANSWER_JUMP). The answers live in ANS_* variables,
# which the configure_* functions and the first-install .env writer read.
# ----------------------------------------------------------------------------
ANSWER_REPLY="" ANSWER_JUMP="" ANSWER_TIERING_INTRO=0 ANSWER_ENV_HINT=""
ANSWER_STEPS=(admin_email admin_name admin_password base_url schema
    lic_mode lic_url lic_token lic_id lic_file
    proxy proxy_url proxy_auth proxy_user proxy_pass no_proxy
    ai
    backup backup_dest backup_path backup_s3_endpoint backup_s3_bucket backup_s3_region
    backup_s3_prefix backup_s3_access backup_s3_secret backup_schedule backup_keep
    volume ingest_path retention
    tiering tier_provider tier_azure_url tier_azure_name tier_azure_container tier_azure_key
    tier_bucket tier_endpoint tier_region tier_prefix tier_env_creds tier_access tier_secret
    tier_move tier_cache)
# Review screen lines: "item first-step last-step label".
ANSWER_ITEMS=("admin_email admin_email admin_email Admin email"
    "admin_name admin_name admin_name Admin name"
    "admin_password admin_password admin_password Admin password"
    "base_url base_url base_url Base URL"
    "schema schema schema Schema profile"
    "license lic_mode lic_file License"
    "proxy proxy no_proxy Outbound proxy"
    "ai ai ai Local AI network"
    "backup backup backup_keep Automatic backups"
    "volume volume ingest_path Planned volume"
    "retention retention retention Retention"
    "tiering tiering tier_cache Cold storage tiering")

# NAN-5749: reads one line from the terminal into the variable named $1 ($2 =
# secret reads without echo); returns read's status on end of input.
#
# bash 5.3 on Linux loses a SIGINT that lands after the prompt is printed but
# before read(2) blocks: the INT trap is left pending and the read never
# returns, so a quick Ctrl-C hung the installer. On bash 4+ the line is read in
# 1-second slices: a timed-out slice ends the read builtin (status > 128) and
# bash runs the pending trap before the next one. Each slice's bytes are
# appended, so input a slice already consumed (a line flushed with one Ctrl-D,
# or a terminal left in non-canonical mode) is kept. The gate is bash >= 4, not
# "5.3 on Linux": it keys on what the loop needs (a timeout status distinct from
# end of input, which bash 3.2 lacks: it returns 1 for both) and covers any
# build with the same race. bash 3.2 (stock macOS /bin/bash) does not lose the
# signal and keeps one blocking read.
#
# A secret turns echo off once with stty for the whole read, on every bash:
# read -s per slice would turn echo back on between slices, and bash 3.2 leaves
# it off when the INT trap exits during read -s. cleanup_env_temp restores it.
# Without a working stty a secret is one blocking read -s: never sliced, so no
# keystroke can echo.
#
# NANO_PROMPT_TIMEOUT (seconds) is the time allowed to answer each prompt
# (press Enter): past it the installer stops (prompt_timed_out). The terminal
# is line-buffered, so typing without Enter does not extend it. Unset, a
# prompt waits for as long as the person at the terminal needs.
TTY_SAVED_STATE=""
tty_read_line() {
    local _tty_rc=0 _tty_buf="" _tty_chunk="" _tty_since=$SECONDS
    if [[ "${2:-}" == secret ]]; then
        if ! { TTY_SAVED_STATE=$(stty -g < /dev/tty 2>/dev/null) && [[ -n "$TTY_SAVED_STATE" ]] \
                && stty -echo < /dev/tty 2>/dev/null; }; then
            tty_restore_state
            IFS= read -rs ${NANO_PROMPT_TIMEOUT:+-t "$NANO_PROMPT_TIMEOUT"} "$1" < /dev/tty || _tty_rc=$?
            (( _tty_rc <= 128 )) || prompt_timed_out
            return "$_tty_rc"
        fi
    fi
    if (( BASH_VERSINFO[0] < 4 )); then
        IFS= read -r ${NANO_PROMPT_TIMEOUT:+-t "$NANO_PROMPT_TIMEOUT"} "$1" < /dev/tty || _tty_rc=$?
        tty_restore_state
        # bash 3.2 returns 1 for a timeout and for end of input alike.
        [[ -z "${NANO_PROMPT_TIMEOUT:-}" ]] || (( _tty_rc == 0 || SECONDS - _tty_since < NANO_PROMPT_TIMEOUT )) \
            || prompt_timed_out
        return "$_tty_rc"
    fi
    while :; do
        _tty_rc=0 _tty_chunk=""
        IFS= read -r -t 1 _tty_chunk < /dev/tty || _tty_rc=$?
        _tty_buf+="$_tty_chunk"
        (( _tty_rc > 128 )) || break
        if [[ -n "${NANO_PROMPT_TIMEOUT:-}" ]] && (( SECONDS - _tty_since >= NANO_PROMPT_TIMEOUT )); then
            tty_restore_state
            prompt_timed_out
        fi
    done
    tty_restore_state
    printf -v "$1" '%s' "$_tty_buf"
    return "$_tty_rc"
}

tty_restore_state() {
    [[ -n "$TTY_SAVED_STATE" ]] || return 0
    stty "$TTY_SAVED_STATE" < /dev/tty 2>/dev/null || true
    TTY_SAVED_STATE=""
}

# Every prompt says what it waits for before it waits, on stderr (a captured
# log shows it even when the terminal output is not kept), and how to answer
# it without a terminal: $1 = the question, $2 = the environment variable
# (or VAR=value) that answers it, if any.
PROMPT_WAIT_LABEL="" PROMPT_WAIT_SKIP=""
prompt_wait_log() {
    PROMPT_WAIT_LABEL="$1" PROMPT_WAIT_SKIP="${2:-}"
    printf '==> waiting for input: %s (%s)\n' "$PROMPT_WAIT_LABEL" "$(prompt_skip_hint)" >&2
}
prompt_skip_hint() {
    if [[ -n "$PROMPT_WAIT_SKIP" ]]; then
        printf 'set %s to skip' "$PROMPT_WAIT_SKIP"
    else
        printf '%s' "run with --non-interactive to skip"
    fi
}
# NANO_PROMPT_TIMEOUT ran out at the prompt prompt_wait_log last announced.
# Exit 4, like the other "no answer" stops.
prompt_timed_out() {
    printf '\n' > /dev/tty 2>/dev/null || true
    printf 'install.sh: no answer within NANO_PROMPT_TIMEOUT=%ss to: %s (%s). Stopped.\n' \
        "$NANO_PROMPT_TIMEOUT" "${PROMPT_WAIT_LABEL:-a prompt}" "$(prompt_skip_hint)" >&2
    exit 4
}

# Reads one answer from the terminal into ANSWER_REPLY ($2 is shown as
# [default] and taken on Enter; $3 = secret reads without echo). Returns 2
# when the answer is `back` or `<`. End of input stops the installer: a
# closed terminal must not re-ask forever.
answer_read() {
    local prompt="$1" default="${2:-}" secret="${3:-}" shown="$1" reply=""
    [[ -n "$default" ]] && shown="$prompt [$default]"
    prompt_wait_log "$prompt" "${ANSWER_ENV_HINT:-}"
    printf '%s: ' "$shown" > /dev/tty
    if [[ -n "$secret" ]]; then
        tty_read_line reply secret || answer_input_ended
        printf '\n' > /dev/tty
    else
        tty_read_line reply || answer_input_ended
    fi
    reply=${reply%$'\r'}
    case "$(trim_space "$reply")" in
        back|BACK|Back|"<") ANSWER_REPLY=""; return 2 ;;
    esac
    [[ -z "$reply" && -n "$default" ]] && reply="$default"
    ANSWER_REPLY="$reply"
    return 0
}

# End of input at a question: no answer, exit 4 (like the other "no answer" stops).
answer_input_ended() {
    printf '\n' > /dev/tty
    printf '%b✗ %s%b\n' "$c_red$c_bold" "Input ended before the questions were answered. Nothing was written." "$c_reset" >&2
    exit 4
}

# Yes/no into ANSWER_REPLY (true/false); $2 is the current answer or default.
answer_yes_no() {
    local question="$1" current="$2" hint="[y/N]" value
    [[ "$current" == true ]] && hint="[Y/n]"
    while :; do
        answer_read "$question $hint" || return
        value="$ANSWER_REPLY"
        [[ -z "$value" ]] && value="$current"
        value=$(normalize_bool "$value")
        [[ -n "$value" ]] && { ANSWER_REPLY="$value"; return 0; }
        warn "Answer y or n."
    done
}

# A value .env and Python both read verbatim: no whitespace, quotes, $, `, \ or #.
answer_env_safe() {
    [[ -n "${1:-}" && "$1" != *[[:space:]\'\"\$\`\\#]* ]]
}

# Validates the collected tiering answers with nano-tiering.py (nothing is
# written; secrets go through the environment, never argv).
answer_tiering_check() {
    NANO_TIERING=on NANO_TIERING_PROVIDER="$ANS_TIER_PROVIDER" NANO_TIERING_BUCKET="${ANS_TIER_BUCKET:-}" \
        NANO_TIERING_ENDPOINT="${ANS_TIER_ENDPOINT:-}" NANO_TIERING_REGION="${ANS_TIER_REGION:-}" \
        NANO_TIERING_PREFIX="${ANS_TIER_PREFIX:-}" NANO_TIERING_MOVE_FACTOR="${ANS_TIER_MOVE:-}" \
        NANO_TIERING_CACHE_SIZE="${ANS_TIER_CACHE:-}" \
        NANO_TIERING_USE_ENVIRONMENT_CREDENTIALS="${ANS_TIER_ENV_CREDS:-false}" \
        NANO_TIERING_AZURE_ACCOUNT_URL="${ANS_TIER_AZURE_URL:-}" NANO_TIERING_AZURE_ACCOUNT_NAME="${ANS_TIER_AZURE_NAME:-}" \
        NANO_TIERING_AZURE_CONTAINER="${ANS_TIER_AZURE_CONTAINER:-}" NANO_TIERING_AZURE_ACCOUNT_KEY="${ANS_TIER_AZURE_KEY:-}" \
        NANO_TIERING_ACCESS_KEY_ID="${ANS_TIER_ACCESS:-}" NANO_TIERING_SECRET_ACCESS_KEY="${ANS_TIER_SECRET:-}" \
        python3 -I scripts/nano-tiering.py --install-dir "$PWD" configure --from-installer --check </dev/null 2>&1
}

# The tiering answers as NANO_TIERING* assignments for `env` (apply phase).
answer_tiering_env() {
    if [[ "${ANS_TIERING:-false}" != true ]]; then
        printf '%s\n' NANO_TIERING=off
        return 0
    fi
    printf '%s\n' NANO_TIERING=on "NANO_TIERING_PROVIDER=$ANS_TIER_PROVIDER" \
        "NANO_TIERING_MOVE_FACTOR=$ANS_TIER_MOVE" "NANO_TIERING_CACHE_SIZE=$ANS_TIER_CACHE"
    if [[ "$ANS_TIER_PROVIDER" == azure ]]; then
        printf '%s\n' "NANO_TIERING_AZURE_ACCOUNT_URL=$ANS_TIER_AZURE_URL" \
            "NANO_TIERING_AZURE_ACCOUNT_NAME=$ANS_TIER_AZURE_NAME" \
            "NANO_TIERING_AZURE_CONTAINER=$ANS_TIER_AZURE_CONTAINER" \
            "NANO_TIERING_AZURE_ACCOUNT_KEY=$ANS_TIER_AZURE_KEY"
        return 0
    fi
    printf '%s\n' "NANO_TIERING_BUCKET=$ANS_TIER_BUCKET" "NANO_TIERING_PREFIX=$ANS_TIER_PREFIX" \
        "NANO_TIERING_USE_ENVIRONMENT_CREDENTIALS=${ANS_TIER_ENV_CREDS:-false}"
    [[ "$ANS_TIER_PROVIDER" == s3-compatible ]] && printf '%s\n' "NANO_TIERING_ENDPOINT=$ANS_TIER_ENDPOINT"
    [[ "$ANS_TIER_PROVIDER" == s3 || "$ANS_TIER_PROVIDER" == s3-compatible ]] \
        && printf '%s\n' "NANO_TIERING_REGION=$ANS_TIER_REGION"
    if [[ "${ANS_TIER_ENV_CREDS:-false}" != true ]]; then
        printf '%s\n' "NANO_TIERING_ACCESS_KEY_ID=$ANS_TIER_ACCESS" "NANO_TIERING_SECRET_ACCESS_KEY=$ANS_TIER_SECRET"
    fi
    return 0
}

# Whether this run asks review item $1 (WANT_<item>=1, set by collect_answers).
answer_wanted() {
    local flag="WANT_$1"
    [[ "${!flag:-0}" == 1 ]]
}

answer_step_applies() {
    case "$1" in
        admin_email|admin_name|admin_password|base_url|schema|ai|retention)
            answer_wanted "$1" ;;
        lic_mode) [[ "${WANT_license:-0}" == 1 ]] ;;
        lic_url|lic_token|lic_id) [[ "${WANT_license:-0}" == 1 && "${ANS_LIC_MODE:-}" == online ]] ;;
        lic_file) [[ "${WANT_license:-0}" == 1 && "${ANS_LIC_MODE:-}" == offline ]] ;;
        proxy) [[ "${WANT_proxy:-0}" == 1 ]] ;;
        proxy_url|proxy_auth|no_proxy) [[ "${WANT_proxy:-0}" == 1 && "${ANS_PROXY:-}" == true ]] ;;
        proxy_user|proxy_pass) [[ "${WANT_proxy:-0}" == 1 && "${ANS_PROXY:-}" == true && "${ANS_PROXY_AUTH:-}" == true ]] ;;
        backup) [[ "${WANT_backup:-0}" == 1 ]] ;;
        backup_dest|backup_schedule|backup_keep) [[ "${WANT_backup:-0}" == 1 && "${ANS_BACKUP:-}" == true ]] ;;
        backup_path) [[ "${WANT_backup:-0}" == 1 && "${ANS_BACKUP:-}" == true && "${ANS_BACKUP_DEST:-}" == path ]] ;;
        backup_s3_*) [[ "${WANT_backup:-0}" == 1 && "${ANS_BACKUP:-}" == true && "${ANS_BACKUP_DEST:-}" == s3 ]] ;;
        volume) [[ "${WANT_volume:-0}" == 1 ]] ;;
        ingest_path) [[ "${WANT_volume:-0}" == 1 && "${WANT_ingest_path:-0}" == 1 && -n "${ANS_VOLUME:-}" && "${ANS_VOLUME:-}" != 0 ]] ;;
        tiering) [[ "${WANT_tiering:-0}" == 1 ]] ;;
        tier_provider|tier_move|tier_cache) [[ "${WANT_tiering:-0}" == 1 && "${ANS_TIERING:-}" == true ]] ;;
        tier_azure_*) [[ "${WANT_tiering:-0}" == 1 && "${ANS_TIERING:-}" == true && "${ANS_TIER_PROVIDER:-}" == azure ]] ;;
        tier_bucket|tier_prefix) [[ "${WANT_tiering:-0}" == 1 && "${ANS_TIERING:-}" == true && "${ANS_TIER_PROVIDER:-}" != azure ]] ;;
        tier_endpoint) [[ "${WANT_tiering:-0}" == 1 && "${ANS_TIERING:-}" == true && "${ANS_TIER_PROVIDER:-}" == s3-compatible ]] ;;
        tier_region) [[ "${WANT_tiering:-0}" == 1 && "${ANS_TIERING:-}" == true \
            && ( "${ANS_TIER_PROVIDER:-}" == s3 || "${ANS_TIER_PROVIDER:-}" == s3-compatible ) ]] ;;
        tier_env_creds) [[ "${WANT_tiering:-0}" == 1 && "${ANS_TIERING:-}" == true \
            && ( "${ANS_TIER_PROVIDER:-}" == s3 || "${ANS_TIER_PROVIDER:-}" == gcs ) ]] ;;
        tier_access|tier_secret) [[ "${WANT_tiering:-0}" == 1 && "${ANS_TIERING:-}" == true \
            && "${ANS_TIER_PROVIDER:-}" != azure && "${ANS_TIER_ENV_CREDS:-false}" != true ]] ;;
        *) return 1 ;;
    esac
}

# Asks one step. Every validating prompt re-asks on a bad answer, as before.
answer_ask_step() {
    local value confirm default label err
    case "$1" in
        admin_email)
            while :; do
                answer_read "Admin email" "${ANS_ADMIN_EMAIL:-}" || return
                value=$(trim_space "$ANSWER_REPLY")
                valid_admin_email "$value" && { ANS_ADMIN_EMAIL=$value; return 0; }
                warn "Enter the admin's email address (name@domain, no spaces)."
            done ;;
        admin_name)
            while :; do
                answer_read "Admin display name" "${ANS_ADMIN_NAME:-Admin}" || return
                value=$(trim_space "$ANSWER_REPLY")
                [[ -n "$value" ]] && { ANS_ADMIN_NAME=$value; return 0; }
                warn "Enter a display name."
            done ;;
        admin_password)
            while :; do
                answer_read "Admin password (blank = autogenerate)" "" secret || return
                if [[ -z "$ANSWER_REPLY" ]]; then
                    ANS_ADMIN_PASSWORD="N!a1$(gen_secret | cut -c1-20)" ANS_PASSWORD_GENERATED=1
                    return 0
                fi
                admin_password_ok "$ANSWER_REPLY" \
                    && { ANS_ADMIN_PASSWORD=$ANSWER_REPLY ANS_PASSWORD_GENERATED=0; return 0; }
                warn "$ADMIN_PASSWORD_RULE"
            done ;;
        base_url)
            while :; do
                answer_read "Public base URL" "${ANS_BASE_URL:-$ANSWER_BASE_URL_DEFAULT}" || return
                value=$(normalize_base_url "$(trim_space "$ANSWER_REPLY")") && { ANS_BASE_URL=$value; return 0; }
                warn "Enter the URL users open nano at, as http(s)://host[:port] (for example https://nano.example.com)."
            done ;;
        schema)
            while :; do
                answer_read "Schema profile — 'ocsf' (recommended), 'ocsf+tenzir' (OCSF + a bundled Tenzir node for direct ingestion), or 'udm' (legacy CIM-style)" "${ANS_SCHEMA:-ocsf}" || return
                value=$(printf '%s' "$ANSWER_REPLY" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
                case "$value" in
                    ""|ocsf) ANS_SCHEMA=ocsf; return 0 ;;
                    udm) ANS_SCHEMA=udm; return 0 ;;
                    ocsf+tenzir)
                        # NAN-5506: the bundled Tenzir node raises this host's floor.
                        if [[ "${MULTI_NODE:-0}" == "1" ]]; then
                            warn "The bundled Tenzir profile is single-node only; choose 'ocsf' or 'udm'."
                        elif err=$( (nano_host_minimums_gate "$NANO_HOST_SINGLE_NODE_ROLES,tenzir" "$PWD") 2>&1 ); then
                            ANS_SCHEMA=ocsf+tenzir; return 0
                        else
                            printf '%s\n' "$err" >&2
                            warn "This host is too small for the bundled Tenzir node; choose 'ocsf' or 'udm'."
                        fi ;;
                    *) warn "Enter 'ocsf', 'ocsf+tenzir', or 'udm'." ;;
                esac
            done ;;
        lic_mode)
            while :; do
                answer_read "License: online check-in (paste the 3 values from app.nano.rs) or offline file (path)? [online/offline]" "${ANS_LIC_MODE:-$ANSWER_LICENSE_DEFAULT}" || return
                value=$(printf '%s' "$ANSWER_REPLY" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
                case "$value" in
                    online|on|1) ANS_LIC_MODE=online; return 0 ;;
                    offline|off|file|2) ANS_LIC_MODE=offline; return 0 ;;
                    *) warn "Answer online or offline." ;;
                esac
            done ;;
        lic_url)
            while :; do
                answer_read "LICENSE_URL" "${ANS_LIC_URL:-$LICENSE_DEFAULT_URL}" || return
                value=$(strip_license_paste "$ANSWER_REPLY" LICENSE_URL)
                valid_license_url "$value" && { ANS_LIC_URL=$value; return 0; }
                warn "Enter the https:// license URL shown on the deployment page."
            done ;;
        lic_token)
            label="LICENSE_TOKEN (input hidden)"
            [[ -n "${ANS_LIC_TOKEN:-}" ]] && label="LICENSE_TOKEN (input hidden) [keep]"
            while :; do
                answer_read "$label" "" secret || return
                [[ -z "$ANSWER_REPLY" && -n "${ANS_LIC_TOKEN:-}" ]] && return 0
                value=$(strip_license_paste "$ANSWER_REPLY" LICENSE_TOKEN)
                valid_license_token "$value" && { ANS_LIC_TOKEN=$value; return 0; }
                warn "That is not an enrollment token (value not shown). Paste LICENSE_TOKEN from the deployment page; if it was lost, regenerate it there."
            done ;;
        lic_id)
            while :; do
                answer_read "NANO_DEPLOYMENT_ID" "${ANS_LIC_ID:-}" || return
                value=$(strip_license_paste "$ANSWER_REPLY" NANO_DEPLOYMENT_ID)
                valid_deployment_id "$value" && { ANS_LIC_ID=$value; return 0; }
                warn "Enter the deployment ID from the deployment page (deploy_ followed by 26 characters)."
            done ;;
        lic_file)
            while :; do
                answer_read "Offline license file path (blank = import it after install under Settings → License)" "${ANS_LIC_FILE:-}" || return
                [[ -z "$ANSWER_REPLY" ]] && { ANS_LIC_FILE=""; return 0; }
                value=$(resolve_offline_license_file "$ANSWER_REPLY") && { ANS_LIC_FILE=$value; return 0; }
            done ;;
        proxy)
            # Offer an exported proxy as the default, without any credentials
            # it carries (they would be shown in the prompt).
            ANSWER_SHELL_PROXY=$(strip_proxy_userinfo "${HTTPS_PROXY:-${https_proxy:-}}")
            valid_proxy_hostport "$ANSWER_SHELL_PROXY" || ANSWER_SHELL_PROXY=""
            default=false
            [[ -n "$ANSWER_SHELL_PROXY" ]] && default=true
            answer_yes_no "Does this server reach the internet through an HTTP(S) proxy?" "${ANS_PROXY:-$default}" || return
            ANS_PROXY=$ANSWER_REPLY ;;
        proxy_url)
            while :; do
                answer_read "Proxy URL (http://host:port)" "${ANS_PROXY_URL:-$ANSWER_SHELL_PROXY}" || return
                valid_proxy_hostport "$ANSWER_REPLY" && { ANS_PROXY_URL=$ANSWER_REPLY; return 0; }
                warn "Enter the proxy as http://host:port or https://host:port (no credentials, quotes or spaces)."
            done ;;
        proxy_auth)
            answer_yes_no "Does the proxy require a username and password?" "${ANS_PROXY_AUTH:-false}" || return
            ANS_PROXY_AUTH=$ANSWER_REPLY ;;
        proxy_user)
            while :; do
                answer_read "Proxy username (DOMAIN\\user is fine)" "${ANS_PROXY_USER:-}" || return
                [[ -n "$ANSWER_REPLY" ]] && { ANS_PROXY_USER=$ANSWER_REPLY; return 0; }
                warn "Enter the proxy username."
            done ;;
        proxy_pass)
            while :; do
                answer_read "Proxy password" "" secret || return
                value=$ANSWER_REPLY
                answer_read "Confirm proxy password" "" secret || return
                confirm=$ANSWER_REPLY
                if [[ -z "$value" ]]; then
                    warn "Enter the proxy password."
                elif [[ "$value" != "$confirm" ]]; then
                    warn "The passwords do not match. Enter them again."
                else
                    ANS_PROXY_PASS=$value
                    return 0
                fi
            done ;;
        no_proxy)
            while :; do
                answer_read "Extra hosts that bypass the proxy, comma-separated (blank = none)" "${ANS_NO_PROXY-${NO_PROXY:-${no_proxy:-}}}" || return
                [[ -z "$ANSWER_REPLY" ]] && { ANS_NO_PROXY=""; return 0; }
                valid_no_proxy "$ANSWER_REPLY" && { ANS_NO_PROXY=$ANSWER_REPLY; return 0; }
                warn "Enter comma-separated host names, domains, IPs or CIDRs (no spaces)."
            done ;;
        ai)
            answer_yes_no "Will nano use an AI model hosted on your own network (e.g. a local LLM on 192.168.x / 10.x)? This allows the AI provider URL to point at private addresses (cloud-metadata stays blocked)." "${ANS_AI:-false}" || return
            ANS_AI=$ANSWER_REPLY ;;
        backup)
            answer_yes_no "Set up automatic backups?" "${ANS_BACKUP:-false}" || return
            ANS_BACKUP=$ANSWER_REPLY ;;
        backup_dest)
            default=1
            [[ "${ANS_BACKUP_DEST:-}" == s3 ]] && default=2
            while :; do
                answer_read "Destination: (1) local or mounted path (NFS/SMB share), (2) S3-compatible bucket (AWS S3, Wasabi, RustFS ...)" "$default" || return
                case "$(trim_space "$ANSWER_REPLY")" in
                    1|path) ANS_BACKUP_DEST=path; return 0 ;;
                    2|s3) ANS_BACKUP_DEST=s3; return 0 ;;
                esac
                warn "Enter 1 or 2."
            done ;;
        backup_path)
            while :; do
                answer_read "Backup directory (absolute path; mount the share first)" "${ANS_BACKUP_PATH:-}" || return
                value=$(trim_space "$ANSWER_REPLY")
                [[ "$value" == /* ]] && answer_env_safe "$value" && { ANS_BACKUP_PATH=$value; return 0; }
                warn "Enter an absolute directory path (no spaces, quotes, \$, \`, \\ or #)."
            done ;;
        backup_s3_endpoint)
            while :; do
                answer_read "S3 endpoint URL" "${ANS_BACKUP_S3_ENDPOINT:-https://s3.us-east-1.amazonaws.com}" || return
                value=$(trim_space "$ANSWER_REPLY")
                [[ "$value" =~ ^https?://[^/[:space:]]+ ]] && answer_env_safe "$value" && { ANS_BACKUP_S3_ENDPOINT=$value; return 0; }
                warn "Enter the endpoint as https://host[:port]."
            done ;;
        backup_s3_bucket)
            while :; do
                answer_read "Bucket" "${ANS_BACKUP_S3_BUCKET:-}" || return
                value=$(trim_space "$ANSWER_REPLY")
                [[ "$value" =~ ^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$ ]] && { ANS_BACKUP_S3_BUCKET=$value; return 0; }
                warn "Enter a bucket name: 3-63 lower-case letters, digits, '.' or '-'."
            done ;;
        backup_s3_region)
            while :; do
                answer_read "Region" "${ANS_BACKUP_S3_REGION:-us-east-1}" || return
                value=$(trim_space "$ANSWER_REPLY")
                [[ "$value" =~ ^[A-Za-z0-9-]{1,64}$ ]] && { ANS_BACKUP_S3_REGION=$value; return 0; }
                warn "Enter a region such as us-east-1."
            done ;;
        backup_s3_prefix)
            while :; do
                answer_read "Key prefix" "${ANS_BACKUP_S3_PREFIX-nano}" || return
                value=$(trim_space "$ANSWER_REPLY")
                [[ "$value" =~ ^[A-Za-z0-9!_.*/()-]{0,256}$ ]] && { ANS_BACKUP_S3_PREFIX=$value; return 0; }
                warn "Enter a key prefix of letters, digits and !_.*()/- only."
            done ;;
        backup_s3_access|backup_s3_secret)
            label="Access key ID"
            [[ "$1" == backup_s3_secret ]] && label="Secret access key"
            [[ -n "$(answer_current "$1")" ]] && label+=" [keep]"
            while :; do
                answer_read "$label" "" secret || return
                [[ -z "$ANSWER_REPLY" && -n "$(answer_current "$1")" ]] && return 0
                if answer_env_safe "$ANSWER_REPLY"; then
                    if [[ "$1" == backup_s3_access ]]; then ANS_BACKUP_S3_ACCESS=$ANSWER_REPLY; else ANS_BACKUP_S3_SECRET=$ANSWER_REPLY; fi
                    return 0
                fi
                warn "Enter the key (it cannot be blank or hold whitespace, quotes, \$, \`, \\ or #)."
            done ;;
        backup_schedule)
            while :; do
                answer_read "Daily backup time (HH:MM, local)" "${ANS_BACKUP_SCHEDULE:-02:00}" || return
                value=$(trim_space "$ANSWER_REPLY")
                [[ "$value" =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]] && { ANS_BACKUP_SCHEDULE=$value; return 0; }
                warn "Enter a 24-hour time as HH:MM (for example 02:00)."
            done ;;
        backup_keep)
            while :; do
                answer_read "Backups to keep" "${ANS_BACKUP_KEEP:-7}" || return
                value=$(trim_space "$ANSWER_REPLY")
                [[ "$value" =~ ^[1-9][0-9]{0,3}$ ]] && { ANS_BACKUP_KEEP=$value; return 0; }
                warn "Enter a whole number from 1 to 9999."
            done ;;
        volume)
            while :; do
                answer_read "Planned log volume in GB per day (Enter to skip: settings then follow this host's size only)" "${ANS_VOLUME:-}" || return
                value=$(printf '%s' "$ANSWER_REPLY" | tr -d '[:space:]')
                [[ -z "$value" ]] && { ANS_VOLUME=""; return 0; }
                valid_planned_gb_per_day "$value" && { ANS_VOLUME=$(( 10#$value )); return 0; }
                warn "Enter a whole number of GB per day, or press Enter to skip."
            done ;;
        ingest_path)
            default=raw
            [[ "${ANS_SCHEMA:-}" == ocsf+tenzir || "${BUNDLE_TENZIR:-0}" == 1 ]] && default=preshaped
            while :; do
                answer_read "Do events arrive as raw logs that nano parses, or pre-shaped OCSF (Tenzir/Cribl)? raw/preshaped" "${ANS_INGEST_PATH:-$default}" || return
                value=$(trim_space "$ANSWER_REPLY")
                [[ "$value" == raw || "$value" == preshaped ]] && { ANS_INGEST_PATH=$value; return 0; }
                warn "Enter raw or preshaped."
            done ;;
        retention)
            while :; do
                answer_read "Event retention in days (the disk still caps it; change later in Settings -> Storage)" "${ANS_RETENTION:-365}" || return
                value=$(printf '%s' "$ANSWER_REPLY" | tr -d '[:space:]')
                valid_retention_days "$value" && { ANS_RETENTION=$(( 10#$value )); return 0; }
                warn "Enter a whole number of days, 1-3650."
            done ;;
        tiering)
            if [[ "$ANSWER_TIERING_INTRO" == 0 ]]; then
                ANSWER_TIERING_INTRO=1
                printf '%s\n' "Cold storage tiering keeps recent events on this host's disk and moves older ClickHouse parts to object storage (AWS S3, S3-compatible, GCS or Azure Blob) when the disk fills; they stay searchable. You can turn it on later with: scripts/nano tiering configure" > /dev/tty
            fi
            answer_yes_no "Enable cold storage tiering?" "${ANS_TIERING:-false}" || return
            ANS_TIERING=$ANSWER_REPLY ;;
        tier_provider)
            while :; do
                answer_read "Object store: s3, s3-compatible (Wasabi, RustFS, ...), gcs or azure" "${ANS_TIER_PROVIDER:-s3}" || return
                value=$(printf '%s' "$ANSWER_REPLY" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
                case "$value" in
                    s3|s3-compatible|gcs|azure)
                        # A different store: its location and credentials are asked anew.
                        if [[ "$value" != "${ANS_TIER_PROVIDER:-}" ]]; then
                            ANS_TIER_BUCKET="" ANS_TIER_ENDPOINT="" ANS_TIER_REGION="" ANS_TIER_ACCESS="" ANS_TIER_SECRET=""
                            ANS_TIER_ENV_CREDS="" ANS_TIER_AZURE_URL="" ANS_TIER_AZURE_NAME="" ANS_TIER_AZURE_CONTAINER="" ANS_TIER_AZURE_KEY=""
                        fi
                        ANS_TIER_PROVIDER=$value; return 0 ;;
                esac
                warn "Enter s3, s3-compatible, gcs or azure."
            done ;;
        tier_azure_url) answer_read "Storage account URL (https://<account>.blob.core.windows.net)" "${ANS_TIER_AZURE_URL:-}" || return
            ANS_TIER_AZURE_URL=$(trim_space "$ANSWER_REPLY") ;;
        tier_azure_name) answer_read "Storage account name" "${ANS_TIER_AZURE_NAME:-}" || return
            ANS_TIER_AZURE_NAME=$(trim_space "$ANSWER_REPLY") ;;
        tier_azure_container) answer_read "Container (must exist)" "${ANS_TIER_AZURE_CONTAINER:-}" || return
            ANS_TIER_AZURE_CONTAINER=$(trim_space "$ANSWER_REPLY") ;;
        tier_azure_key)
            label="Storage account key"
            [[ -n "${ANS_TIER_AZURE_KEY:-}" ]] && label+=" [keep]"
            answer_read "$label" "" secret || return
            [[ -z "$ANSWER_REPLY" && -n "${ANS_TIER_AZURE_KEY:-}" ]] || ANS_TIER_AZURE_KEY=$(trim_space "$ANSWER_REPLY") ;;
        tier_bucket) answer_read "Bucket (must exist)" "${ANS_TIER_BUCKET:-}" || return
            ANS_TIER_BUCKET=$(trim_space "$ANSWER_REPLY") ;;
        tier_endpoint) answer_read "Endpoint (https://host[:port])" "${ANS_TIER_ENDPOINT:-}" || return
            ANS_TIER_ENDPOINT=$(trim_space "$ANSWER_REPLY") ;;
        tier_region) answer_read "Region" "${ANS_TIER_REGION:-us-east-1}" || return
            ANS_TIER_REGION=$(trim_space "$ANSWER_REPLY") ;;
        tier_prefix) answer_read "Key prefix inside the bucket" "${ANS_TIER_PREFIX:-nano}" || return
            ANS_TIER_PREFIX=$(trim_space "$ANSWER_REPLY") ;;
        tier_env_creds)
            label="an EC2 instance role"
            [[ "$ANS_TIER_PROVIDER" == gcs ]] && label="this GCE VM's service account"
            answer_yes_no "Use $label instead of access keys?" "${ANS_TIER_ENV_CREDS:-false}" || return
            ANS_TIER_ENV_CREDS=$ANSWER_REPLY ;;
        tier_access)
            label="Access key ID"
            [[ "$ANS_TIER_PROVIDER" == gcs ]] && label="HMAC access key"
            answer_read "$label" "${ANS_TIER_ACCESS:-}" || return
            ANS_TIER_ACCESS=$(trim_space "$ANSWER_REPLY") ;;
        tier_secret)
            label="Secret"
            [[ -n "${ANS_TIER_SECRET:-}" ]] && label="Secret [keep]"
            answer_read "$label" "" secret || return
            [[ -z "$ANSWER_REPLY" && -n "${ANS_TIER_SECRET:-}" ]] || ANS_TIER_SECRET=$(trim_space "$ANSWER_REPLY") ;;
        tier_move) answer_read "Start moving parts when free local disk falls below (fraction, 0 = paused)" "${ANS_TIER_MOVE:-0.3}" || return
            ANS_TIER_MOVE=$(trim_space "$ANSWER_REPLY") ;;
        tier_cache)
            answer_read "Local cache for cold reads" "${ANS_TIER_CACHE:-10Gi}" || return
            ANS_TIER_CACHE=$(trim_space "$ANSWER_REPLY")
            # The last tiering answer: check the whole set now (no network),
            # so a bad value is fixed here rather than after install.
            if ! err=$(answer_tiering_check); then
                printf '%s\n' "${err#nano }" >&2
                answer_yes_no "Enter the object store settings again?" true || return
                if [[ "$ANSWER_REPLY" == true ]]; then
                    ANSWER_JUMP=tier_provider
                    return 3
                fi
                ANS_TIERING=false
            fi ;;
        *) return 1 ;;
    esac
    return 0
}

# Asks one review item's questions on their own (a configure_* function
# called directly on a terminal, or an answer to fix after a failed check).
answer_ask_group() {
    local entry item first last label
    for entry in "${ANSWER_ITEMS[@]}"; do
        read -r item first last label <<< "$entry"
        [[ "$item" == "$1" ]] && break
    done
    [[ "$item" == "$1" ]] || fail "Internal error: no question group $1."
    printf -v "WANT_$1" '%s' 1
    answer_run_steps "$(answer_step_index "$first")" "$(answer_step_index "$last")"
}

# The current value of a secret step, to offer "[keep]".
answer_current() {
    case "$1" in
        backup_s3_access) printf '%s' "${ANS_BACKUP_S3_ACCESS:-}" ;;
        backup_s3_secret) printf '%s' "${ANS_BACKUP_S3_SECRET:-}" ;;
    esac
}

answer_step_index() {
    local i
    for i in "${!ANSWER_STEPS[@]}"; do
        [[ "${ANSWER_STEPS[i]}" == "$1" ]] && { printf '%s' "$i"; return 0; }
    done
    return 1
}

# The environment variable that answers step $1 without a terminal (shown in
# the "waiting for input" line; the full table is in --help and the docs).
answer_step_env() {
    case "$1" in
        admin_email) printf NANO_ADMIN_EMAIL ;;
        admin_name) printf NANO_ADMIN_NAME ;;
        admin_password) printf NANO_ADMIN_PASSWORD ;;
        base_url) printf NANO_BASE_URL ;;
        schema) printf NANO_SCHEMA_PROFILE ;;
        lic_mode) printf 'LICENSE_TOKEN or NANO_LICENSE_MODE' ;;
        lic_url) printf LICENSE_URL ;;
        lic_token) printf LICENSE_TOKEN ;;
        lic_id) printf NANO_DEPLOYMENT_ID ;;
        lic_file) printf NANO_LICENSE_FILE ;;
        proxy|proxy_url) printf NANO_HTTPS_PROXY ;;
        proxy_auth|proxy_user) printf NANO_PROXY_USERNAME ;;
        proxy_pass) printf NANO_PROXY_PASSWORD ;;
        no_proxy) printf NANO_NO_PROXY ;;
        ai) printf NANO_ALLOW_PRIVATE_AI_ENDPOINTS ;;
        backup) printf NANO_BACKUP_ENABLED ;;
        backup_dest) printf NANO_BACKUP_DESTINATION ;;
        backup_path) printf NANO_BACKUP_PATH ;;
        backup_s3_endpoint) printf NANO_BACKUP_S3_ENDPOINT ;;
        backup_s3_bucket) printf NANO_BACKUP_S3_BUCKET ;;
        backup_s3_region) printf NANO_BACKUP_S3_REGION ;;
        backup_s3_prefix) printf NANO_BACKUP_S3_PREFIX ;;
        backup_s3_access) printf NANO_BACKUP_S3_ACCESS_KEY ;;
        backup_s3_secret) printf NANO_BACKUP_S3_SECRET_KEY ;;
        backup_schedule) printf NANO_BACKUP_SCHEDULE ;;
        backup_keep) printf NANO_BACKUP_KEEP ;;
        volume) printf NANO_PLANNED_GB_PER_DAY ;;
        ingest_path) printf NANO_INGEST_PATH ;;
        retention) printf NANO_RETENTION_DAYS ;;
        tiering) printf NANO_TIERING ;;
        tier_provider) printf NANO_TIERING_PROVIDER ;;
        tier_azure_url) printf NANO_TIERING_AZURE_ACCOUNT_URL ;;
        tier_azure_name) printf NANO_TIERING_AZURE_ACCOUNT_NAME ;;
        tier_azure_container) printf NANO_TIERING_AZURE_CONTAINER ;;
        tier_azure_key) printf NANO_TIERING_AZURE_ACCOUNT_KEY ;;
        tier_bucket) printf NANO_TIERING_BUCKET ;;
        tier_endpoint) printf NANO_TIERING_ENDPOINT ;;
        tier_region) printf NANO_TIERING_REGION ;;
        tier_prefix) printf NANO_TIERING_PREFIX ;;
        tier_env_creds) printf NANO_TIERING_USE_ENVIRONMENT_CREDENTIALS ;;
        tier_access) printf NANO_TIERING_ACCESS_KEY_ID ;;
        tier_secret) printf NANO_TIERING_SECRET_ACCESS_KEY ;;
        tier_move) printf NANO_TIERING_MOVE_FACTOR ;;
        tier_cache) printf NANO_TIERING_CACHE_SIZE ;;
    esac
}

# Runs steps $1..$2 (indexes into ANSWER_STEPS). `back` moves to the previous
# step asked in this range; at its first step it asks that step again.
answer_run_steps() {
    local first="$1" last="$2" i="$1" j rc
    while (( i <= last )); do
        if ! answer_step_applies "${ANSWER_STEPS[i]}"; then
            i=$((i + 1))
            continue
        fi
        rc=0
        ANSWER_ENV_HINT=$(answer_step_env "${ANSWER_STEPS[i]}")
        answer_ask_step "${ANSWER_STEPS[i]}" || rc=$?
        ANSWER_ENV_HINT=""
        case "$rc" in
            0) i=$((i + 1)) ;;
            2)
                j=$((i - 1))
                while (( j >= first )) && ! answer_step_applies "${ANSWER_STEPS[j]}"; do j=$((j - 1)); done
                if (( j < first )); then
                    warn "This is the first question here; answer it (Enter keeps the value shown in brackets)."
                else
                    i=$j
                fi ;;
            3) i=$(answer_step_index "$ANSWER_JUMP") ;;
            *) fail "Internal error asking ${ANSWER_STEPS[i]}." ;;
        esac
    done
}

# One review line's value. Secrets are never shown.
answer_item_value() {
    local text
    case "$1" in
        admin_email) printf '%s' "$ANS_ADMIN_EMAIL" ;;
        admin_name) printf '%s' "$ANS_ADMIN_NAME" ;;
        admin_password)
            if [[ "${ANS_PASSWORD_GENERATED:-0}" == 1 ]]; then printf 'autogenerate (shown at the end)'; else printf 'set (hidden)'; fi ;;
        base_url) printf '%s' "$ANS_BASE_URL" ;;
        schema) printf '%s' "$ANS_SCHEMA" ;;
        license)
            if [[ "$ANS_LIC_MODE" == online ]]; then
                text="online check-in, deployment $ANS_LIC_ID, token set (hidden)"
                [[ "$ANS_LIC_URL" == "$LICENSE_DEFAULT_URL" ]] || text+=", $ANS_LIC_URL"
                printf '%s' "$text"
            elif [[ -n "${ANS_LIC_FILE:-}" ]]; then
                printf 'offline file %s' "$ANS_LIC_FILE"
            else
                printf 'offline, import the file after install'
            fi ;;
        proxy)
            if [[ "$ANS_PROXY" != true ]]; then printf 'none'; return 0; fi
            text="$ANS_PROXY_URL"
            [[ "$ANS_PROXY_AUTH" == true ]] && text+=" (user $ANS_PROXY_USER, password set (hidden))"
            [[ -n "${ANS_NO_PROXY:-}" ]] && text+=", bypass $ANS_NO_PROXY"
            printf '%s' "$text" ;;
        ai) if [[ "$ANS_AI" == true ]]; then printf 'yes (private AI provider addresses allowed)'; else printf 'no'; fi ;;
        backup)
            if [[ "$ANS_BACKUP" != true ]]; then printf 'off'; return 0; fi
            if [[ "$ANS_BACKUP_DEST" == path ]]; then text="$ANS_BACKUP_PATH"
            else text="$ANS_BACKUP_S3_ENDPOINT bucket $ANS_BACKUP_S3_BUCKET${ANS_BACKUP_S3_PREFIX:+/$ANS_BACKUP_S3_PREFIX} ($ANS_BACKUP_S3_REGION), keys set (hidden)"; fi
            printf 'daily at %s to %s, keep %s' "$ANS_BACKUP_SCHEDULE" "$text" "$ANS_BACKUP_KEEP" ;;
        volume)
            if [[ -z "${ANS_VOLUME:-}" || "$ANS_VOLUME" == 0 ]]; then printf 'not declared (sized from this host)'; return 0; fi
            text="$ANS_VOLUME GB/day"
            answer_step_applies ingest_path && text+=", ${ANS_INGEST_PATH} ingest"
            printf '%s' "$text" ;;
        retention) printf '%s days' "$ANS_RETENTION" ;;
        tiering)
            if [[ "$ANS_TIERING" != true ]]; then printf 'off'; return 0; fi
            if [[ "$ANS_TIER_PROVIDER" == azure ]]; then
                text="azure $ANS_TIER_AZURE_URL container $ANS_TIER_AZURE_CONTAINER, key set (hidden)"
            else
                text="$ANS_TIER_PROVIDER bucket $ANS_TIER_BUCKET/$ANS_TIER_PREFIX"
                [[ "$ANS_TIER_PROVIDER" == s3-compatible ]] && text+=" at $ANS_TIER_ENDPOINT"
                [[ -n "${ANS_TIER_REGION:-}" ]] && answer_step_applies tier_region && text+=" ($ANS_TIER_REGION)"
                if [[ "${ANS_TIER_ENV_CREDS:-false}" == true ]]; then text+=", instance credentials"; else text+=", keys set (hidden)"; fi
            fi
            printf '%s, move below %s free, cache %s' "$text" "$ANS_TIER_MOVE" "$ANS_TIER_CACHE" ;;
    esac
}

answer_review() {
    local entry item first last label n choice
    local -a review_items=()
    while :; do
        printf '\nReview your answers\n' > /dev/tty
        review_items=()
        for entry in "${ANSWER_ITEMS[@]}"; do
            read -r item first last label <<< "$entry"
            answer_wanted "$item" || continue
            review_items+=("$entry")
            printf '  %2d  %-22s %s\n' "${#review_items[@]}" "$label" "$(answer_item_value "$item")" > /dev/tty
        done
        printf '\n' > /dev/tty
        ANSWER_ENV_HINT=""
        if ! answer_read "Enter to install, a number to change that answer, or q to quit (nothing written yet)"; then
            # `back` here is not a confirmation: show the review again.
            warn "Type the number of the answer to change, or press Enter to install."
            continue
        fi
        choice=$(trim_space "$ANSWER_REPLY")
        case "$choice" in
            "") return 0 ;;
            q|Q|quit)
                printf '%s\n' "Stopped at the review: nothing was written and nothing was started." > /dev/tty
                exit 0 ;;
        esac
        if [[ "$choice" =~ ^[0-9]+$ ]] && (( 10#$choice >= 1 && 10#$choice <= ${#review_items[@]} )); then
            n=$(( 10#$choice - 1 ))
            read -r item first last label <<< "${review_items[n]}"
            answer_run_steps "$(answer_step_index "$first")" "$(answer_step_index "$last")"
        else
            warn "Press Enter to install, type a number from 1 to ${#review_items[@]}, or q to quit."
        fi
    done
}

# Decides which questions this run asks (the same conditions the configure_*
# functions use), asks them, and shows the review screen. $1 = 1 on a first
# install (no .env yet).
# shellcheck disable=SC2034  # WANT_* are read through answer_wanted.
collect_answers() {
    local first_install="$1" recorded_mode wanted=0 name
    if ! have_controlling_tty; then
        unattended_inputs_check "$first_install" "$NANO_EDITION"
        return 0
    fi
    WANT_admin_email=0 WANT_admin_name=0 WANT_admin_password=0 WANT_base_url=0 WANT_schema=0
    WANT_license=0 WANT_proxy=0 WANT_ai=0 WANT_backup=0 WANT_volume=0 WANT_ingest_path=0
    WANT_retention=0 WANT_tiering=0
    ANSWER_BASE_URL_DEFAULT="http://localhost" ANSWER_LICENSE_DEFAULT=online
    if [[ "$first_install" == 1 ]]; then
        [[ -n "${NANO_ADMIN_EMAIL:-}" ]] || WANT_admin_email=1
        [[ -n "${NANO_ADMIN_NAME:-}" ]] || WANT_admin_name=1
        [[ -n "${NANO_ADMIN_PASSWORD:-}" || "${NANO_PREPARE_ONLY:-0}" == "1" ]] || WANT_admin_password=1
        [[ -n "${NANO_BASE_URL:-}" ]] || WANT_base_url=1
        [[ -n "${NANO_SCHEMA_PROFILE:-}" ]] || WANT_schema=1
    elif [[ -z "${NANO_BASE_URL:-}" ]] && base_url_needs_reask; then
        # A reused .env holding a BASE_URL that is not a URL (v2.0.28 "N"):
        # no default unless it is a bare host, offered back as https://.
        WANT_base_url=1
        ANSWER_BASE_URL_DEFAULT=$(base_url_reask_default)
        warn "This install's .env has BASE_URL='$(env_value BASE_URL)', which is not a URL users can open nano at."
    fi
    if license_question_applies "$first_install"; then
        WANT_license=1
        recorded_mode=$(env_value NANO_LICENSE_MODE)
        [[ "$first_install" == "0" && -z "$recorded_mode" ]] && ANSWER_LICENSE_DEFAULT=offline
    fi
    [[ -z "$(env_value HTTPS_PROXY)" && -z "$(env_value NANO_OUTBOUND_PROXY_ASKED)" && -z "${NANO_HTTPS_PROXY:-}" ]] \
        && WANT_proxy=1
    [[ -z "$(env_value NANOSIEM_ALLOW_PRIVATE_AI_ENDPOINTS)" && -z "${NANO_ALLOW_PRIVATE_AI_ENDPOINTS:-}" ]] && WANT_ai=1
    if [[ "${MULTI_NODE:-0}" != "1" && "$(env_value NANO_BACKUP_ASKED)" != "true" && -z "${NANO_BACKUP_ENABLED+set}" \
        && -f scripts/nano-backup-scheduler.py ]] && command -v python3 >/dev/null 2>&1; then
        WANT_backup=1
    fi
    if planned_volume_question_applies; then
        WANT_volume=1
        [[ -z "${NANO_INGEST_PATH:-}" && -z "$(env_value NANO_INGEST_PATH)" ]] && WANT_ingest_path=1
    fi
    retention_question_applies && WANT_retention=1
    tiering_question_applies && WANT_tiering=1
    for name in admin_email admin_name admin_password base_url schema license proxy ai backup volume retention tiering; do
        answer_wanted "$name" && wanted=1
    done
    [[ "$wanted" == 1 ]] || return 0
    # Ctrl-C before the review is confirmed: nothing has been written yet.
    trap 'printf "\n" >/dev/tty; warn "Interrupted before the answers were confirmed: nothing was written and nothing was started."; exit 130' INT
    printf '\n%s\n%s\n\n' "Answer each question; Enter takes the [default]. Type back to fix the previous answer." \
        "Nothing is written until you confirm the review at the end; Ctrl-C leaves this host untouched." > /dev/tty
    answer_run_steps 0 $(( ${#ANSWER_STEPS[@]} - 1 ))
    answer_review
    trap - INT
}

# Whether the license is asked (resolve_license's "nothing known" branch).
license_question_applies() {
    local first_install="$1" recorded_mode recorded_token recorded_id
    [[ "$NANO_EDITION" == enterprise ]] || return 1
    [[ "${MULTI_NODE:-0}" == "1" && ",${ROLE_ARG:-}," != *,app,* ]] && return 1
    [[ -z "$LICENSE_TOKEN_INPUT" && -z "$LICENSE_FILE_INPUT" && "$LICENSE_MODE_INPUT" != offline ]] || return 1
    is_truthy "${AIRGAP_MODE:-}" && return 1
    is_truthy "$(env_value AIRGAP_MODE)" && return 1
    recorded_mode=$(env_value NANO_LICENSE_MODE)
    recorded_token=$(env_value LICENSE_TOKEN)
    [[ -n "$recorded_token" ]] || recorded_token=$(env_value DEPLOYMENT_TOKEN)
    recorded_id=$(env_value NANO_DEPLOYMENT_ID)
    [[ -n "$recorded_token" && -n "$recorded_id" ]] && return 1
    [[ "$recorded_mode" == offline || "$recorded_mode" == airgap ]] && return 1
    [[ "$first_install" == 1 ]] || return 0
    return 0
}

# Planned volume and retention are asked when neither the environment nor
# .env gives them, on a single host that has never started nano (a fresh
# install, or a re-run after a Ctrl-C or a refused destination).
volume_questions_open() {
    [[ "${MULTI_NODE:-0}" != "1" ]] || return 1
    [[ "${REUSE_ENV:-0}" != "1" && ! -f .env ]] && return 0
    install_never_ran
}
planned_volume_question_applies() {
    [[ -z "${NANO_PLANNED_GB_PER_DAY:-}" && -z "$(env_value NANO_PLANNED_GB_PER_DAY)" ]] && volume_questions_open
}
retention_question_applies() {
    [[ -z "${NANO_RETENTION_DAYS:-}" && -z "$(env_value NANO_RETENTION_DAYS)" ]] && volume_questions_open
}
tiering_question_applies() {
    local key
    [[ "${MULTI_NODE:-0}" != "1" && "$NANO_EDITION" == enterprise ]] || return 1
    [[ -f scripts/nano-tiering.py && -f scripts/lib/clickhouse_tiering.py ]] || return 1
    command -v python3 >/dev/null 2>&1 || return 1
    [[ -z "$(env_value NANO_TIERING)" ]] || return 1
    for key in NANO_TIERING NANO_TIERING_PROVIDER NANO_TIERING_BUCKET NANO_TIERING_REGION NANO_TIERING_ENDPOINT \
        NANO_TIERING_PREFIX NANO_TIERING_MOVE_FACTOR NANO_TIERING_CACHE_SIZE NANO_TIERING_USE_ENVIRONMENT_CREDENTIALS \
        NANO_TIERING_AZURE_ACCOUNT_URL NANO_TIERING_AZURE_CONTAINER NANO_TIERING_AZURE_ACCOUNT_NAME \
        NANO_TIERING_ACCESS_KEY_ID NANO_TIERING_SECRET_ACCESS_KEY NANO_TIERING_AZURE_ACCOUNT_KEY; do
        [[ -z "$(trim_space "${!key:-}")" ]] || return 1
    done
    return 0
}

# A reused .env whose BASE_URL is not a URL users can open, on a host that
# owns .env (single node or the app role).
base_url_needs_reask() {
    local recorded
    recorded=$(env_value BASE_URL)
    [[ -n "$recorded" ]] || return 1
    normalize_base_url "$recorded" >/dev/null && return 1
    [[ "${MULTI_NODE:-0}" != "1" || ",${ROLE_ARG:-}," == *,app,* ]]
}
base_url_reask_default() {
    local recorded
    recorded=$(trim_space "$(env_value BASE_URL)")
    if [[ "$recorded" != *://* && ( "$recorded" == *.* || "$recorded" == \[* ) ]] \
        && normalize_base_url "https://$recorded" >/dev/null; then
        normalize_base_url "https://$recorded"
    fi
    return 0
}

# Unattended runs (non-interactive mode, or no controlling terminal): every
# question takes its environment variable or its default, except the values
# below, which have no safe default. All of them are named in one message,
# before anything is written: collect_answers calls this at the point an
# interactive run asks its questions (after the host, port and certificate
# checks, before .env, a secret or a container). $1 = 1 on a first install
# (no .env), $2 = the edition. Prints "VARIABLE<TAB>what it is" lines.
unattended_missing_inputs() {
    local first_install="$1" edition="${2:-}"
    # A role-split host without the app role never creates the admin or .env.
    [[ -z "${ROLE_ARG:-}" || ",${ROLE_ARG}," == *,app,* ]] || return 0
    if [[ "$first_install" == 1 ]]; then
        valid_admin_email "$(trim_space "${NANO_ADMIN_EMAIL:-}")" \
            || printf '%s\t%s\n' NANO_ADMIN_EMAIL "the first admin's email address (name@domain)$( [[ -z "${NANO_ADMIN_EMAIL:-}" ]] || printf '; the value given is not one')"
        [[ -n "${NANO_ADMIN_PASSWORD:-}" || "${NANO_PREPARE_ONLY:-0}" == 1 ]] \
            || printf '%s\t%s\n' NANO_ADMIN_PASSWORD "the first admin's password: 12+ bytes with upper and lower case, a digit and a special character"
        [[ -n "${NANO_BASE_URL:-}" ]] \
            || printf '%s\t%s\n' NANO_BASE_URL "the URL users open nano at, as http(s)://host[:port] (for example https://nano.example.com)"
    fi
    unattended_feature_inputs "$edition"
    # Enterprise license (resolve_license fails closed without one).
    [[ "$edition" == enterprise && "${NANO_PREPARE_ONLY:-0}" != 1 ]] || return 0
    [[ -z "$LICENSE_TOKEN_INPUT" && -z "$LICENSE_FILE_INPUT" && "$LICENSE_MODE_INPUT" != offline ]] || return 0
    ! is_truthy "${AIRGAP_MODE:-}" || return 0
    if [[ "$first_install" != 1 ]]; then
        # A re-run fails only when .env records a mode without its values
        # (pending); a pre-2.0.5 install without one keeps its offline license.
        license_question_applies 0 || return 0
        [[ -n "$(env_value NANO_LICENSE_MODE)" ]] || return 0
    fi
    printf '%s\t%s\n' "LICENSE_TOKEN + NANO_DEPLOYMENT_ID" \
        "the license values from the deployment page in app.nano.rs (LICENSE_URL defaults to $LICENSE_DEFAULT_URL); or NANO_LICENSE_MODE=offline (import the file after install) or AIRGAP_MODE=true"
}

# Automatic backups and storage tiering asked for in the environment: the
# values they need, checked here so a gap stops the run before .env exists
# (configure_automatic_backups / configure_storage_tiering run after it).
# Same conditions as those functions; tiering uses nano-tiering.py's own
# check (nothing written, secrets through the environment).
unattended_feature_inputs() {
    local edition="$1" kind out
    if [[ -z "${ROLE_ARG:-}" && "$(normalize_bool "${NANO_BACKUP_ENABLED:-}")" == true \
        && "$(env_value NANO_BACKUP_ASKED)" != true && -f scripts/nano-backup-scheduler.py ]]; then
        kind=$(trim_space "${NANO_BACKUP_DESTINATION:-}")
        case "$kind" in
            path)
                [[ "$(trim_space "${NANO_BACKUP_PATH:-}")" == /* ]] \
                    || printf '%s\t%s\n' NANO_BACKUP_PATH "the absolute backup directory (NANO_BACKUP_DESTINATION=path)" ;;
            s3)
                local var
                for var in NANO_BACKUP_S3_ENDPOINT NANO_BACKUP_S3_BUCKET NANO_BACKUP_S3_ACCESS_KEY NANO_BACKUP_S3_SECRET_KEY; do
                    [[ -n "$(trim_space "${!var:-}")" ]] \
                        || printf '%s\t%s\n' "$var" "needed for NANO_BACKUP_DESTINATION=s3"
                done ;;
            *) printf '%s\t%s\n' NANO_BACKUP_DESTINATION "path or s3 (NANO_BACKUP_ENABLED=true)" ;;
        esac
    fi
    [[ -z "${ROLE_ARG:-}" ]] || return 0
    case "$(printf '%s' "${NANO_TIERING:-}" | tr '[:upper:]' '[:lower:]')" in
        on|true|yes|1) ;;
        *) [[ -n "${NANO_TIERING_PROVIDER:-}" && -z "${NANO_TIERING:-}" ]] || return 0 ;;
    esac
    if [[ "$edition" != enterprise || ! -f scripts/nano-tiering.py || ! -f scripts/lib/clickhouse_tiering.py ]]; then
        printf '%s\t%s\n' NANO_TIERING "storage tiering is an enterprise feature: remove NANO_TIERING / --tiering"
        return 0
    fi
    command -v python3 >/dev/null 2>&1 || return 0
    if ! out=$(python3 -I scripts/nano-tiering.py --install-dir "$PWD" configure --from-installer --check </dev/null 2>&1); then
        out=$(printf '%s' "$out" | tr '\n' ' ')
        printf '%s\t%s\n' "NANO_TIERING_*" "$(trim_space "${out#nano }")"
    fi
}

# Stops with every missing value in one message. $1 = unattended_missing_inputs
# lines, $2 = what the run has (not) done so far.
fail_missing_inputs() {
    local var what
    {
        printf '%b✗ Missing or invalid values (%s). Set each one below and re-run. %s%b\n' \
            "$c_red$c_bold" "$(noninteractive_reason)" "$2" "$c_reset"
        while IFS=$'\t' read -r var what; do
            [[ -n "$var" ]] && printf '    %-36s %s\n' "$var" "$what"
        done <<< "$1"
        printf '%s\n' "  Every other question takes its environment variable or its default: see install.sh --help and docs/getting-started/non-interactive-install.md."
    } >&2
    exit 1
}

unattended_inputs_check() {
    local missing
    missing=$(unattended_missing_inputs "$@")
    [[ -z "$missing" ]] || fail_missing_inputs "$missing" "Nothing was changed."
}
# <<< interactive answers (NAN-5508) <<<
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
        warn "Enrichment requires 6 GB for ClickHouse; CLICKHOUSE_MEM_LIMIT is $v and the enrichment feeds (IPinfo, Tor, ThreatFox) are on. Raise it to CLICKHOUSE_MEM_LIMIT=6G in .env, or disable the feeds with PLATFORM_FEEDS_AUTO_UPDATE=false, then re-run install.sh (it reassembles ClickHouse's configuration before starting it). Without the memory, events get no geo/ASN (ingest keeps working)."
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
        | grep -F "${2}@" | awk 'NR == 1')
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
    r=$(sed -n 's/^# Release: v\{0,1\}//p' "$1" 2>/dev/null | awk 'NR == 1')
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

# NAN-5509: the package manager command for this host, inferred from
# /etc/os-release (ID and ID_LIKE), so a missing tool's message names the exact
# install line. Prints nothing when the family is unknown.
os_release_path=/etc/os-release os_kernel=$(uname -s)
if [[ -n "${NANO_INSTALLER_TEST_OS_RELEASE:-}" && "${NANO_INSTALLER_TEST_MODE:-0}" == "1" ]]; then
    os_release_path="$NANO_INSTALLER_TEST_OS_RELEASE" os_kernel=Linux
fi
os_family=""
if [[ "$os_kernel" == Darwin ]]; then
    os_family=macos
elif [[ -r "$os_release_path" ]]; then
    os_ids=$(awk -F= '$1 == "ID" || $1 == "ID_LIKE" { gsub(/"/, "", $2); printf "%s ", $2 }' "$os_release_path")
    case " $os_ids " in
        *" debian "* | *" ubuntu "*) os_family=apt ;;
        *" fedora "* | *" rhel "* | *" centos "* | *" rocky "* | *" almalinux "* | *" amzn "* | *" ol "*) os_family=dnf ;;
        *" suse "* | *" opensuse "* | *" sles "*) os_family=zypper ;;
        *" alpine "*) os_family=apk ;;
        *" arch "*) os_family=pacman ;;
    esac
fi
# install_hint <package>: "Install it: sudo apt-get install -y <package>."
install_hint() {
    case "$os_family" in
        apt) printf 'Install it: sudo apt-get update && sudo apt-get install -y %s' "$1" ;;
        dnf) printf 'Install it: sudo dnf install -y %s' "$1" ;;
        zypper) printf 'Install it: sudo zypper install -y %s' "$1" ;;
        apk) printf 'Install it: sudo apk add %s' "$1" ;;
        pacman) printf 'Install it: sudo pacman -S --needed %s' "$1" ;;
        macos) printf 'Install it: brew install %s' "$1" ;;
        *) printf 'Install the %s package with your package manager' "$1" ;;
    esac
    printf ', then re-run.'
}

require_cmd docker   "Install Docker Engine: https://docs.docker.com/engine/install/ (then add your user to the docker group: sudo usermod -aG docker \$USER, log out and back in)."
# git only fetches a get.nano.rs checkout (or clones a new one); an extracted
# release bundle never uses it.
if [[ ! -e "$NANO_INSTALL_DIR" || -e "$NANO_INSTALL_DIR/.git" ]] \
    && [[ ! -f "$NANO_INSTALL_DIR/.nano-bundle" ]]; then
    require_cmd git  "$(install_hint git)"
fi
require_cmd openssl  "$(install_hint openssl)"
require_cmd curl     "$(install_hint curl)"
# Every install renders ClickHouse's config with python3 (network allow-list,
# config directories); without it the install failed after every prompt.
require_cmd python3  "$(install_hint python3) (nano's installer needs Python 3.9 or later; node is not a substitute)."

compose_plugin_hint() {
    case "$os_family" in
        apt | dnf) printf 'Install the compose plugin from Docker'"'"'s repository: sudo %s install -y docker-compose-plugin (see https://docs.docker.com/compose/install/linux/).' \
            "$([[ "$os_family" == apt ]] && printf apt-get || printf dnf)" ;;
        *) printf 'Update Docker or install the compose plugin: https://docs.docker.com/compose/install/linux/' ;;
    esac
}
if ! docker compose version </dev/null >/dev/null 2>&1; then
    fail "docker compose v2 is required (the 'docker compose' plugin, not the old docker-compose). $(compose_plugin_hint)"
fi

# Docker Compose 2.24.4 or later: role-split renders and the NAN-5408 metrics
# overlay use `!reset`/`!override`, which older Compose rejects or misreads.
compose_version=""
compose_at_least_2_24_4() {
    local major minor patch
    compose_version=$(docker compose version --short </dev/null 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | awk 'NR == 1')
    IFS=. read -r major minor patch <<< "$compose_version"
    [[ "$major" =~ ^[0-9]+$ ]] || major=0
    [[ "$minor" =~ ^[0-9]+$ ]] || minor=0
    [[ "$patch" =~ ^[0-9]+$ ]] || patch=0
    ! (( major < 2 || (major == 2 && minor < 24) || (major == 2 && minor == 24 && patch < 4) ))
}

if [[ -n "$INVENTORY_ARG" ]]; then
    require_cmd python3 "Install Python 3 (used only to validate and render the sovereign host inventory)."
    compose_at_least_2_24_4 || fail "Role-split installs require Docker Compose 2.24.4+ (found $compose_version). $(compose_plugin_hint)"
    [[ -f "$INVENTORY_ARG" ]] || fail "Inventory not found: $INVENTORY_ARG"
    INVENTORY_PATH="$(cd "$(dirname "$INVENTORY_ARG")" && pwd -P)/$(basename "$INVENTORY_ARG")"
elif ! compose_at_least_2_24_4; then
    # Single node: the metrics overlay (NANO_METRICS_BIND_ADDRESS) uses
    # `!reset`, which older Compose rejects; the base stack still starts.
    warn "Docker Compose ${compose_version:-unknown} is older than 2.24.4, which nano is tested with (publishing metrics with NANO_METRICS_BIND_ADDRESS needs it). $(compose_plugin_hint)"
fi

# NAN-5509: a user outside the docker group used to see only "can't talk to
# it", ran `sudo ./install.sh`, and left a root-owned install behind.
if [[ "$(id -u)" == 0 && -n "${SUDO_USER:-}" && "${SUDO_USER}" != root ]]; then
    warn "Running as root through sudo. Every later install.sh and scripts/nano run must then use sudo too, and the files it writes belong to root. Prefer: sudo usermod -aG docker $SUDO_USER, log out and back in (or run: newgrp docker), then run install.sh without sudo."
fi
if [[ "${NANO_PREPARE_ONLY:-0}" != "1" && "${NANO_CHECK_ONLY:-0}" != "1" ]] \
    && ! docker_info_err=$(docker info </dev/null 2>&1 >/dev/null); then
    case "$docker_info_err" in
        *"permission denied"* | *"Permission denied"*)
            fail "Your user ($(id -un)) cannot use Docker: permission denied on the Docker socket. Add it to the docker group: sudo usermod -aG docker \$USER, then log out and back in (or run: newgrp docker) and re-run install.sh. Do not run install.sh with sudo: the install would belong to root, and every later run and upgrade would need sudo too." ;;
        *"Cannot connect to the Docker daemon"* | *"Is the docker daemon running"* | *"connect: no such file"*)
            fail "The Docker daemon is not running. Start it (sudo systemctl enable --now docker; on Docker Desktop, open the app) and re-run." ;;
        *)
            fail "Docker is not usable by this user: $(printf '%s' "$docker_info_err" | tr '\n' ' ' | cut -c1-300) Start Docker, or fix the error above, and re-run." ;;
    esac
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
        | grep -E '^(COMPOSE_PROFILES=(.*,)?(lake|lean)(,|$)|NANO_LOG_QUERY_BACKEND=lake|NANO_ENABLE_LAKE_CONTROL_PLANE=(1|true)|NANO_LAKE_[A-Z_]+=)' >/dev/null; then
        fail "The install at $NANO_INSTALL_DIR runs the 1.x object-lake edition, which cannot be upgraded in place to this release. Install into a new directory (NANO_INSTALL_DIR=\$HOME/nano-v2) and move sources there."
    fi
fi

# NAN-5509: an install directory left behind by an earlier `sudo ./install.sh`
# failed later as "Could not fetch the current release ... Check the network"
# (git refuses a checkout owned by another user) or as a write error.
if [[ -d "$NANO_INSTALL_DIR" && "$(id -u)" != 0 ]]; then
    install_dir_owner=""
    # git refuses a checkout another user owns; anything else only needs to be
    # writable (a shared, group-writable directory is fine).
    if [[ -e "$NANO_INSTALL_DIR/.git" ]]; then
        # BSD stat first; GNU `stat -f` means file-system status and fails here.
        install_dir_owner=$(stat -f '%u' "$NANO_INSTALL_DIR/.git" 2>/dev/null) \
            || install_dir_owner=$(stat -c '%u' "$NANO_INSTALL_DIR/.git" 2>/dev/null) \
            || install_dir_owner=""
        [[ "$install_dir_owner" != "$(id -u)" ]] || install_dir_owner=""
    fi
    if [[ -n "$install_dir_owner" || ! -w "$NANO_INSTALL_DIR" ]]; then
        fail "$NANO_INSTALL_DIR ${install_dir_owner:+is owned by uid $install_dir_owner}${install_dir_owner:-is not writable}, not by you ($(id -un)); an earlier run probably used sudo. Take it back: sudo chown -R $(id -un): $NANO_INSTALL_DIR, then re-run install.sh without sudo."
    fi
fi

# ----------------------------------------------------------------------------
# NAN-5559: a legacy 0.1.x install moves to 2.x only on purpose
# ----------------------------------------------------------------------------
# A 0.1.x open install from that era's `curl get.nano.rs | bash` is a git
# checkout whose .env pins NANO_VERSION=latest. Re-running this installer there
# upgrades it to 2.x, which changes the OCSF data layout (migration 180 moves
# the 1.8 table aside as ocsf_logs_legacy_v179; history is not searchable until
# `scripts/nano ocsf-backfill` copies it). "latest" is not a release, so the
# release-to-release confirmation (confirm_upgrade) never fires for it. This
# guard detects such an install BEFORE the checkout is fetched or anything is
# written, says what the upgrade does, and proceeds only on an explicit yes:
# typed on a terminal, or NANO_CONFIRM_LEGACY_UPGRADE=1 for an unattended run.
# It offers (terminal) or takes (unattended) a PostgreSQL dump plus a copy of
# .env, outside the install directory, first.
#
# NAN-5564: Vector can acknowledge events and still lose them while the
# upgrade restarts the stack, so senders must stop until it is done. This one
# constant is the only place that says so: the NAN-5564 fix empties it. When it
# does, also change "2. Pause ingest" under "Legacy open 0.1.x (OCSF 1.8) to
# v2" in docs/administration/upgrades.md, which tells operators the same.
LEGACY_SENDER_STOP_NOTICE="Stop your log senders (or block the ingest ports in your firewall) now, and keep them stopped until this upgrade has finished and the API reports healthy. Events sent while the stack restarts can be acknowledged and still lost."
LEGACY_UPGRADE=0
LEGACY_FROM=""
LEGACY_BACKUP_DIR=""
# Written once the upgrade is confirmed, removed after the closing summary: a
# re-run after a failed upgrade (by then .env may already record 2.x, so the
# guard stays quiet) still ends with the backfill / drop steps.
LEGACY_MARKER="$NANO_INSTALL_DIR/.nano-legacy-upgrade"
LEGACY_SUMMARY=0
# Vector-to-Vector (:6000) senders of the 0.1.x install (legacy_vector_native_probe),
# and the sender names their client certificate bundles are issued for.
LEGACY_VN_USED=0
LEGACY_VN_EVENTS=""
LEGACY_VN_PEERS=""
LEGACY_VN_SENDERS=""

# One value of a dotenv file (KEY=value; quotes and CR stripped, last wins).
legacy_env_value() {
    [[ -f "$1" ]] || return 0
    awk -v k="$2" '
        index($0, k "=") == 1 {
            v = substr($0, length(k) + 2)
            gsub(/[\r"'"'"']/, "", v)
        }
        END { print v }
    ' "$1"
}

# The "# Release:" of a lock file, without the v ("" when absent).
legacy_lock_release() {
    [[ -f "$1" ]] || return 0
    sed -n 's/^# Release: v\{0,1\}//p' "$1" | awk 'NR == 1 { print $1 }'
}

# The tag of a container's image ("" when there is no such container, it is
# pinned by digest, or docker cannot tell).
legacy_container_tag() {
    local image
    command -v docker >/dev/null 2>&1 || return 0
    image=$(docker inspect --format '{{.Config.Image}}' "$1" </dev/null 2>/dev/null) || return 0
    image=${image%%@*}
    image=${image##*/}
    [[ "$image" == *:* ]] && printf '%s\n' "${image##*:}"
    return 0
}

# NAN-5559: does the running 0.1.x Vector take Vector-to-Vector traffic on
# :6000? 0.1.x listened there in plaintext; 2.x requires mutual TLS, so every
# such sender needs a client certificate at the cutover. Read only and best
# effort, before anything changes, with nothing beyond bash and cat in the
# Vector image:
#   * the vector_native source's received-events counter, from Vector's
#     Prometheus exporter (config/vector/92-metrics.toml, :9598 inside the
#     container, not published), cumulative since Vector started;
#   * the peers connected to :6000 right now (/proc/net/tcp* of the
#     container's network namespace). A Docker gateway address there is a
#     sender relayed by docker-proxy.
# Sets LEGACY_VN_EVENTS, LEGACY_VN_PEERS (comma separated), LEGACY_VN_USED.
legacy_vector_native_probe() {
    local port=9598 metrics_port metrics tcp
    local -a limit=()
    command -v docker >/dev/null 2>&1 || return 0
    # A wedged daemon must not hang the guard (the exec itself has no deadline).
    ! command -v timeout >/dev/null 2>&1 || limit=(timeout 45)
    [[ "$(docker inspect --format '{{.State.Running}}' nano-vector </dev/null 2>/dev/null)" == true ]] || return 0
    if [[ -f "$NANO_INSTALL_DIR/config/vector/92-metrics.toml" ]]; then
        metrics_port=$(awk '
            function flush() { if (prom && addr != "") { print addr; done = 1; exit } }
            /^[[:space:]]*\[/ { flush(); prom = 0; addr = "" }
            /^[[:space:]]*type[[:space:]]*=[[:space:]]*"prometheus_exporter"/ { prom = 1 }
            /^[[:space:]]*address[[:space:]]*=/ { if (match($0, /:[0-9]+"/)) addr = substr($0, RSTART + 1, RLENGTH - 2) }
            END { if (!done) flush() }
        ' "$NANO_INSTALL_DIR/config/vector/92-metrics.toml" 2>/dev/null) || metrics_port=""
        [[ ! "$metrics_port" =~ ^[0-9]+$ ]] || port=$metrics_port
    fi
    # shellcheck disable=SC2016 # expanded inside the container
    metrics=$(${limit[@]+"${limit[@]}"} docker exec nano-vector bash -c 'exec 3<>"/dev/tcp/127.0.0.1/$1" || exit 1
        printf "GET /metrics HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n" >&3
        if command -v timeout >/dev/null 2>&1; then timeout 20 cat <&3; else cat <&3; fi' _ "$port" \
        </dev/null 2>/dev/null) || metrics=""
    LEGACY_VN_EVENTS=$(printf '%s\n' "$metrics" | awk '
        /^#/ { next }
        /component_received_events_total\{/ && /component_kind="source"/ && (/component_id="vector_native"/ || /component_type="vector"/) {
            v = $0; sub(/^.*\}[[:space:]]*/, "", v); split(v, a, /[[:space:]]+/); sum += a[1]; n++
        }
        END { if (n) printf "%.0f\n", sum }')
    tcp=$(${limit[@]+"${limit[@]}"} docker exec nano-vector sh -c 'cat /proc/net/tcp /proc/net/tcp6 2>/dev/null; true' </dev/null 2>/dev/null) || tcp=""
    LEGACY_VN_PEERS=$(printf '%s\n' "$tcp" | awk -v want=6000 '
        function hex(s,   i, n) {
            n = 0; s = toupper(s)
            for (i = 1; i <= length(s); i++) n = n * 16 + index("0123456789ABCDEF", substr(s, i, 1)) - 1
            return n
        }
        function v4(h) { return hex(substr(h, 7, 2)) "." hex(substr(h, 5, 2)) "." hex(substr(h, 3, 2)) "." hex(substr(h, 1, 2)) }
        function v6(h,   i, w, out) {
            out = ""
            for (i = 0; i < 4; i++) {
                w = substr(h, i * 8 + 1, 8)
                w = tolower(substr(w, 7, 2) substr(w, 5, 2) substr(w, 3, 2) substr(w, 1, 2))
                out = out (i ? ":" : "") substr(w, 1, 4) ":" substr(w, 5, 4)
            }
            return out
        }
        $1 ~ /:$/ && $4 == "01" {
            split($2, l, ":"); if (hex(l[2]) != want) next
            split($3, r, ":"); a = r[1]
            if (length(a) == 8) ip = v4(a)
            else if (toupper(substr(a, 1, 24)) == "0000000000000000FFFF0000") ip = v4(substr(a, 25, 8))
            else ip = v6(a)
            if (!(ip in seen)) { seen[ip] = 1; list = list (list == "" ? "" : ",") ip }
        }
        END { print list }')
    if [[ "${LEGACY_VN_EVENTS:-0}" =~ ^[1-9][0-9]*$ || -n "$LEGACY_VN_PEERS" ]]; then
        LEGACY_VN_USED=1
    fi
    return 0
}

# Sender names (commas or spaces) -> one comma-separated, de-duplicated list;
# fails on a name scripts/nano vector-client-cert would refuse.
legacy_vector_native_names() {
    local name out="" item
    local -a items=()
    read -r -a items <<< "${1//,/ }"
    for item in "${items[@]}"; do
        [[ "$item" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$ ]] || return 1
        for name in ${out//,/ }; do [[ "$name" != "$item" ]] || continue 2; done
        out+="${out:+,}$item"
    done
    [[ -n "$out" ]] || return 1
    printf '%s\n' "$out"
}

# The sender names for the bundles: NANO_VECTOR_NATIVE_SENDERS, else (only
# when :6000 is in use) asked on a terminal ($1 = 1). Unattended without names
# it warns with the exact commands; it never stops the upgrade.
legacy_vector_native_senders() {
    local ask="$1" reply eof list
    if [[ -n "${NANO_VECTOR_NATIVE_SENDERS:-}" ]]; then
        LEGACY_VN_SENDERS=$(legacy_vector_native_names "$NANO_VECTOR_NATIVE_SENDERS") \
            || fail "NANO_VECTOR_NATIVE_SENDERS='$NANO_VECTOR_NATIVE_SENDERS' is not a list of sender names (1-63 letters, digits, dots, underscores or hyphens each, separated by commas). Nothing was changed."
        log "Vector-to-Vector senders to issue client certificate bundles for: $LEGACY_VN_SENDERS"
        return 0
    fi
    # Bundles staged on this 0.1.x host before the window (vector-native-pki.sh
    # bundle --ensure): their senders are the list, nothing to ask.
    list=""
    if [[ -s "$NANO_INSTALL_DIR/.nano-pki/vector-native/clients.tsv" ]]; then
        while IFS= read -r reply; do
            if [[ -n "$reply" && -s "$NANO_INSTALL_DIR/vector-client-bundles/$reply/$reply.crt" ]]; then
                list+="$reply,"
            fi
        done < <(awk -F '\t' '$4 == "active" { print $1 }' "$NANO_INSTALL_DIR/.nano-pki/vector-native/clients.tsv")
    fi
    if [[ -n "$list" ]] && list=$(legacy_vector_native_names "$list"); then
        LEGACY_VN_SENDERS=$list
        log "Vector-to-Vector senders with bundles staged before the upgrade: $LEGACY_VN_SENDERS (kept as they are)"
        return 0
    fi
    [[ "$LEGACY_VN_USED" == 1 ]] || return 0
    if [[ "$ask" == 1 ]]; then
        while :; do
            reply="" eof=0
            prompt_wait_log "the names of the Vector senders on port 6000" NANO_VECTOR_NATIVE_SENDERS
            printf '%s ' "Name each upstream Vector that sends to port 6000, comma separated (for example edge-1,edge-2); each gets a client certificate bundle. Enter skips:" > /dev/tty
            tty_read_line reply || eof=1
            [[ "$eof" == 0 ]] || printf '\n' > /dev/tty
            [[ -n "${reply//[[:space:],]/}" ]] || break
            if list=$(legacy_vector_native_names "$reply"); then
                LEGACY_VN_SENDERS=$list
                return 0
            fi
            warn "Sender names are 1-63 letters, digits, dots, underscores or hyphens, separated by commas." >&2
            [[ "$eof" == 0 ]] || break
        done
    fi
    warn "!! Vector-to-Vector senders were detected on port 6000, and no sender names were given, so this run issues no client certificates. Port 6000 requires mutual TLS after this upgrade: those senders are refused until each has one. After the upgrade, per sender: cd $NANO_INSTALL_DIR && scripts/nano vector-client-cert <name> --out $NANO_INSTALL_DIR/vector-client-bundles/<name> (it prints the sink config). To issue them in this run instead, stop now and re-run with NANO_VECTOR_NATIVE_SENDERS=<name>,<name>."
}

# Why the install in $1 is a 0.1.x one: one reason per line, nothing for a
# fresh directory or a 2.x install (whose .env always records an X.Y.Z
# NANO_VERSION). Reads files and container metadata only: no database access.
legacy_install_signals() {
    local dir="$1" env="$1/.env" version release tag
    [[ -f "$env" ]] || return 0
    version=$(legacy_env_value "$env" NANO_VERSION)
    version=${version#v}
    case "$version" in
        latest) printf '%s\n' ".env has NANO_VERSION=latest (the 0.1.x installer's default)" ;;
        0.*) printf '%s\n' ".env has NANO_VERSION=$version" ;;
        *)
            # A real 1.x+ release (2.x, or the 1.x lake line refused above) is
            # never 0.1.x. Anything else (unset, a branch, a SHA, a value with a
            # trailing comment) proves nothing either way: the other signals decide.
            [[ "$version" =~ ^[1-9][0-9]*\.[0-9]+\.[0-9]+$ ]] && return 0
            ;;
    esac
    if [[ -z "$(legacy_env_value "$env" NANO_EDITION)$(legacy_env_value "$env" NANO_IMAGE_PREFIX)" ]]; then
        printf '%s\n' ".env has no NANO_EDITION and no NANO_IMAGE_PREFIX (written before 2.x)"
    fi
    release=$(legacy_lock_release "$dir/images.lock")
    [[ "$release" != 0.* ]] || printf '%s\n' "images.lock in $dir is for release $release"
    tag=$(legacy_container_tag nano-api)
    case "$tag" in
        latest | 0.*) printf '%s\n' "the running nano-api container uses image tag $tag" ;;
    esac
    return 0
}

# 0 when this run will move the install in $1 onto a 2.x tree: a git checkout
# is fetched (unless NANO_SKIP_GIT_UPDATE=1), and a tree that is already 2.x
# (an extracted bundle, or a checkout updated by hand) starts 2.x images. A
# tree still on 0.1.x that is not updated fails later, before anything runs.
legacy_upgrade_applies() {
    local dir="$1" lock
    [[ "$RECORD_PG_HA_IDENTITY_ONLY" != 1 ]] || return 1
    [[ -e "$dir/.git" && "${NANO_SKIP_GIT_UPDATE:-0}" != 1 ]] && return 0
    for lock in images.lock images.enterprise.customer.lock images.enterprise.lock; do
        is_line_release "$(legacy_lock_release "$dir/$lock")" && return 0
    done
    return 1
}

# The 0.1.x release the install runs, as precisely as the signals allow.
legacy_from_version() {
    local dir="$1" version
    version=$(legacy_lock_release "$dir/images.lock")
    [[ "$version" == 0.* ]] && { printf '%s' "$version"; return 0; }
    version=$(legacy_env_value "$dir/.env" NANO_VERSION)
    version=${version#v}
    [[ "$version" == 0.* ]] && { printf '%s' "$version"; return 0; }
    version=$(legacy_container_tag nano-api)
    [[ "$version" == 0.* ]] && { printf '%s' "$version"; return 0; }
    printf '0.1.x'
}

# The 2.x release this run installs, or a description when it is only known
# after the fetch.
legacy_target_release() {
    local dir="$1" lock release
    if [[ -n "$NANO_VERSION" ]]; then
        printf '%s' "$NANO_VERSION"
        return 0
    fi
    if [[ ! -e "$dir/.git" || "${NANO_SKIP_GIT_UPDATE:-0}" == 1 ]]; then
        for lock in images.lock images.enterprise.customer.lock images.enterprise.lock; do
            release=$(legacy_lock_release "$dir/$lock")
            is_line_release "$release" && { printf '%s' "$release"; return 0; }
        done
    fi
    printf '%s' "the current release on $NANO_BRANCH"
}

legacy_upgrade_announce() {
    local signals="$1" target="$2"
    warn "Upgrading nano 0.1.x to 2.x ($target)"
    printf '  This install runs nano %s:\n' "$LEGACY_FROM"
    printf '%s\n' "$signals" | sed 's/^/    - /'
    cat <<EOF

  What changes:
    - PostgreSQL (rules, users, cases, settings) is migrated when 2.x starts.
      Migrations can't be undone: keep a backup (this installer offers one).
    - The OCSF data layout. Events stored before the upgrade move to a legacy
      table and are NOT searchable until you copy them into the new layout.
      Once the stack is up, run (it can take a while; it resumes if stopped):
        cd $NANO_INSTALL_DIR && scripts/nano ocsf-backfill --order newest-first
      (On an install that never stored OCSF events it reports nothing to copy.)
    - Then, optionally, free the legacy table's disk. First a dry run, which
      checks that every day was copied, then the drop:
        cd $NANO_INSTALL_DIR && scripts/nano ocsf-legacy-drop
        cd $NANO_INSTALL_DIR && scripts/nano ocsf-legacy-drop --confirm
    - NANO_VERSION=latest in .env is replaced by the exact 2.x release, so a
      later re-run upgrades release by release and asks first.
EOF
    if [[ "$LEGACY_VN_USED" == 1 ]]; then
        printf '\n'
        warn "Vector-to-Vector senders use port 6000 (${LEGACY_VN_EVENTS:-0} event(s) since Vector started; connected now: ${LEGACY_VN_PEERS:-none}). After the upgrade, port 6000 requires mutual TLS: each upstream Vector needs a client certificate bundle, which this upgrade issues per sender name (NANO_VECTOR_NATIVE_SENDERS, or asked on a terminal)."
    fi
    if [[ -n "$LEGACY_SENDER_STOP_NOTICE" ]]; then
        printf '\n'
        warn "$LEGACY_SENDER_STOP_NOTICE"
    fi
    printf '\n'
}

# The manual backup, as printed for an unattended run.
legacy_backup_commands() {
    local user db
    user=$(legacy_env_value "$NANO_INSTALL_DIR/.env" POSTGRES_USER)
    db=$(legacy_env_value "$NANO_INSTALL_DIR/.env" POSTGRES_DB)
    cat <<EOF
      mkdir -m 700 ~/nano-legacy-backup
      docker exec nano-postgres pg_dump --username=${user:-nanosiem} --dbname=${db:-nanosiem} --format=custom > ~/nano-legacy-backup/postgres.dump
      cp -p $NANO_INSTALL_DIR/.env ~/nano-legacy-backup/env
EOF
}

# pg_dump (custom format) of the running 0.1.x PostgreSQL plus a copy of .env,
# into a new 0700 directory outside the install directory. Fails (before
# anything was changed) when the dump cannot be taken.
legacy_upgrade_backup() {
    local dir user db running install_real parent_real size
    dir="${NANO_LEGACY_BACKUP_DIR:-$HOME/nano-legacy-backup-$(date -u +%Y%m%dT%H%M%SZ)}"
    [[ "$dir" == /* ]] \
        || fail "NANO_LEGACY_BACKUP_DIR must be an absolute path (got '$dir'; a quoted ~ is not expanded). Nothing was changed."
    dir=${dir%/}
    user=$(legacy_env_value "$NANO_INSTALL_DIR/.env" POSTGRES_USER)
    db=$(legacy_env_value "$NANO_INSTALL_DIR/.env" POSTGRES_DB)
    user=${user:-nanosiem} db=${db:-nanosiem}
    [[ "$user" =~ ^[A-Za-z_][A-Za-z0-9_]{0,62}$ && "$db" =~ ^[A-Za-z_][A-Za-z0-9_]{0,62}$ ]] \
        || fail "POSTGRES_USER / POSTGRES_DB in $NANO_INSTALL_DIR/.env are not plain names; take the backup yourself, then re-run with NANO_LEGACY_UPGRADE_SKIP_BACKUP=1. Nothing was changed."
    running=$(docker inspect --format '{{.State.Running}}' nano-postgres </dev/null 2>/dev/null || true)
    [[ "$running" == true ]] \
        || fail "Cannot take the backup: the nano-postgres container is not running. Start the install as it is first (cd $NANO_INSTALL_DIR && docker compose -f $COMPOSE_FILE up -d postgres), then re-run; or re-run with NANO_LEGACY_UPGRADE_SKIP_BACKUP=1 to upgrade without one. Nothing was changed."
    # Outside the install directory, checked before anything is created: the
    # parent must exist, and is compared physically (symlinks resolved).
    [[ -d "${dir%/*}/" ]] \
        || fail "The parent directory of the backup directory $dir does not exist; create it or choose another with NANO_LEGACY_BACKUP_DIR. Nothing was changed."
    install_real=$(cd "$NANO_INSTALL_DIR" && pwd -P)
    parent_real=$(cd "${dir%/*}/" && pwd -P)
    if [[ "$parent_real/${dir##*/}" == "$install_real" || "$parent_real/" == "$install_real/"* ]]; then
        fail "The backup directory $dir is inside the install directory; choose another with NANO_LEGACY_BACKUP_DIR. Nothing was changed."
    fi
    # A new or empty directory only: it is made 0700, which must never hit an
    # existing directory full of other files (NANO_LEGACY_BACKUP_DIR=$HOME).
    if [[ -e "$dir" || -L "$dir" ]]; then
        [[ -d "$dir" && ! -L "$dir" && -z "$(ls -A "$dir" 2>/dev/null)" ]] \
            || fail "Backup directory $dir already exists and is not an empty directory; choose a new one with NANO_LEGACY_BACKUP_DIR. Nothing was changed."
    fi
    (umask 077 && mkdir -- "$dir" 2>/dev/null) || [[ -d "$dir" ]] \
        || fail "Could not create the backup directory $dir. Nothing was changed."
    chmod 700 "$dir" || fail "Could not make $dir private (chmod 700). Nothing was changed."
    log "Backing up PostgreSQL and .env to $dir"
    if ! (umask 077 && docker exec nano-postgres pg_dump --username="$user" --dbname="$db" --format=custom \
            </dev/null > "$dir/postgres.dump"); then
        fail "pg_dump in nano-postgres failed (above); the backup in $dir is incomplete. Nothing was changed."
    fi
    [[ -s "$dir/postgres.dump" ]] || fail "pg_dump wrote an empty dump to $dir/postgres.dump. Nothing was changed."
    (umask 077 && cp "$NANO_INSTALL_DIR/.env" "$dir/env") && chmod 600 "$dir/env" \
        || fail "Could not copy .env to $dir/env. Nothing was changed."
    size=$(wc -c < "$dir/postgres.dump" | tr -d ' ')
    LEGACY_BACKUP_DIR="$dir"
    ok "Backup written to $dir (postgres.dump: pg_dump custom format, $size bytes; env: a copy of .env, which holds secrets). Keep it until the upgrade is verified."
}

# NAN-5564 / NAN-5566: a single-node Vector from 2.0.31 or older has no ingest
# gate, so senders that post to its published ports directly (:8080, :8088,
# OTLP, :6000) cannot be closed before this upgrade stops it, and an event in
# flight then can be lost. Asked BEFORE anything is fetched, pulled or written,
# so a refusal changes nothing. Accepted: y on a terminal, or (unattended)
# NANO_CONFIRM_SENDERS_PAUSED=1, NANO_CONFIRM_UPGRADE=1 or
# NANO_CONFIRM_LEGACY_UPGRADE=1; the warning is printed either way. A Vector
# with the gate (its container carries NANO_PIPELINE_IDENTITY) is not asked about.
# BEGIN nano-senders-paused
confirm_senders_paused_if_old_vector() {
    local cid="" identity="" reply="" eof=0 workdir flag
    [[ "${NANO_SENDERS_PAUSED_CHECKED:-0}" != 1 ]] || return 0
    NANO_SENDERS_PAUSED_CHECKED=1
    # Single node only: a role-split ingest host closes its ingest-edge instead.
    [[ -z "${ROLE_ARG:-}" && -z "${INVENTORY_ARG:-}" && ! -f "$NANO_INSTALL_DIR/.nano-role.env" ]] || return 0
    workdir=$(cd "$NANO_INSTALL_DIR" 2>/dev/null && pwd -P) || workdir="$NANO_INSTALL_DIR"
    cid=$(docker ps -q --filter label=com.docker.compose.service=vector \
        --filter "label=com.docker.compose.project.working_dir=$workdir" </dev/null 2>/dev/null | awk 'NR == 1') || cid=""
    [[ -n "$cid" ]] || cid=$(docker ps -q --filter name='^/nano-vector$' </dev/null 2>/dev/null | awk 'NR == 1') || cid=""
    [[ -n "$cid" ]] || return 0
    identity=$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$cid" </dev/null 2>/dev/null \
        | awk 'sub(/^NANO_PIPELINE_IDENTITY=/, "") && !seen++') || identity=""
    [[ -z "$identity" ]] || return 0
    warn "This Vector predates the ingest gate (nano 2.0.31 or older): pause every sender that posts to its ports directly (:8080, :8088, OTLP, :6000) before this upgrade stops it, or events in flight can be lost. Senders through nginx (/ingest) are closed automatically."
    for flag in NANO_CONFIRM_SENDERS_PAUSED NANO_CONFIRM_UPGRADE NANO_CONFIRM_LEGACY_UPGRADE; do
        if [[ "${!flag:-}" == 1 ]]; then
            log "$flag=1: going on with the senders that post to Vector directly paused."
            NANO_CONFIRM_SENDERS_PAUSED=1
            export NANO_CONFIRM_SENDERS_PAUSED
            return 0
        fi
    done
    if [[ "${NANO_CHECK_ONLY:-0}" == 1 ]]; then
        log "NANO_CHECK_ONLY=1: a real run asks for this (or needs NANO_CONFIRM_SENDERS_PAUSED=1 unattended)."
        return 0
    fi
    if ! have_controlling_tty; then
        printf '%s\n' "install.sh: not upgraded, nothing was changed. Pause the senders that post to Vector's ports directly, then re-run with NANO_CONFIRM_SENDERS_PAUSED=1 (NANO_CONFIRM_UPGRADE=1 or NANO_CONFIRM_LEGACY_UPGRADE=1 confirm it too), or run install.sh from a terminal." >&2
        exit 1
    fi
    prompt_wait_log "are the senders that post to Vector directly paused?" NANO_CONFIRM_SENDERS_PAUSED=1
    printf '%s ' "Are the senders that post to Vector directly paused? Type y to go on [y/N]:" > /dev/tty
    tty_read_line reply || eof=1
    if [[ "$eof" == 1 && -z "${reply//[[:space:]]/}" ]]; then
        printf '\n' > /dev/tty
        printf '%s\n' "install.sh: no answer to the senders question; nothing was changed (exit 4)." >&2
        exit 4
    fi
    if [[ "$(normalize_bool "$reply")" != true ]]; then
        printf '%s\n' "Not upgraded: nothing was changed." > /dev/tty
        printf '%s\n' "install.sh: senders not confirmed paused; nothing was changed (exit 3). Pause them, then re-run." >&2
        exit 3
    fi
    NANO_CONFIRM_SENDERS_PAUSED=1
    export NANO_CONFIRM_SENDERS_PAUSED
}
# END nano-senders-paused

legacy_upgrade_guard() {
    local signals target reply eof backup=1 asked_tty=0
    signals=$(legacy_install_signals "$NANO_INSTALL_DIR")
    [[ -n "$signals" ]] || return 0
    legacy_upgrade_applies "$NANO_INSTALL_DIR" || return 0
    # The managed layout (/opt/nanosiem, IMAGE_TAG in .env, its own
    # docker-compose.yml) has a separate, tested bridge; never take it here.
    if [[ -n "$(legacy_env_value "$NANO_INSTALL_DIR/.env" IMAGE_TAG)" && ! -f "$NANO_INSTALL_DIR/docker-compose.opensource.yml" ]]; then
        fail "$NANO_INSTALL_DIR is a managed 0.1.x install (IMAGE_TAG in .env, no docker-compose.opensource.yml), which this installer does not upgrade. Follow \"Managed v0.1.702 bridge\" in docs/administration/upgrades.md. Nothing was changed."
    fi
    LEGACY_UPGRADE=1
    LEGACY_FROM=$(legacy_from_version "$NANO_INSTALL_DIR")
    target=$(legacy_target_release "$NANO_INSTALL_DIR")
    legacy_vector_native_probe
    legacy_upgrade_announce "$signals" "$target"
    # NANO_CHECK_ONLY=1 on a tree that is not fetched changes nothing: say it, stop there.
    if [[ "${NANO_CHECK_ONLY:-0}" == 1 && ( ! -e "$NANO_INSTALL_DIR/.git" || "${NANO_SKIP_GIT_UPDATE:-0}" == 1 ) ]]; then
        log "NANO_CHECK_ONLY=1: a real run asks before this upgrade (or needs NANO_CONFIRM_LEGACY_UPGRADE=1 unattended)."
        return 0
    fi
    [[ "${NANO_LEGACY_UPGRADE_SKIP_BACKUP:-}" == 1 ]] && backup=0
    if [[ "${NANO_CONFIRM_LEGACY_UPGRADE:-}" == 1 ]]; then
        log "NANO_CONFIRM_LEGACY_UPGRADE=1: upgrading."
    elif ! have_controlling_tty; then
        {
            printf '%s\n' "This run has no terminal to confirm the 0.1.x to 2.x upgrade on, and it never upgrades one silently. Nothing was changed."
            printf '%s\n' "To upgrade unattended, re-run with NANO_CONFIRM_LEGACY_UPGRADE=1 and either:"
            printf '%s\n' "  - let the installer take the backup (PostgreSQL dump and a copy of .env, into"
            printf '%s\n' "    ~/nano-legacy-backup-<time>, or the absolute path in NANO_LEGACY_BACKUP_DIR) before it changes anything; or"
            printf '%s\n' "  - take it yourself first, for example:"
            legacy_backup_commands
            printf '%s\n' "    and add NANO_LEGACY_UPGRADE_SKIP_BACKUP=1."
            printf '%s\n' "Or run install.sh from a terminal: it asks, and offers the backup."
        } >&2
        fail "Not upgraded: set NANO_CONFIRM_LEGACY_UPGRADE=1 to upgrade this 0.1.x install to 2.x."
    else
        asked_tty=1
        reply="" eof=0
        prompt_wait_log "upgrade this 0.1.x install to 2.x?" NANO_CONFIRM_LEGACY_UPGRADE=1
        printf '%s ' "Type y to upgrade to 2.x now (anything else stops here):" > /dev/tty
        tty_read_line reply || eof=1
        if [[ "$eof" == 1 && -z "${reply//[[:space:]]/}" ]]; then
            printf '\n' > /dev/tty
            printf '%s\n' "install.sh: no answer to the upgrade question; nothing was changed (exit 4)." >&2
            exit 4
        fi
        if [[ "$(normalize_bool "$reply")" != true ]]; then
            printf '%s\n' "Not upgraded: nothing was changed." > /dev/tty
            printf '%s\n' "install.sh: upgrade not confirmed; nothing was changed (exit 3)." >&2
            exit 3
        fi
        if [[ "$backup" == 1 ]]; then
            while :; do
                reply="" eof=0
                prompt_wait_log "back up PostgreSQL and .env before the upgrade?" "NANO_CONFIRM_LEGACY_UPGRADE=1 (backs up; NANO_LEGACY_UPGRADE_SKIP_BACKUP=1 skips it)"
                printf '%s ' "Back up PostgreSQL and .env first (to a new directory outside $NANO_INSTALL_DIR)? [Y/n]:" > /dev/tty
                tty_read_line reply || eof=1
                if [[ "$eof" == 1 && -z "${reply//[[:space:]]/}" ]]; then
                    printf '\n' > /dev/tty
                    printf '%s\n' "install.sh: no answer to the backup question; nothing was changed (exit 4)." >&2
                    exit 4
                fi
                [[ -n "${reply//[[:space:]]/}" ]] || break
                case "$(normalize_bool "$reply")" in
                    true) break ;;
                    false) backup=0; break ;;
                esac
                warn "Answer y or n (Enter backs up)." >&2
            done
        fi
    fi
    legacy_vector_native_senders "$asked_tty"
    confirm_senders_paused_if_old_vector
    if [[ "$backup" == 1 ]]; then
        legacy_upgrade_backup
    else
        warn "Upgrading without a backup."
    fi
    (umask 077 && printf 'LEGACY_FROM=%s\nLEGACY_BACKUP_DIR=%s\nLEGACY_VN_USED=%s\nLEGACY_VN_EVENTS=%s\nLEGACY_VN_PEERS=%s\nLEGACY_VN_SENDERS=%s\n' \
        "$LEGACY_FROM" "$LEGACY_BACKUP_DIR" "$LEGACY_VN_USED" "$LEGACY_VN_EVENTS" "$LEGACY_VN_PEERS" "$LEGACY_VN_SENDERS" \
        > "$LEGACY_MARKER") \
        || fail "Could not write $LEGACY_MARKER. Nothing was changed."
    # The release-to-release question (confirm_upgrade) is answered.
    UPGRADE_CONFIRMED=1
}
legacy_upgrade_guard
# A re-run after an upgrade that stopped before its summary.
if [[ "$LEGACY_UPGRADE" != 1 && -f "$LEGACY_MARKER" && ! -L "$LEGACY_MARKER" ]]; then
    LEGACY_SUMMARY=1
    LEGACY_FROM=$(legacy_env_value "$LEGACY_MARKER" LEGACY_FROM)
    LEGACY_BACKUP_DIR=$(legacy_env_value "$LEGACY_MARKER" LEGACY_BACKUP_DIR)
    LEGACY_VN_USED=$(legacy_env_value "$LEGACY_MARKER" LEGACY_VN_USED)
    [[ "$LEGACY_VN_USED" == 1 ]] || LEGACY_VN_USED=0
    LEGACY_VN_EVENTS=$(legacy_env_value "$LEGACY_MARKER" LEGACY_VN_EVENTS)
    LEGACY_VN_PEERS=$(legacy_env_value "$LEGACY_MARKER" LEGACY_VN_PEERS)
    LEGACY_VN_SENDERS=$(legacy_env_value "$LEGACY_MARKER" LEGACY_VN_SENDERS)
    # The marker is ours (0600); still, only valid names go to the PKI tool.
    [[ -z "$LEGACY_VN_SENDERS" ]] || LEGACY_VN_SENDERS=$(legacy_vector_native_names "$LEGACY_VN_SENDERS") || LEGACY_VN_SENDERS=""
    log "Finishing the upgrade from nano ${LEGACY_FROM:-0.1.x} that an earlier run started"
fi

# ----------------------------------------------------------------------------
# 2. Clone or update the repo
# ----------------------------------------------------------------------------
# NAN-5471: update a get.nano.rs git checkout to the fetched release.
#
# The nano-rs/nano mirror is force-regenerated on every sync, so its history
# diverges from any prior checkout and can never fast-forward: the update is a
# hard reset to the fetched remote HEAD (NAN-1929: an ff-only merge left a
# stale images.lock and then failed digest verification).
#
# Local state is sorted before that reset:
#   * tenzir/pipeline.tql is operator-editable (the install summary says so).
#     An edit is carried across the reset and stays live; `git diff` then
#     shows it against the new release's shipped pipeline.
#   * untracked files the release does not ship (tenzir/pipeline.tql.bak*
#     from the Tenzir guard, the secrets-helper lock, operator notes) survive
#     a reset untouched, so they never block it.
#   * any other change to a shipped file, or an untracked file the reset
#     would overwrite or delete (at a path the release ships, at a directory
#     the release ships files under, or under a path the release ships as a
#     file), fails: never install the old release and report success.
#   * an edited pipeline a previous, interrupted run saved but never put back
#     (tenzir/.pipeline.tql.local.*) is restored first, before anything else.
# With nothing to update (the fetched tree is the checked-out one), local
# changes are kept as they are.
# NAN-5508: a re-run that moves the install to another release says so before
# anything changes, and asks on a terminal (unattended runs print it and go
# on). A git checkout asks in update_git_checkout, before its reset.
confirm_upgrade() {
    # $4 = check-only-ok where NANO_CHECK_ONLY=1 changes nothing after this
    # (the tree is already fetched): the question is then only reported.
    local from="$1" to="$2" how="$3" check_only_ok="${4:-}"
    # NAN-5559: a 0.1.x install was announced and confirmed by its own guard.
    [[ "$LEGACY_UPGRADE" != 1 ]] || return 0
    [[ "$from" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && -n "$to" && "$from" != "$to" ]] || return 0
    UPGRADE_CONFIRMED=1
    warn "This upgrades nano $from → $to. Database migrations run on start and can't be undone (keep a backup: scripts/nano backup)."
    # NAN-5521: NANO_CONFIRM_UPGRADE=1 pre-answers yes (a pty-driven run).
    if [[ "${NANO_CONFIRM_UPGRADE:-}" == "1" ]]; then
        log "NANO_CONFIRM_UPGRADE=1: upgrading. $how"
        return 0
    fi
    if [[ "$check_only_ok" == check-only-ok && "${NANO_CHECK_ONLY:-0}" == 1 ]]; then
        log "NANO_CHECK_ONLY=1: a real run asks before this upgrade (or needs NANO_CONFIRM_UPGRADE=1 with --non-interactive)."
        return 0
    fi
    if ! have_controlling_tty; then
        # Explicit non-interactive mode never takes this irreversible step by
        # default (migrations can't be undone); a run with no terminal at all
        # keeps upgrading, as every unattended upgrade always has.
        if [[ "${NANO_NONINTERACTIVE:-0}" == 1 ]]; then
            fail_missing_inputs "$(printf '%s\t%s\n' NANO_CONFIRM_UPGRADE=1 \
                "confirms the upgrade from nano $from to $to (database migrations can't be undone)")" "Nothing was changed."
        fi
        log "Unattended run: upgrading. $how"
        return 0
    fi
    log "$how"
    # NAN-5529: running ./install.sh to upgrade means yes, so Enter upgrades
    # (the warning above says what that does). Declining exits non-zero
    # (NAN-5521: a run that did not upgrade must not read as success): 3 for
    # an explicit no, 4 for no answer (end of input, e.g. a closed terminal).
    local reply eof
    while :; do
        reply="" eof=0
        prompt_wait_log "upgrade to $to now?" NANO_CONFIRM_UPGRADE=1
        printf '%s ' "Upgrade to $to now? [Y/n]:" > /dev/tty
        tty_read_line reply || eof=1
        if [[ "$eof" == 1 && -z "${reply//[[:space:]]/}" ]]; then
            printf '\n' > /dev/tty
            printf '%s\n' "Not upgraded: nothing was changed." > /dev/tty
            printf '%s\n' "install.sh: no answer to the upgrade question; nothing was changed (exit 4). Answer y (or press Enter), or set NANO_CONFIRM_UPGRADE=1 to upgrade without asking." >&2
            exit 4
        fi
        [[ "$eof" == 0 ]] || printf '\n' > /dev/tty
        [[ -n "${reply//[[:space:]]/}" ]] || return 0
        case "$(normalize_bool "$reply")" in
            true) return 0 ;;
            false)
                printf '%s\n' "Not upgraded: nothing was changed." > /dev/tty
                printf '%s\n' "install.sh: upgrade declined; nothing was changed (exit 3)." >&2
                exit 3
                ;;
        esac
        warn "Answer y or n (Enter upgrades)." >&2
    done
}

restore_pipeline_and_exit() {
    cp -p "$PIPELINE_RESTORE_FROM" "$PIPELINE_RESTORE_TO" && rm -f "$PIPELINE_RESTORE_FROM"
    exit "$1"
}

update_git_checkout() {
    local dir="$1" branch="$2" tracked untracked conflicts pipeline="tenzir/pipeline.tql"
    local keep_pipeline="" pipeline_copy="" shipped_pipeline_changed=0 leftovers recorded target lock
    # A checkout without tenzir/ (find fails) has no leftovers; under pipefail
    # that must not end the run silently.
    leftovers=$({ find "$dir/tenzir" -maxdepth 1 -name '.pipeline.tql.local.*' -type f 2>/dev/null || true; } | sort)
    if [[ -n "$leftovers" ]]; then
        if [[ "$(printf '%s\n' "$leftovers" | wc -l)" -eq 1 ]] \
            && git -C "$dir" diff --quiet HEAD -- "$pipeline" </dev/null 2>/dev/null; then
            cp -p "$leftovers" "$dir/$pipeline" \
                || fail "Could not put back your edited $dir/$pipeline from $leftovers (saved by an interrupted run)."
            rm -f "$leftovers"
            warn "Restored your edited $pipeline, which an interrupted earlier run had saved in $leftovers."
        else
            printf '  %s\n' "$leftovers" >&2
            fail "An interrupted earlier run saved your edited $dir/$pipeline in the file(s) above, and $pipeline has changed since. Nothing was installed. Copy the version you want to keep to $dir/$pipeline, delete the saved file(s), then re-run."
        fi
    fi
    git -C "$dir" fetch --depth 1 origin "$branch" </dev/null \
        || fail "Could not fetch the current release into $dir (git fetch origin $branch). Check the network and re-run, or re-run with NANO_SKIP_GIT_UPDATE=1 to reinstall the checkout as it is."
    if git -C "$dir" diff --quiet HEAD FETCH_HEAD -- </dev/null 2>/dev/null; then
        log "Checkout at $dir is already the current release"
        return 0
    fi
    # NAN-5508: say (and on a terminal ask) before the reset when the fetched
    # release differs from the one this install runs.
    if [[ -f "$dir/.env" ]]; then
        recorded=$(awk 'index($0, "NANO_VERSION=") == 1 { v = substr($0, 14); gsub(/[\r"'"'"']/, "", v) } END { print v }' "$dir/.env")
        target="${NANO_VERSION:-}"
        if [[ -z "$target" ]]; then
            for lock in images.lock images.enterprise.lock; do
                target=$(git -C "$dir" show "FETCH_HEAD:$lock" </dev/null 2>/dev/null \
                    | sed -n 's/^# Release: v\{0,1\}//p' | awk 'NR == 1')
                target="${target%% *}"
                [[ -z "$target" ]] || break
            done
        fi
        confirm_upgrade "$recorded" "$target" "To restart without upgrading, re-run with NANO_SKIP_GIT_UPDATE=1 ./install.sh."
        [[ "$LEGACY_UPGRADE" != 1 ]] || log "Upgrading nano $LEGACY_FROM to ${target:-the fetched release}"
    fi
    # NAN-5566: before the reset below (whatever the recorded release), so a
    # refusal changes nothing. Idempotent: the main flow's call then returns.
    confirm_senders_paused_if_old_vector
    # Tracked changes (staged or not) against the checked-out release.
    tracked=$(git -C "$dir" diff --name-status --no-renames HEAD -- </dev/null) \
        || fail "Could not read the local changes in $dir (git diff)."
    # Untracked, non-ignored files the reset would overwrite or delete: one
    # the release ships at the same path, a file where the release ships a
    # directory (foo vs foo/bar), or one under a path the release ships as a
    # file (d/x vs d).
    untracked=$(git -C "$dir" ls-files --others --exclude-standard -z </dev/null \
        | tr '\0' '\n' | awk '
            NR == FNR {
                shipped[$0] = 1
                path = $0
                while (sub(/\/[^\/]*$/, "", path)) shipped_dir[path] = 1
                next
            }
            {
                if ($0 in shipped || $0 in shipped_dir) { print; next }
                path = $0
                while (sub(/\/[^\/]*$/, "", path)) if (path in shipped) { print; next }
            }' <(git -C "$dir" ls-tree -r --name-only FETCH_HEAD </dev/null) -) \
        || fail "Could not read the untracked files in $dir (git ls-files)."
    conflicts=$(printf '%s\n' "$tracked" \
        | awk -F'\t' -v pipeline="$pipeline" 'NF && !($1 == "M" && $2 == pipeline) { print "  " $1 " " $2 }')
    if [[ -n "$untracked" ]]; then
        conflicts+="${conflicts:+$'\n'}$(printf '%s\n' "$untracked" | sed 's/^/  untracked (the update would replace or delete it): /')"
    fi
    if [[ -n "$conflicts" ]]; then
        printf '%s\n' "$conflicts" >&2
        fail "$dir has local changes to files the current release replaces (listed above), so it cannot be updated and nothing was installed. Move each change out of the checkout (git -C $dir stash, or copy the file elsewhere and git -C $dir checkout -- <file>), then re-run. To deliberately reinstall the checkout as it is, without the update, re-run with NANO_SKIP_GIT_UPDATE=1."
    fi
    if printf '%s\n' "$tracked" | awk -F'\t' -v pipeline="$pipeline" '$1 == "M" && $2 == pipeline { found = 1 } END { exit !found }'; then
        keep_pipeline=1
        git -C "$dir" diff --quiet HEAD FETCH_HEAD -- "$pipeline" </dev/null 2>/dev/null || shipped_pipeline_changed=1
        # Same directory and mode 0600: an operator pipeline can carry sink
        # credentials. Removed only once the edit is back in place.
        pipeline_copy=$(umask 077 && mktemp "$dir/tenzir/.pipeline.tql.local.XXXXXX") \
            || fail "Could not save your edited $dir/$pipeline before the update."
        cp -p "$dir/$pipeline" "$pipeline_copy" \
            || fail "Could not save your edited $dir/$pipeline before the update."
    fi
    log "Updating existing checkout at $dir"
    if [[ -n "$keep_pipeline" ]]; then
        # Interrupted between the reset and the restore: put the edit back
        # now (the next run restores a copy left behind by a harder kill).
        PIPELINE_RESTORE_FROM="$pipeline_copy" PIPELINE_RESTORE_TO="$dir/$pipeline"
        trap 'restore_pipeline_and_exit 130' INT
        trap 'restore_pipeline_and_exit 143' TERM
    fi
    git -C "$dir" reset --hard FETCH_HEAD </dev/null \
        || fail "Could not update $dir to the current release.${pipeline_copy:+ Your edited $pipeline is saved in $pipeline_copy.} Remove the checkout and re-run to reclone."
    if [[ -n "$keep_pipeline" ]]; then
        # cp -p: the operator's mode too (a 0600 pipeline with sink credentials
        # must not come back with the shipped file's 0644).
        cp -p "$pipeline_copy" "$dir/$pipeline" \
            || fail "Could not restore your edited $dir/$pipeline after the update; it is saved in $pipeline_copy."
        rm -f "$pipeline_copy"
        trap - INT TERM
        if [[ "$shipped_pipeline_changed" == "1" ]]; then
            warn "Kept your edited $pipeline. This release ships a changed pipeline: review it with git -C $dir diff $pipeline (your edit against the new shipped version) and see \"Bundled Tenzir node\" in the Upgrade guide."
        else
            log "Kept your edited $pipeline"
        fi
    fi
}

if [[ -e "$NANO_INSTALL_DIR/.git" && "$CONVERT_EDITION_INPUT" == enterprise ]]; then
    # NAN-5558: never fetch the open repository over a conversion.
    fail "Refusing to convert $NANO_INSTALL_DIR to enterprise (NANO_CONVERT_EDITION=enterprise): it is still a git checkout (.git), which this installer would reset to the open repository. Nothing was changed. Use scripts/nano convert --to enterprise."
elif [[ -e "$NANO_INSTALL_DIR/.git" ]]; then
    if [[ "${NANO_SKIP_GIT_UPDATE:-0}" == "1" || "$RECORD_PG_HA_IDENTITY_ONLY" == "1" ]]; then
        log "Not updating the checkout (NANO_SKIP_GIT_UPDATE=1 or --record-pg-ha-identity) — installing the checkout at $NANO_INSTALL_DIR as is"
    else
        update_git_checkout "$NANO_INSTALL_DIR" "$NANO_BRANCH"
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

# NAN-5558: while `scripts/nano convert` is unfinished, only its own installer
# runs (it passes NANO_CONVERT_RUN, the journal's run_id) may change this
# install. Finish it with --resume, or undo it with --rollback.
if [[ -e .nano-convert.json || -L .nano-convert.json ]]; then
    convert_state=$(sed -n 's/^  "state": *"\([a-z-]*\)".*/\1/p' .nano-convert.json 2>/dev/null | awk 'NR == 1')
    convert_run=$(sed -n 's/^  "run_id": *"\([A-Za-z0-9TZ-]*\)".*/\1/p' .nano-convert.json 2>/dev/null | awk 'NR == 1')
    case "$convert_state" in
        verified | rolled-back) ;;
        *)
            [[ -n "$convert_run" && "${NANO_CONVERT_RUN:-}" == "$convert_run" ]] \
                || fail "A conversion to enterprise is in progress here (state ${convert_state:-unknown}, .nano-convert.json). Finish it with scripts/nano convert --resume, or undo it with scripts/nano convert --rollback. Nothing was changed."
            ;;
    esac
fi

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
                postgres|postgres-ha) running_roles+=",postgres" ;;
                clickhouse) running_roles+=",clickhouse" ;;
                keeper) running_roles+=",keeper" ;;
                vector|vector-config-consumer|vector-tap|ingest-edge) running_roles+=",ingest" ;;
                nano-api|nano-jobs|nano-search|nano-web|nginx|app-internal-edge) running_roles+=",app" ;;
                prometheus|grafana) running_roles+=",monitoring" ;;
            esac
        done < <(docker ps --filter "label=com.docker.compose.project=$installed_project" \
            --format '{{.Label "com.docker.compose.service"}}' </dev/null 2>/dev/null || true)
    fi
    effective_roles=""
    for canonical_role in app ingest clickhouse keeper postgres monitoring; do
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

# NAN-5251: a role-split .env must stay byte-identical on every host, so any
# run that changes it, on any role, says so. The baseline is taken when an
# existing .env is reused; every later writer (license, release keys, the
# PostgreSQL HA identity, backfilled secrets, ...) is then covered by one
# comparison instead of a message per writer. The baseline lives only in this
# shell (never exported, never written to disk).
SHARED_ENV_BASELINE=""
SHARED_ENV_TRACKED=0
shared_env_rebaseline() {
    [[ -f .env ]] || return 0
    SHARED_ENV_BASELINE="$(cat .env; printf .)"
    SHARED_ENV_BASELINE="${SHARED_ENV_BASELINE%.}"
    SHARED_ENV_TRACKED=1
}
report_shared_env_change() {
    local notice
    [[ "${MULTI_NODE:-0}" == "1" && "$SHARED_ENV_TRACKED" == "1" && -f .env ]] || return 0
    notice="$(nano_shared_env_change_notice "$SHARED_ENV_BASELINE" .env)" || return 0
    [[ -n "$notice" ]] && warn "$notice"
    shared_env_rebaseline
}
[[ -r scripts/lib/async-loader-readiness.sh ]] \
    || fail "scripts/lib/async-loader-readiness.sh not found in $NANO_INSTALL_DIR. The source tree or release bundle is incomplete."
# shellcheck source=scripts/lib/async-loader-readiness.sh
. scripts/lib/async-loader-readiness.sh
[[ -r scripts/lib/image-pull.sh ]] \
    || fail "scripts/lib/image-pull.sh not found in $NANO_INSTALL_DIR. The source tree or release bundle is incomplete."
# shellcheck source=scripts/lib/image-pull.sh
. scripts/lib/image-pull.sh
[[ -r scripts/lib/data-mount.sh ]] \
    || fail "scripts/lib/data-mount.sh not found in $NANO_INSTALL_DIR. The source tree or release bundle is incomplete."
# shellcheck source=scripts/lib/data-mount.sh
. scripts/lib/data-mount.sh

# NAN-5251: a data disk that did not mount at boot leaves Docker running on an
# empty directory of the root disk. Installing there would start a new, empty
# member (or a fresh database) beside the real data. Linux only: Docker Desktop
# keeps its data inside its own VM.
if [[ "$(uname -s)" == Linux && "${NANO_PREPARE_ONLY:-0}" != "1" ]]; then
    docker_root_dir=$(docker info --format '{{.DockerRootDir}}' </dev/null 2>/dev/null || true)
    if [[ -n "$docker_root_dir" ]]; then
        if ! data_mount_state=$(nano_check_data_mount "$docker_root_dir"); then
            data_mount=${data_mount_state#unmounted }
            fail "The data disk for $docker_root_dir ($data_mount in /etc/fstab) is not mounted, so Docker is running on the root disk without this host's data. Nothing was changed. Stop Docker (sudo systemctl stop docker.socket docker), mount the disk (sudo mount $data_mount), check that $docker_root_dir holds the previous data, start Docker, then add the docker.service drop-in from the install guide so Docker never starts without the disk again. If this host's storage is managed some other way, set NANO_DATA_MOUNT=<mount point> (or NANO_DATA_MOUNT=none to skip this check)."
        fi
        case "$data_mount_state" in
            "mounted "*" no")
                data_mount=${data_mount_state#mounted }
                data_mount=${data_mount% no}
                warn "docker.service does not require the data disk $data_mount: after a reboot where the disk fails to mount, Docker starts empty on the root disk. Add a drop-in: sudo mkdir -p /etc/systemd/system/docker.service.d && printf '[Unit]\\nRequiresMountsFor=$data_mount\\n' | sudo tee /etc/systemd/system/docker.service.d/nano-data-disk.conf && sudo systemctl daemon-reload"
                ;;
            "mounted "*)
                data_mount=${data_mount_state#mounted }
                ok "Data disk ${data_mount% *} is mounted under Docker"
                ;;
        esac
        # NAN-5269: after a hard reset udev can miss the data disk; Docker then
        # (correctly) stays stopped and the host stays down until someone
        # mounts the disk by hand. The self-heal timer retries during the
        # first 30 minutes after boot.
        if [[ "$data_mount_state" == "mounted "* ]]; then
            data_mount=${data_mount_state#mounted }
            data_mount=${data_mount% *}
            heal_state=$(nano_ensure_data_disk_heal "$data_mount" scripts/lib/data-disk-heal.sh)
            case "$heal_state" in
                current) ok "Data disk self-heal timer is installed (nano-data-disk-heal.timer)" ;;
                installed) ok "Installed the data disk self-heal timer (nano-data-disk-heal.timer; remove: sudo sh scripts/lib/data-disk-heal.sh uninstall)" ;;
                manual*) warn "The data disk $data_mount has no self-heal timer: after a hard reset that misses the disk, Docker stays stopped until someone mounts it by hand. Install it once (it needs root): ${heal_state#manual }. Remove it later with: sudo sh scripts/lib/data-disk-heal.sh uninstall. Set NANO_DATA_DISK_HEAL=off to stop this check." ;;
            esac
        fi
    fi
fi

# NAN-5214/NAN-5263: record the PostgreSQL HA cluster's system identifier in
# the shared .env once this host's Patroni member holds the cluster's data.
# Prints recorded <id> | unchanged <id> | conflict <reason> | pending.
# The first postgres host cannot record it during its own install: a 3-member
# etcd has no quorum until a second postgres host joins, so the cluster only
# bootstraps then. It records it with `install.sh --record-pg-ha-identity`
# (below) after the other postgres hosts are installed, without recreating
# any container (that member is usually the leader).
pg_ha_record_identity() {
    local wait_seconds="$1" deadline status outcome="pending"
    deadline=$(( $(date +%s) + wait_seconds ))
    while :; do
        status=0
        outcome=$(docker compose "${COMPOSE_ARGS[@]}" exec -T postgres-ha \
                pg_controldata -D /var/lib/postgresql/data 2>/dev/null </dev/null \
            | python3 -I scripts/lib/pg_ha_system_id.py .env) || status=$?
        [[ "$status" == 4 ]] || break
        (( $(date +%s) < deadline )) || break
        sleep 5
    done
    printf '%s\n' "$outcome"
}

PG_HA_COPY_ADVICE="copy the FIRST postgres host's .env to every other host (app, ingest, ClickHouse, Keeper and postgres) before the next install.sh run anywhere, then check that 'sha256sum .env' matches on every host"

if [[ "$RECORD_PG_HA_IDENTITY_ONLY" == "1" ]]; then
    [[ -f .env && -f .nano-role.env && -f deploy/compose/docker-compose.enterprise.yml ]] \
        || fail "--record-pg-ha-identity runs on an installed PostgreSQL HA host; $NANO_INSTALL_DIR has no .env/.nano-role.env from a role-split install."
    grep -q '^NANO_PATRONI_BOOTSTRAP=' .nano-role.env \
        || fail "This host runs no PostgreSQL HA member (no NANO_PATRONI_BOOTSTRAP in .nano-role.env); run --record-pg-ha-identity on the first postgres host."
    grep -q '^NANO_PATRONI_BOOTSTRAP="true"' .nano-role.env \
        || warn "This is not the first postgres host. The first postgres host's .env is the one to copy; run --record-pg-ha-identity there."
    MULTI_NODE=1
    COMPOSE_FILE="deploy/compose/docker-compose.enterprise.yml"
    COMPOSE_ARGS=(--env-file .env --env-file .nano-role.env -f "$COMPOSE_FILE")
    shared_env_rebaseline
    log "Reading the PostgreSQL HA cluster identity from this host's member (nothing is rendered, pulled or restarted)"
    pg_ha_outcome=$(pg_ha_record_identity "${NANO_PG_HA_SYSTEM_ID_WAIT:-60}")
    case "$pg_ha_outcome" in
        recorded*)
            ok "Recorded the PostgreSQL cluster identity in .env (${pg_ha_outcome#recorded })"
            shared_env_rebaseline
            warn "The shared .env changed on this host (NANO_PG_HA_SYSTEM_ID): $PG_HA_COPY_ADVICE." ;;
        unchanged*)
            ok "The PostgreSQL cluster identity is already recorded in .env (${pg_ha_outcome#unchanged }); nothing changed." ;;
        conflict*)
            fail "PostgreSQL HA identity mismatch: ${pg_ha_outcome#conflict }. This host's database is not the cluster recorded in .env; do not continue. See 'Recovering after losing the bootstrap host and etcd' in the multi-node guide." ;;
        *)
            fail "This host's PostgreSQL HA member holds no cluster data yet. The cluster bootstraps once a second postgres host is installed (etcd needs 2 of 3 members); install the other postgres hosts, check 'docker compose ps postgres-ha', then run this again." ;;
    esac
    exit 0
fi

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

# Prints a fixed-point number for report_sizing_changes' comparison only.
# printf, never print: mawk (Debian/Ubuntu's default awk) prints any value
# above 2^31 as %.6g, so two ~8 GiB byte limits that differ by under 10 KB
# printed alike and a reduction went unreported (NAN-5440 audit).
sizing_numeric_value() {
    local key="$1" value="$2"
    value="${value%\"}" value="${value#\"}"
    value="${value%\'}" value="${value#\'}"
    awk -v key="$key" -v value="$value" '
        BEGIN {
            if (key ~ /CPU/) {
                if (value ~ /^[0-9]+([.][0-9]+)?m$/) {
                    sub(/m$/, "", value)
                    printf "%.6f\n", value / 1000
                } else if (value ~ /^[0-9]+([.][0-9]+)?$/) {
                    printf "%.6f\n", value + 0
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
                printf "%.6f\n", number + 0
                exit
            }
            if (value ~ /^[0-9]+([.][0-9]+)?$/)
                printf "%.6f\n", value + 0
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
        # NAN-5636: server settings (e.g. max_temporary_data_on_disk_size) load
        # only at ClickHouse start; profile settings reload live.
        if [[ "$xml_kind" == server ]] && ! cmp -s "$old_xml" "$new_xml"; then
            log "Sizing change: ClickHouse server settings apply when ClickHouse restarts. A single-node rerun recreates it; on a role host, restart the ClickHouse container after this rerun."
        fi
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
# NAN-5263: the release this install ran BEFORE this run ("" for a fresh install
# or one that predates the key). Only installs from before v2 (no ingest tokens
# yet) can still be in the deprecated legacy multiplex ingest mode.
PRE_RUN_NANO_VERSION=$(env_value NANO_VERSION)
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
OPEN_IMAGE_PREFIX="ghcr.io/nano-rs/nano"

# NAN-5558: the one edition change an install allows, open -> enterprise, made
# only by `scripts/nano convert --to enterprise`. It extracts the enterprise
# compose package over an open single-node install, then runs this installer
# with NANO_CONVERT_EDITION=enterprise and the license. Every condition below
# must hold; otherwise the edition and image-source guards stay as they are.
CONVERTING_TO_ENTERPRISE=0
if [[ "$CONVERT_EDITION_INPUT" == enterprise && "$RECORDED_EDITION" == enterprise && "$MARKER_EDITION" == enterprise ]]; then
    # A resumed conversion: an earlier run already recorded the enterprise
    # edition. This is an ordinary enterprise re-run.
    log "NANO_CONVERT_EDITION=enterprise: this install already records the enterprise edition; continuing as a normal re-run"
elif [[ "$CONVERT_EDITION_INPUT" == enterprise ]]; then
    convert_refused() {
        fail "Refusing to convert this install to enterprise (NANO_CONVERT_EDITION=enterprise): $1 Nothing was changed. Use scripts/nano convert --to enterprise, which checks all of this first."
    }
    [[ -f .env ]] || convert_refused "there is no existing install here (.env is missing); install the enterprise bundle directly instead."
    [[ "$RECORDED_EDITION" == open ]] || convert_refused "this install's .env records edition '${RECORDED_EDITION:-none}'; only an open install converts."
    [[ "$MARKER_EDITION" == enterprise ]] || convert_refused "the source tree's .nano-edition says '${MARKER_EDITION:-nothing}'; extract the enterprise compose package over $NANO_INSTALL_DIR first."
    [[ -z "$ENV_EDITION" || "$ENV_EDITION" == enterprise ]] || convert_refused "NANO_EDITION=$ENV_EDITION is set in the environment."
    [[ "$RECORDED_PREFIX" == "$OPEN_IMAGE_PREFIX" ]] || convert_refused ".env records NANO_IMAGE_PREFIX=${RECORDED_PREFIX:-none}, not the open edition's $OPEN_IMAGE_PREFIX."
    [[ -z "$INVENTORY_ARG$ROLE_ARG" && ! -e .nano-role.env ]] || convert_refused "this is a role-split install; conversion supports single-node installs only."
    [[ ! -e .git ]] || convert_refused "$NANO_INSTALL_DIR is still a git checkout (.git), which a re-run would reset to the open repository."
    [[ -f images.enterprise.customer.lock ]] || convert_refused "images.enterprise.customer.lock is missing; the enterprise compose package ships it."
    [[ -z "${NANO_IMAGES_LOCK:-}" || "$NANO_IMAGES_LOCK" == images.enterprise.customer.lock ]] \
        || convert_refused "NANO_IMAGES_LOCK=$NANO_IMAGES_LOCK; a converted install pulls the customer images (images.enterprise.customer.lock)."
    if [[ -n "$LICENSE_TOKEN_INPUT" && -n "$LICENSE_DEPLOYMENT_ID_INPUT" ]] \
        || [[ "$LICENSE_MODE_INPUT" == offline || -n "$LICENSE_FILE_INPUT" ]]; then
        :
    else
        convert_refused "no license was given to this run (LICENSE_TOKEN and NANO_DEPLOYMENT_ID, or NANO_LICENSE_MODE=offline with NANO_LICENSE_FILE)."
    fi
    CONVERTING_TO_ENTERPRISE=1
    RECORDED_EDITION=enterprise
    log "Converting this open install to enterprise (NANO_CONVERT_EDITION=enterprise): same release, same data"
fi

NANO_EDITION="" EDITION_FROM=""
for src in "the source tree (.nano-edition)=$MARKER_EDITION" "this install's .env=$RECORDED_EDITION" "the NANO_EDITION environment variable=$ENV_EDITION"; do
    value="${src##*=}" origin="${src%=*}"
    [[ -z "$value" ]] && continue
    [[ "$value" == open || "$value" == enterprise ]] || fail "Invalid edition '$value' from $origin (expected open or enterprise)."
    if [[ -z "$NANO_EDITION" ]]; then
        NANO_EDITION="$value" EDITION_FROM="$origin"
    elif [[ "$value" != "$NANO_EDITION" ]]; then
        fail "Edition mismatch: $EDITION_FROM says $NANO_EDITION but $origin says $value. An install never switches edition on a re-run; use the bundle for this install's edition, or a new NANO_INSTALL_DIR. To move an open install to enterprise (Self-run), use scripts/nano convert --to enterprise."
    fi
done
[[ -n "$NANO_EDITION" ]] || fail "Cannot determine the edition: $NANO_INSTALL_DIR has no .nano-edition marker and no recorded install. Set NANO_EDITION=open or NANO_EDITION=enterprise."

# The <prefix>-api line of a lock names the install's image prefix.
lock_image_prefix() {
    awk '$1 ~ /-api$/ && $2 ~ /^sha256:/ {sub(/-api$/, "", $1); print $1; exit}' "$1" 2>/dev/null
}

# NAN-5505: an enterprise bundle ships two locks with the same digests.
# images.enterprise.customer.lock names the customer repository, the only one
# the license-issued pull credential can read; images.enterprise.lock names
# nano's internal repository. Without NANO_IMAGES_LOCK the customer lock is
# the default when the bundle ships it, except for an install already running
# the internal images (it keeps them; switching would recreate everything).
CUSTOMER_LOCK=images.enterprise.customer.lock
INTERNAL_LOCK=images.enterprise.lock
CUSTOMER_PREFIX="" INTERNAL_PREFIX=""
[[ -f "$CUSTOMER_LOCK" ]] && CUSTOMER_PREFIX=$(lock_image_prefix "$CUSTOMER_LOCK")
[[ -f "$INTERNAL_LOCK" ]] && INTERNAL_PREFIX=$(lock_image_prefix "$INTERNAL_LOCK")

# A customer Self-run install: license values given to this run or recorded.
has_customer_license() {
    [[ -n "$LICENSE_TOKEN_INPUT$LICENSE_FILE_INPUT" ]] && return 0
    [[ "$LICENSE_MODE_INPUT" == offline || "$LICENSE_MODE_INPUT" == online ]] && return 0
    [[ -n "$(env_value LICENSE_TOKEN)$(env_value DEPLOYMENT_TOKEN)" ]] && return 0
    case "$(env_value NANO_LICENSE_MODE)" in online|offline) return 0 ;; esac
    return 1
}

# True when no container was ever created for this install: none carries this
# directory's Compose label and none runs an image under the recorded prefix.
# Unknown (docker cannot list containers) counts as "has run".
install_never_ran() {
    local listing here physical
    here="$PWD" physical=$(pwd -P)
    listing=$(docker ps -a --format '{{.Image}}|{{.Label "com.docker.compose.project.working_dir"}}' </dev/null 2>/dev/null) || return 1
    while IFS='|' read -r image workdir; do
        [[ -z "$image$workdir" ]] && continue
        if [[ -n "$workdir" ]]; then
            [[ "$workdir" == "$here" || "$workdir" == "$physical" ]] && return 1
            [[ -d "$workdir" && "$(cd "$workdir" 2>/dev/null && pwd -P)" == "$physical" ]] && return 1
        fi
        [[ -n "$RECORDED_PREFIX" && "$image" == "$RECORDED_PREFIX-"* ]] && return 1
    done <<< "$listing"
    return 0
}

# NAN-5505: v2.0.29 and earlier defaulted to the internal lock, so a plain
# ./install.sh recorded nano's internal prefix in .env before the pull failed.
# Such a customer install never started anything and may move to the customer
# prefix (same digests). An install that ever ran keeps the refusal below.
internal_to_customer_switch_ok() {
    [[ -n "$CUSTOMER_PREFIX" && -n "$INTERNAL_PREFIX" && "$RECORDED_PREFIX" == "$INTERNAL_PREFIX" ]] || return 1
    # Role-split: only the app host decides; other hosts follow the prefix in
    # the .env copied from it, so the cluster never mixes prefixes.
    [[ -n "$INVENTORY_ARG" && ",${ROLE_ARG}," != *,app,* ]] && return 1
    has_customer_license || return 1
    install_never_ran
}

case "$NANO_EDITION" in
    open) IMAGES_LOCK="images.lock" ;;
    enterprise)
        if [[ -n "${NANO_IMAGES_LOCK:-}" ]]; then
            IMAGES_LOCK="$NANO_IMAGES_LOCK"
        elif [[ -z "$CUSTOMER_PREFIX" ]]; then
            IMAGES_LOCK="$INTERNAL_LOCK"
        elif [[ -n "$RECORDED_PREFIX" && "$RECORDED_PREFIX" == "$INTERNAL_PREFIX" ]] && ! internal_to_customer_switch_ok; then
            IMAGES_LOCK="$INTERNAL_LOCK"
        else
            IMAGES_LOCK="$CUSTOMER_LOCK"
        fi
        ;;
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

NANO_IMAGE_PREFIX=$(lock_image_prefix "$IMAGES_LOCK")
[[ -n "$NANO_IMAGE_PREFIX" ]] || fail "$IMAGES_LOCK records no <prefix>-api image."
if [[ "$CONVERTING_TO_ENTERPRISE" == 1 ]]; then
    # NAN-5558: the open prefix in .env becomes the customer prefix, and only
    # that: same release, customer lock.
    [[ "$IMAGES_LOCK" == "$CUSTOMER_LOCK" && -n "$CUSTOMER_PREFIX" && "$NANO_IMAGE_PREFIX" == "$CUSTOMER_PREFIX" \
        && "$NANO_IMAGE_PREFIX" != "$OPEN_IMAGE_PREFIX" ]] \
        || convert_refused "the enterprise package's customer lock does not name the customer image repository."
    [[ "$NANO_VERSION" == "$PRE_RUN_NANO_VERSION" ]] \
        || convert_refused "this install runs release ${PRE_RUN_NANO_VERSION:-unknown} and the enterprise package is release $NANO_VERSION. Conversion never changes the release: upgrade the open install to $NANO_VERSION first (or use the $PRE_RUN_NANO_VERSION enterprise package)."
    log "Switching the image source from $RECORDED_PREFIX-* (open) to $NANO_IMAGE_PREFIX-* (enterprise customer repository)"
else
    if [[ "$NANO_EDITION" == open && "$NANO_IMAGE_PREFIX" != "$OPEN_IMAGE_PREFIX" ]] \
        || [[ "$NANO_EDITION" == enterprise && "$NANO_IMAGE_PREFIX" == "$OPEN_IMAGE_PREFIX" ]]; then
        fail "$IMAGES_LOCK lists $NANO_IMAGE_PREFIX-* images, which are not the $NANO_EDITION edition's."
    fi
    if [[ -n "$RECORDED_PREFIX" && "$RECORDED_PREFIX" != "$NANO_IMAGE_PREFIX" ]] \
        && [[ "$NANO_IMAGE_PREFIX" == "$CUSTOMER_PREFIX" ]] && internal_to_customer_switch_ok; then
        log "Switching this install from nano's internal image repository ($RECORDED_PREFIX-*) to the customer repository ($NANO_IMAGE_PREFIX-*): same image digests, and nothing has run here yet"
    elif [[ -n "$RECORDED_PREFIX" && "$RECORDED_PREFIX" != "$NANO_IMAGE_PREFIX" ]]; then
        fail "This install runs $RECORDED_PREFIX-* images but $IMAGES_LOCK lists $NANO_IMAGE_PREFIX-*. Refusing to switch image source on a re-run."
    fi
fi
ok "Edition $NANO_EDITION (from $EDITION_FROM), release $NANO_VERSION ($NANO_IMAGE_PREFIX-*)"

# NAN-5354: a re-run on an existing install is an upgrade from the release in
# .env (PRE_RUN_NANO_VERSION) to $NANO_VERSION, and must not skip a release the
# upgrade policy marks as a required stop (v2.0.20 before v2.0.23: its audit
# readers must be live before writers stop dual-writing). Same rule as
# `scripts/nano upgrade` (the path union over every release up to the target),
# from the same code: scripts/lib/nano_bundle.py upgrade-path. Covers
# single-node and every role-split (--role) host of a release bundle (which
# ships the policy), before anything is written. An open-core git checkout has
# no deploy/release/ (the mirror strips it), so the check is skipped there with
# a note.
check_required_stops() {
    local policy=deploy/release/upgrade-policy.json out
    [[ "$PRE_RUN_NANO_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && "$PRE_RUN_NANO_VERSION" != "$NANO_VERSION" ]] || return 0
    if [[ ! -f "$policy" ]]; then
        warn "No upgrade policy in this tree ($policy; open-core git checkouts do not ship it): skipping the required-stop check for $PRE_RUN_NANO_VERSION -> $NANO_VERSION. Follow the release notes' upgrade path (required stops are listed there)."
        return 0
    fi
    if ! command -v python3 >/dev/null 2>&1; then
        if tr -d '[:space:]' < "$policy" | grep '"required_stops":\["' >/dev/null; then
            fail "This release's upgrade policy has required stops, and python3 is needed to check the path from $PRE_RUN_NANO_VERSION to $NANO_VERSION. Install Python 3, then re-run."
        fi
        return 0
    fi
    out=$(python3 -I scripts/lib/nano_bundle.py upgrade-path --policy "$policy" \
        --from "$PRE_RUN_NANO_VERSION" --to "$NANO_VERSION" </dev/null 2>&1) \
        || fail "Refusing to upgrade: ${out#nano bundle: } (install each required release with its own bundle or checkout, then re-run this one)."
}
check_required_stops

if [[ "${UPGRADE_CONFIRMED:-0}" != 1 ]]; then
    if [[ -e .git ]]; then
        confirm_upgrade "$PRE_RUN_NANO_VERSION" "$NANO_VERSION" "To restart without upgrading, re-run with NANO_SKIP_GIT_UPDATE=1 ./install.sh." check-only-ok
    else
        confirm_upgrade "$PRE_RUN_NANO_VERSION" "$NANO_VERSION" "To stay on $PRE_RUN_NANO_VERSION, run ./install.sh from its own bundle instead." check-only-ok
    fi
fi
# NAN-5566: before .env is written and images are pulled (a bundle install, or
# a re-run whose checkout was already current), so a refusal changes nothing.
confirm_senders_paused_if_old_vector

validate_egress_policy_input
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
validate_ingest_ack_durability_input
validate_planned_volume_input
validate_retention_input
validate_detection_max_matches_input
if [[ -n "${NANO_BASE_URL:-}" ]]; then
    # A value pasted with a trailing space or saved with CRLF endings is
    # trimmed first, the same as a typed answer.
    normalize_base_url "$(trim_space "$NANO_BASE_URL")" >/dev/null \
        || fail "NANO_BASE_URL must be http(s)://host[:port][/path] (got '$NANO_BASE_URL')."
fi

if [[ "${NANO_CHECK_ONLY:-0}" == "1" ]]; then
    printf 'edition=%s\nversion=%s\nimage_prefix=%s\nlock=%s\n' "$NANO_EDITION" "$NANO_VERSION" "$NANO_IMAGE_PREFIX" "$IMAGES_LOCK"
    exit 0
fi

# NAN-5506: host size (vCPU, RAM, free disk) against nano's minimum for this
# host's roles, before any prompt or .env write. The first point the sources
# (and so the shared minimums) exist on a curl | bash install.
[[ -r scripts/lib/host-minimums.sh ]] \
    || fail "scripts/lib/host-minimums.sh not found in $NANO_INSTALL_DIR. The source tree or release bundle is incomplete."
# shellcheck source=scripts/lib/host-minimums.sh
. scripts/lib/host-minimums.sh
log "Checking host size"
nano_host_minimums_gate "$ROLE_ARG" "$PWD"

[[ -r scripts/lib/install-preflight.sh ]] \
    || fail "scripts/lib/install-preflight.sh not found in $NANO_INSTALL_DIR. The source tree or release bundle is incomplete."
# shellcheck source=scripts/lib/install-preflight.sh
. scripts/lib/install-preflight.sh

# NAN-5558: record the converted edition and image source now, before any
# helper reads .env. scripts/nano-tiering.py (and Agent Lane's renderer) take
# the edition from .env, so with the open value still there the conversion
# failed at the tiering step. This changes no container: Compose reads .env
# only when the stack is (re)created further down. The same keys are written
# again below on every run.
if [[ "$CONVERTING_TO_ENTERPRISE" == 1 ]]; then
    nano_env_set_keys .env "NANO_EDITION=$NANO_EDITION" "NANO_VERSION=$NANO_VERSION" "NANO_IMAGE_PREFIX=$NANO_IMAGE_PREFIX" \
        || fail "Could not record NANO_EDITION/NANO_IMAGE_PREFIX in .env for the conversion. Nothing was changed."
    ok "Recorded the enterprise edition and image source in .env (conversion)"
fi

# NAN-5521: a stack started before 2.0.30 with NANO_COMPOSE_OVERLAYS in the
# environment only (the portal's TLS command) has those overlays on its running
# containers but not in .env, so this re-run would recreate nginx without
# docker-compose.tls.yml and turn HTTPS off. Record what the running stack uses
# unless this run sets NANO_COMPOSE_OVERLAYS itself (an explicit choice).
if [[ "$MULTI_NODE" != "1" && -z "${NANO_COMPOSE_OVERLAYS+set}" && -f .env ]]; then
    running_overlays=$(nano_running_compose_overlays "$PWD" "$(env_value COMPOSE_PROJECT_NAME)")
    if merged_overlays=$(nano_merge_running_overlays "$(env_value NANO_COMPOSE_OVERLAYS)" "$running_overlays"); then
        nano_env_set_keys .env "NANO_COMPOSE_OVERLAYS=$merged_overlays" \
            || fail "Could not record NANO_COMPOSE_OVERLAYS in .env."
        warn "The running stack uses compose overlay(s) .env did not list; recorded NANO_COMPOSE_OVERLAYS=$merged_overlays in .env so this run keeps them (to drop one, run with NANO_COMPOSE_OVERLAYS set to the list you want)."
    fi
fi

# NAN-5509: the TLS overlay (NANO_COMPOSE_OVERLAYS in the environment, or as
# recorded in .env) makes nginx load config/nginx/ssl/{fullchain,privkey}.pem.
# Without them every prompt, the pull and the migrations ran, and the install
# ended 5 minutes later as "API did not become healthy (HTTP 000)".
if [[ -n "${NANO_COMPOSE_OVERLAYS+set}" ]]; then
    tls_overlay_list="$NANO_COMPOSE_OVERLAYS"
else
    tls_overlay_list="$(env_value NANO_COMPOSE_OVERLAYS)"
fi
# NAN-5521: on an existing install (.env and its containers or volumes) nginx
# is already serving these files, so a problem is a loud warning, not a
# refusal; a fresh install still refuses. NANO_SKIP_TLS_PREFLIGHT=1 skips it.
if [[ "$MULTI_NODE" != "1" ]] && nano_tls_overlay_requested "$tls_overlay_list"; then
    if [[ "${NANO_SKIP_TLS_PREFLIGHT:-0}" == "1" ]]; then
        warn "NANO_SKIP_TLS_PREFLIGHT=1: not checking the HTTPS certificate in config/nginx/ssl. If nginx cannot load it, HTTPS stays down after this run."
    elif tls_problem=$(nano_tls_cert_check "$PWD"); then
        ok "HTTPS certificate: config/nginx/ssl/fullchain.pem and privkey.pem match and are valid"
    elif nano_host_min_existing_install "$PWD"; then
        warn "!! ${tls_problem% Nothing was changed.}"
        warn "!! Continuing because this is an existing install (nginx may already be serving these files). Fix the certificate soon: if nginx cannot load it after this run, HTTPS is down. Set NANO_SKIP_TLS_PREFLIGHT=1 to skip this check."
    else
        fail "$tls_problem"
    fi
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

# NAN-5367: the role-split renderer admits this host's Docker address pools to
# ClickHouse when bridge-network services here reach it on the host address.
if [[ "$MULTI_NODE" == "1" ]]; then
    NANO_DOCKER_ADDRESS_POOLS_JSON=$(docker info --format '{{json .DefaultAddressPools}}' </dev/null 2>/dev/null || true)
    export NANO_DOCKER_ADDRESS_POOLS_JSON
fi

# NAN-5213: with several app hosts only the FIRST app host in inventory order
# may create the shared .env or generate secrets. Another app host that made
# its own .env would sign tokens with a different JWT_SECRET and encrypt
# credentials with a different NANOSIEM_ENCRYPTION_KEY.
APP_SECRET_OWNER=0
if [[ "$MULTI_NODE" == "1" && ",${ROLE_ARG}," == *,app,* ]]; then
    APP_SECRET_OWNER=1
    app_primary_json=$(python3 -I deploy/compose/render-inventory.py \
        --inventory "$INVENTORY_PATH" --roles "$ROLE_ARG" --identity-only </dev/null) \
        || fail "Inventory validation failed. No services have started."
    if [[ "$(python3 -I -c 'import json,sys; print("0" if json.loads(sys.argv[1]).get("app_primary") is False else "1")' "$app_primary_json" </dev/null)" == "0" ]]; then
        APP_SECRET_OWNER=0
    fi
fi
if [[ "$MULTI_NODE" == "1" && ! -f .env && "$APP_SECRET_OWNER" != "1" ]]; then
    if [[ ",${ROLE_ARG}," == *,app,* ]]; then
        fail "This is not the first app host in the inventory. A role-split cluster's shared .env is created on the first app host (use NANO_PREPARE_ONLY=1 there), then copied securely to every other host, including the other app hosts, before installing role(s) $ROLE_ARG."
    fi
    fail "A role-split cluster's shared .env must be created on an app-role host first (use NANO_PREPARE_ONLY=1), then copied securely to this host before installing role(s) $ROLE_ARG."
fi

# NAN-5508: no .env, but this Compose project's databases are still on the
# host (a moved or deleted install directory, a re-extracted bundle). A new
# .env would generate new database passwords, and PostgreSQL and ClickHouse
# keep the ones their data was created with. Stop before asking anything.
compose_project_name() {
    local name="${COMPOSE_PROJECT_NAME:-}"
    [[ -n "$name" ]] || name=$(basename "$PWD")
    name=$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9_-')
    while [[ "$name" == [_-]* ]]; do name=${name#?}; done
    printf '%s' "$name"
}
refuse_fresh_env_over_volumes() {
    local project volumes="" volume
    project=$(compose_project_name)
    [[ -n "$project" ]] || return 0
    for volume in nano-postgres-data nano-clickhouse-data; do
        volumes+=$(docker volume ls -q --filter "label=com.docker.compose.project=$project" \
            --filter "label=com.docker.compose.volume=$volume" </dev/null 2>/dev/null | tr '\n' ' ' || true)
    done
    volumes=$(trim_space "$volumes")
    [[ -z "$volumes" ]] && return 0
    fail "This Docker host still holds nano's databases from an earlier install of $PWD (Compose project '$project': $volumes), but there is no .env here. Those databases only accept the passwords in the .env they were created with, so the installer will not generate new ones. Restore that .env to $PWD/.env (from a backup or the old install directory, mode 600) and re-run. To delete the old data and start fresh instead: docker compose -f $COMPOSE_FILE -p $project down -v (this DELETES ALL nano data on this host), then re-run. Nothing was written."
}
if [[ ! -f .env && "$MULTI_NODE" != "1" ]]; then
    refuse_fresh_env_over_volumes
fi

# NAN-5509/NAN-5513: refuse when another program holds a port nano publishes.
# CONFIG_JSON is `docker compose config --format json`; PORTS its
# nano_published_ports lines. Ports this install's own Compose project holds
# (a re-run of a running install) are not conflicts. NANO_SKIP_PORT_CHECK=1
# skips the check.
fail_on_port_conflicts() {
    local config_json="$1" ports="$2" done_sentence="$3" project conflicts
    [[ -n "$ports" && "${NANO_SKIP_PORT_CHECK:-0}" != "1" ]] || return 0
    project=$(printf '%s' "$config_json" | nano_compose_project 2>/dev/null) || project=""
    [[ -n "$project" ]] || project=$(compose_project_name)
    conflicts=$(nano_port_conflicts "$ports" "$NANO_INSTALL_DIR" "$project")
    [[ -z "$conflicts" ]] && return 0
    printf '%s\n' "$conflicts" | sed 's/^/  - /' >&2
    fail "nano cannot publish the port(s) above: another program already uses them. Stop it (for a system service: sudo systemctl disable --now <service>), or move it to another port, then re-run install.sh. $done_sentence NANO_SKIP_PORT_CHECK=1 skips this check."
}
# NAN-5513: check the base graph's ports before the first question, so a busy
# port does not cost the operator every answer first. The overlays and
# profiles the answers choose are re-checked after rendering, before the pull.
if [[ "$MULTI_NODE" != "1" && "${NANO_SKIP_PORT_CHECK:-0}" != "1" ]]; then
    # A fresh install has no .env yet: stand in for the variables the graph
    # requires (${VAR:?}) so it still renders. Placeholders only, never
    # secrets, and only when unset; ports do not depend on them.
    early_env=()
    if [[ ! -f .env ]]; then
        while IFS= read -r early_var; do
            # Compose sees only the exported environment (install.sh has set
            # some of these, e.g. NANO_VERSION, as plain shell variables).
            [[ -n "$early_var" && -z "$(printenv "$early_var" 2>/dev/null || true)" ]] \
                && early_env+=("$early_var=placeholder")
        done < <(grep -oE '\$\{[A-Za-z_][A-Za-z0-9_]*:\?' "$COMPOSE_FILE" 2>/dev/null | sed 's/^\${//; s/:?$//' | sort -u)
    fi
    early_config=$(env ${early_env[@]+"${early_env[@]}"} docker compose -f "$COMPOSE_FILE" config --format json </dev/null 2>/dev/null) || early_config=""
    early_ports=$(printf '%s' "$early_config" | nano_published_ports 2>/dev/null) || early_ports=""
    fail_on_port_conflicts "$early_config" "$early_ports" "Nothing was changed."
fi

# NAN-5508: every interactive question, then the review screen, before
# anything below writes .env, generates a secret or starts a container.
if [[ -f .env ]]; then
    collect_answers 0
else
    collect_answers 1
fi

# NAN-5508: NANO_BASE_URL given to a re-run changes BASE_URL (and the dev mode
# it implies) in .env; it was only used for this run's messages before.
record_base_url_input() {
    local recorded url dev mode=off
    [[ -n "${NANO_BASE_URL:-}" ]] || return 0
    url=$(normalize_base_url "$(trim_space "$NANO_BASE_URL")") \
        || fail "NANO_BASE_URL must be http(s)://host[:port][/path] (got '$NANO_BASE_URL')."
    BASE_URL=$url
    recorded=$(env_value BASE_URL)
    [[ "$url" == "$recorded" ]] && return 0
    if [[ "$MULTI_NODE" == "1" && ",${ROLE_ARG}," != *,app,* ]]; then
        fail "NANO_BASE_URL=$url differs from this host's .env (${recorded:-unset}). Set it on the app host (re-run install.sh there with NANO_BASE_URL), copy that .env to every host, then re-run install.sh here."
    fi
    dev=false
    [[ "$url" == http://* ]] && dev=true mode=on
    nano_env_set_keys .env "BASE_URL=$url" "NANOSIEM_DEV_MODE=$dev" \
        || fail "Could not record BASE_URL in .env."
    log "Changed BASE_URL from ${recorded:-unset} to $url in .env (NANOSIEM_DEV_MODE=$dev: dev mode $mode)"
}

if [[ -f .env ]]; then
    if [[ "$LEGACY_UPGRADE" == 1 ]]; then
        # NAN-5559: not "restarting": this run replaces 0.1.x with 2.x.
        warn ".env already exists: keeping existing secrets and upgrading the stack from nano $LEGACY_FROM to $NANO_VERSION (NANO_VERSION=${PRE_RUN_NANO_VERSION:-unset} in .env becomes $NANO_VERSION)."
    elif [[ "$PRE_RUN_NANO_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && "$PRE_RUN_NANO_VERSION" != "$NANO_VERSION" ]]; then
        warn ".env already exists — keeping existing secrets and upgrading the stack from $PRE_RUN_NANO_VERSION to $NANO_VERSION."
    else
        warn ".env already exists — keeping existing secrets and restarting the stack on $NANO_VERSION."
    fi
    REUSE_ENV=1
    shared_env_rebaseline
    # NAN-5263: an earlier installer (v2.0.8) could leave a key twice (a second
    # NANO_LICENSE_MODE line). Keep the effective (last) value, once.
    collapsed_keys=$(nano_env_collapse_duplicates .env) \
        || fail "Could not collapse duplicate lines in .env."
    [[ -z "$collapsed_keys" ]] || ok "Collapsed duplicate .env line(s) for $collapsed_keys (kept the value in effect)"
    record_base_url_input
    revalidate_recorded_base_url
    # Role-split compose intentionally exposes only the five fixed roles. The
    # single-node-only Tenzir profile is not silently dropped or allowed to
    # replace the requested host profile set.
    BUNDLE_TENZIR=0
    grep -qE '^COMPOSE_PROFILES=.*tenzir' .env 2>/dev/null && BUNDLE_TENZIR=1
    if [[ "$MULTI_NODE" == "1" && "$BUNDLE_TENZIR" == "1" ]]; then
        fail "The bundled Tenzir profile is single-node only; role-split installs must use the ocsf or udm schema profile without bundled Tenzir."
    fi
    secret_mode=generate
    if [[ "$MULTI_NODE" == "1" && "$APP_SECRET_OWNER" != "1" ]]; then
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
        warn "Senders using named ingest tokens keep working. Senders that still send the old public token get HTTP 401: issue each one a named token under Ingestion → Log Sources → Credentials ($BASE_URL/ingestion/log-sources/credentials)."
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
        nano_env_set_keys .env "NANO_VECTOR_CONFIG_DELIVERY_STRICT=false" \
            || fail "Could not record NANO_VECTOR_CONFIG_DELIVERY_STRICT in .env."
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
    # NAN-5470: the ClickHouse workload identities (interactive search,
    # dictionary sources) generated just now exist only in this .env. Every
    # ClickHouse server defines those users from the shared .env, and nano-search
    # logs in as nanosiem_search, so the app must not start before the
    # ClickHouse hosts have them. Stop before anything starts; the passwords are
    # saved, so the re-run after the copy goes ahead.
    workload_keys_new=""
    for workload_key in CLICKHOUSE_SEARCH_PASSWORD CLICKHOUSE_DICT_PASSWORD NANO_CLICKHOUSE_CLUSTER_SECRET; do
        if [[ ",${NANO_BACKFILLED_SECRET_KEYS// /}," == *,"$workload_key",* ]]; then
            workload_keys_new="${workload_keys_new:+$workload_keys_new, }$workload_key"
        fi
    done
    if [[ "$MULTI_NODE" == "1" && "$secret_mode" == generate && "${NANO_PREPARE_ONLY:-0}" != "1" \
        && -n "$workload_keys_new" ]]; then
        fail "Generated $workload_keys_new in $NANO_INSTALL_DIR/.env (v2.0.28: dedicated ClickHouse users for interactive search and dictionary sources). Every ClickHouse host defines those users from the shared .env and nano-search logs in with them, so the ClickHouse hosts need it first. Securely copy $NANO_INSTALL_DIR/.env to every inventory host, re-run install.sh on each Keeper and ClickHouse host (one at a time), then re-run this command here and install.sh on the other hosts. Nothing was started."
    fi
    # NAN-5470 (P1-6): on an INSTALLED role-split cluster, NANO_PREPARE_ONLY=1
    # is the upgrade pre-step that creates the new shared secrets for the
    # other hosts. It writes only those (above) and stops: no release pin
    # (NANO_VERSION would make `nano upgrade` see the target as installed),
    # no re-render of .nano-generated under the running containers.
    if [[ "${NANO_PREPARE_ONLY:-0}" == "1" && "$MULTI_NODE" == "1" && -n "$(env_value NANO_VERSION)" ]]; then
        ok "Prepared the shared secrets in $NANO_INSTALL_DIR/.env (${NANO_BACKFILLED_SECRET_KEYS:-none were missing}); the installed release, the generated configuration and every running service are unchanged."
        printf 'Securely copy %s/.env to every inventory host, then run scripts/nano upgrade from this host.\n' "$NANO_INSTALL_DIR"
        exit 0
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
        nano_env_set_keys .env "NANO_SCHEMA_PROFILE=udm" \
            || fail "Could not record NANO_SCHEMA_PROFILE in .env."
        log "Pinned NANO_SCHEMA_PROFILE=udm in .env (this install predates the schema choice)"
    fi
    # Set in place only when this run adds or changes a license value.
    resolve_license 0
    record_license .env
else
    REUSE_ENV=0
    log "Configuring first-time admin account"

    # NAN-5508: the answers confirmed on the review screen.
    [[ "${WANT_admin_email:-0}" == 1 ]] && ADMIN_EMAIL=$ANS_ADMIN_EMAIL
    [[ "${WANT_admin_name:-0}" == 1 ]] && ADMIN_NAME=$ANS_ADMIN_NAME
    if [[ "${WANT_admin_password:-0}" == 1 ]]; then
        ADMIN_PASSWORD=$ANS_ADMIN_PASSWORD GENERATED_PASSWORD=${ANS_PASSWORD_GENERATED:-0}
    fi
    [[ -z "$ADMIN_EMAIL" ]]    && prompt_admin_email
    [[ -z "$ADMIN_EMAIL" ]]    && fail "Admin email is required."

    # Unattended, the display name takes its default (the prompt's).
    if [[ -z "$ADMIN_NAME" ]] && ! have_controlling_tty; then
        ADMIN_NAME=Admin
    elif [[ -z "$ADMIN_NAME" ]]; then
        ADMIN_NAME=$(prompt_tty "Admin display name" "Admin" "" NANO_ADMIN_NAME) || exit
    fi
    [[ -z "$ADMIN_NAME" ]]     && fail "Admin name is required."

    if [[ -z "$ADMIN_PASSWORD" && "${NANO_PREPARE_ONLY:-0}" == "1" ]]; then
        # The password is never written to .env, so a prepare run does not
        # ask for it: ./install.sh asks when it creates the account.
        :
    elif [[ -z "$ADMIN_PASSWORD" ]]; then
        prompt_admin_password
    fi
    [[ -z "$ADMIN_PASSWORD" ]] || validate_admin_password "$ADMIN_PASSWORD"

    # An explicit environment value makes the documented non-interactive
    # install path fully non-interactive.
    if [[ -n "${ANS_BASE_URL:-}" ]]; then
        BASE_URL=$ANS_BASE_URL
    elif [[ -z "${NANO_BASE_URL:-}" ]]; then
        prompt_base_url "$BASE_URL"
    else
        # A value pasted with a trailing space or saved with CRLF endings is
        # trimmed first, the same as a typed answer.
        BASE_URL=$(normalize_base_url "$(trim_space "$NANO_BASE_URL")") \
            || fail "NANO_BASE_URL must be http(s)://host[:port][/path] (got '$NANO_BASE_URL')."
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
    SCHEMA_PROFILE="${NANO_SCHEMA_PROFILE:-${ANS_SCHEMA:-}}"
    if [[ -z "$SCHEMA_PROFILE" ]] && ! have_controlling_tty; then
        # Fully non-interactive (no TTY): take the default rather than fail.
        SCHEMA_PROFILE=ocsf
    elif [[ -z "$SCHEMA_PROFILE" ]]; then
        while :; do
            SCHEMA_PROFILE=$(prompt_tty \
                "Schema profile — 'ocsf' (recommended), 'ocsf+tenzir' (OCSF + a bundled Tenzir node for direct ingestion), or 'udm' (legacy CIM-style)" "ocsf" "" NANO_SCHEMA_PROFILE) || exit
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
    # NAN-5506: an ocsf+tenzir pick made at the prompt (after the host-size
    # check) needs the Tenzir single node's floor; checked before .env exists.
    if [[ "$BUNDLE_TENZIR" == "1" && "$MULTI_NODE" != "1" && "${HM_ROLES:-}" != *,tenzir* ]]; then
        nano_host_minimums_gate "$NANO_HOST_SINGLE_NODE_ROLES,tenzir" "$PWD"
    fi

    # License: asked here, before anything is written, and fails closed for an
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
configure_egress_policy
configure_private_ai_endpoints
configure_ingest_ack_durability
configure_automatic_backups
configure_planned_volume
# NAN-5506: the recommended size for the planned volume (warning only), and a
# PLATFORM_FEEDS_AUTO_UPDATE given for this run (the host-size check honored
# it) kept in .env so later restarts and upgrades keep the feeds the same.
nano_host_minimums_recommend "$PLANNED_GB_PER_DAY" "$ROLE_ARG"
if [[ "${PLATFORM_FEEDS_AUTO_UPDATE:-}" =~ ^[A-Za-z0-9]+$ && "${MULTI_NODE:-0}" != "1" \
    && "$(env_value PLATFORM_FEEDS_AUTO_UPDATE)" != "$PLATFORM_FEEDS_AUTO_UPDATE" ]]; then
    nano_env_set_keys .env "PLATFORM_FEEDS_AUTO_UPDATE=$PLATFORM_FEEDS_AUTO_UPDATE" \
        || fail "Could not record PLATFORM_FEEDS_AUTO_UPDATE in .env."
    log "Recorded PLATFORM_FEEDS_AUTO_UPDATE=$PLATFORM_FEEDS_AUTO_UPDATE in .env"
fi
configure_retention_days
configure_detection_max_matches
configure_storage_tiering

# ----------------------------------------------------------------------------
# NAN-5361: Agent Lane listener (enterprise). A dedicated HTTPS ClickHouse
# listener for AI agents, off unless .env (single host) or the inventory (role
# split) turns it on with an allow-list. The port is published only after
# deploy/compose/agentlane/nano-agentlane-host (root) has loaded the matching
# firewall and staged the certificate; otherwise nothing is published.
# ----------------------------------------------------------------------------
AGENTLANE_OVERLAY=""
AGENTLANE_HELPER=deploy/compose/agentlane/nano-agentlane-host
agentlane_flag_on() {
    case "$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')" in
        1|true|yes|on) return 0 ;;
        *) return 1 ;;
    esac
}
# Add (add) or drop (remove) an installer-managed overlay in .env's
# NANO_COMPOSE_OVERLAYS, which scripts/nano and nano upgrade read; every other
# overlay the operator listed is kept as it was.
record_managed_overlay() {
    local overlay="$1" action="$2" current updated="" item
    current=$(env_value NANO_COMPOSE_OVERLAYS)
    for item in $current; do
        [[ "$item" == "$overlay" ]] || updated="${updated:+$updated }$item"
    done
    [[ "$action" == add ]] && updated="${updated:+$updated }$overlay"
    [[ "$updated" == "$current" ]] && return 0
    nano_env_set_keys .env "NANO_COMPOSE_OVERLAYS=$updated" \
        || fail "Could not record NANO_COMPOSE_OVERLAYS in .env."
}
agentlane_record_overlay() { record_managed_overlay docker-compose.agentlane.yml "$1"; }
# Withdraw a render the firewall does not match, so no later `docker compose
# up` (scripts/nano, nano upgrade, a manual restart) publishes a port or starts
# a listener this host's firewall does not guard: single host drops the
# overlay (and its NANO_COMPOSE_OVERLAYS entry), role split the listener file
# the renderer already wrote into the published config.d.
agentlane_unpublish() {
    if [[ "$MULTI_NODE" == "1" ]]; then
        rm -f .nano-generated/clickhouse/config.d/zz-agentlane-listener.xml
    else
        agentlane_record_overlay remove
        rm -f docker-compose.agentlane.yml
    fi
}
# Fail closed unless the root helper applied exactly this render's firewall
# and certificate. Root runs it directly; anyone else gets the command.
agentlane_require_applied() {
    local state
    state=$(bash "$AGENTLANE_HELPER" status "$NANO_INSTALL_DIR" 2>/dev/null) || true
    [[ "$state" == applied ]] && return 0
    if [[ "$(id -u)" == 0 ]]; then
        log "Applying the Agent Lane firewall and certificate (${state:-not-applied})"
        if ! bash "$AGENTLANE_HELPER" apply "$NANO_INSTALL_DIR"; then
            agentlane_unpublish
            fail "Agent Lane: nano-agentlane-host apply failed. The listener was not published."
        fi
        return 0
    fi
    agentlane_unpublish
    fail "Agent Lane is on, but this host's listener firewall is ${state:-not applied} (not-applied/stale: first run, or the allow-list, port or certificate paths changed; live-*: the live nftables table is missing or nano-agentlane-check.timer has not verified it in the last 2 minutes). Nothing was published. Run: sudo bash $NANO_INSTALL_DIR/$AGENTLANE_HELPER apply $NANO_INSTALL_DIR, then re-run install.sh (no root needed)."
}
agentlane_warn_leftover() {
    [[ -f /etc/nano/agentlane/applied.json ]] || return 0
    warn "Agent Lane is off, but this host still has its listener firewall and certificate. Remove them with: sudo bash $NANO_INSTALL_DIR/$AGENTLANE_HELPER remove"
}
configure_agentlane_single() {
    local summary enabled port bind public_url
    [[ "$MULTI_NODE" == "1" ]] && return 0
    if ! agentlane_flag_on "$(env_value NANO_AGENTLANE_LISTENER)"; then
        # Off (every install before v2.0.23): drop a previous render, if any.
        if [[ -f deploy/compose/agentlane.py || -f docker-compose.agentlane.yml ]]; then
            agentlane_record_overlay remove
            rm -f docker-compose.agentlane.yml
            rm -rf .nano-agentlane
            agentlane_warn_leftover
        fi
        return 0
    fi
    [[ "$NANO_EDITION" == enterprise ]] \
        || fail "NANO_AGENTLANE_LISTENER=true in .env, but Agent Lane is an enterprise feature and this install is the $NANO_EDITION edition. Remove it from .env."
    [[ -f deploy/compose/agentlane.py && -f "$AGENTLANE_HELPER" ]] \
        || fail "NANO_AGENTLANE_LISTENER=true, but this bundle has no Agent Lane listener files (deploy/compose/agentlane*). Use the enterprise bundle for v2.0.23 or later."
    command -v python3 >/dev/null 2>&1 || fail "The Agent Lane listener needs python3 on this host."
    summary=$(python3 -I deploy/compose/agentlane.py render-single --install-dir "$NANO_INSTALL_DIR" --env-file .env </dev/null) \
        || fail "Agent Lane listener settings in .env are invalid (above). Nothing was published."
    IFS=$'\t' read -r enabled port bind public_url < <(
        python3 -I -c 'import json,sys; v=json.loads(sys.argv[1]); print(v["enabled"], v.get("port",""), v.get("bind_address",""), v.get("public_url",""), sep="\t")' "$summary"
    )
    [[ "$enabled" == True ]] || fail "Agent Lane render did not enable the listener."
    agentlane_require_applied
    agentlane_record_overlay add
    AGENTLANE_OVERLAY=docker-compose.agentlane.yml
    ok "Agent Lane listener: https on ${bind}:${port}, allow-listed sources only (shown in Settings as $public_url)"
}
configure_agentlane_single

# NAN-5408: "your own Prometheus" on a single node. NANO_METRICS_BIND_ADDRESS
# (one of this host's own private IPv4 addresses; scripts/lib/metrics-bind.sh)
# turns on docker-compose.metrics-expose.yml: a /metrics-only edge publishing
# api, search, jobs, Vector, ClickHouse and node-exporter on that address. The
# overlay is recorded in NANO_COMPOSE_OVERLAYS so `nano` and `nano upgrade`
# keep it, and dropped again when the setting is removed. Everything is
# checked before anything is written to .env.
METRICS_EXPOSE_OVERLAY=""
configure_metrics_expose_single() {
    local overlay=docker-compose.metrics-expose.yml addr allow_public reason on_host
    addr=${NANO_METRICS_BIND_ADDRESS:-$(env_value NANO_METRICS_BIND_ADDRESS)}
    allow_public=${NANO_METRICS_ALLOW_PUBLIC:-$(env_value NANO_METRICS_ALLOW_PUBLIC)}
    if [[ "$MULTI_NODE" == "1" ]]; then
        [[ -z "$addr" ]] || warn "NANO_METRICS_BIND_ADDRESS is ignored on a role-split install: give a host the monitoring role instead (docs/administration/monitor-self-run.md, \"Your own Prometheus: several hosts\")."
        return 0
    fi
    if [[ -z "$addr" ]]; then
        if [[ " $(env_value NANO_COMPOSE_OVERLAYS) " == *" $overlay "* ]]; then
            record_managed_overlay "$overlay" remove
            # Undo the jobs widening this setting made, unless the monitoring
            # profile still scrapes jobs.
            if [[ "$(env_value NANO_JOBS_BIND_ADDR)" == 0.0.0.0 && ",$(env_value COMPOSE_PROFILES)," != *,monitoring,* ]]; then
                nano_env_set_keys .env "NANO_JOBS_BIND_ADDR=" \
                    || fail "Could not reset NANO_JOBS_BIND_ADDR in .env."
                log "Reset NANO_JOBS_BIND_ADDR (nano-jobs listens on loopback again)"
            fi
            log "NANO_METRICS_BIND_ADDRESS is not set: metrics are no longer published for an external Prometheus"
        fi
        return 0
    fi
    reason=$(nano_metrics_bind_error "$addr" "$allow_public") \
        || fail "NANO_METRICS_BIND_ADDRESS: $reason."
    on_host=0
    nano_metrics_bind_on_host "$addr" || on_host=$?
    case "$on_host" in
        0) ;;
        2) warn "Cannot list this host's addresses (no \`ip\` command); make sure NANO_METRICS_BIND_ADDRESS=$addr is one of them." ;;
        *) fail "NANO_METRICS_BIND_ADDRESS=$addr is not an address of this host (ip -4 -o addr show). Use the private address your Prometheus connects to." ;;
    esac
    if [[ -n "$(env_value NANO_METRICS_NODE_PORT)" ]]; then
        [[ "$(env_value NANO_METRICS_NODE_PORT)" =~ ^[1-9][0-9]{0,4}$ ]] && (( $(env_value NANO_METRICS_NODE_PORT) <= 65535 )) \
            || fail "NANO_METRICS_NODE_PORT must be a port number (1-65535)."
    fi
    compose_at_least_2_24_4 \
        || fail "NANO_METRICS_BIND_ADDRESS needs Docker Compose 2.24.4 or later (found ${compose_version:-unknown}). Update Docker Compose, or remove the setting."
    [[ -f "$overlay" && -f config/monitoring/metrics-edge.conf ]] \
        || fail "NANO_METRICS_BIND_ADDRESS is set, but this bundle has no $overlay. Use v2.0.25 or later."
    [[ -n "$(env_value NANO_SERVICE_TOKEN)" ]] \
        || fail "NANO_METRICS_BIND_ADDRESS is set, but NANO_SERVICE_TOKEN is missing from .env (the /metrics bearer token)."
    # Checked: persist what the installer was given, so a later plain `docker
    # compose up` (scripts/nano), which reads only .env, sees the same values.
    if [[ "$addr" != "$(env_value NANO_METRICS_BIND_ADDRESS)" ]]; then
        nano_env_set_keys .env "NANO_METRICS_BIND_ADDRESS=$addr" \
            || fail "Could not record NANO_METRICS_BIND_ADDRESS in .env."
    fi
    if [[ -n "${NANO_METRICS_ALLOW_PUBLIC:-}" && "$NANO_METRICS_ALLOW_PUBLIC" != "$(env_value NANO_METRICS_ALLOW_PUBLIC)" ]]; then
        nano_env_set_keys .env "NANO_METRICS_ALLOW_PUBLIC=$NANO_METRICS_ALLOW_PUBLIC" \
            || fail "Could not record NANO_METRICS_ALLOW_PUBLIC in .env."
    fi
    if [[ -z "$(env_value NANO_JOBS_BIND_ADDR)" ]]; then
        nano_env_set_keys .env "NANO_JOBS_BIND_ADDR=0.0.0.0" \
            || fail "Could not record NANO_JOBS_BIND_ADDR in .env."
        log "Persisted NANO_JOBS_BIND_ADDR=0.0.0.0 to .env (the metrics edge scrapes nano-jobs on the private Compose network)"
    fi
    record_managed_overlay "$overlay" add
    METRICS_EXPOSE_OVERLAY="$overlay"
    ok "Metrics for your own Prometheus: GET /metrics only, on ${addr} ports 3000 3002 3003 9598 9363 $(env_value NANO_METRICS_NODE_PORT | grep . || echo 9100). Limit them to your Prometheus with your firewall."
}
[[ -f scripts/lib/metrics-bind.sh ]] \
    || fail "scripts/lib/metrics-bind.sh not found in $NANO_INSTALL_DIR. The source tree or release bundle is incomplete."
# shellcheck source=scripts/lib/metrics-bind.sh
. scripts/lib/metrics-bind.sh
configure_metrics_expose_single

# Resolve overlays before sizing as well as startup: an overlay can replace the
# Vector data volume with a host bind/external driver, whose capacity cannot be
# inferred from DockerRootDir. Keeping one validated list prevents the sizing
# and runtime Compose graphs from disagreeing.
# NAN-5387 review: the overlays recorded in .env apply to a plain ./install.sh
# rerun too (scripts/nano and nano upgrade already read them), so the graph
# install.sh plans and starts is the customer's whole graph. The invoking
# environment still wins when it sets NANO_COMPOSE_OVERLAYS (even to "").
if [[ -n "${NANO_COMPOSE_OVERLAYS+set}" ]]; then
    read -r -a NANO_OVERLAY_LIST <<< "$NANO_COMPOSE_OVERLAYS"
else
    read -r -a NANO_OVERLAY_LIST <<< "$(env_value NANO_COMPOSE_OVERLAYS)"
fi
# NAN-5397: a host converted from the pre-v2 layout keeps
# docker-compose.legacy-preserved.yml, whose canonical config binds point at
# .nano-v2-control/<bundle sha>/ (frozen at the transition bundle; an old one
# also pins nginx.conf as a file). Drop those pins once the transition has
# settled so this release's config files reach the services.
if [[ "$MULTI_NODE" != "1" && " ${NANO_OVERLAY_LIST[*]-} " == *" docker-compose.legacy-preserved.yml "* \
    && -f scripts/lib/compose_stale_mounts.py ]]; then
    python3 -I scripts/lib/compose_stale_mounts.py --root "$NANO_INSTALL_DIR" \
        --prune-overlay docker-compose.legacy-preserved.yml </dev/null \
        || warn "Could not check docker-compose.legacy-preserved.yml for pinned config mounts."
fi
if [[ -n "$AGENTLANE_OVERLAY" && " ${NANO_OVERLAY_LIST[*]-} " != *" $AGENTLANE_OVERLAY "* ]]; then
    NANO_OVERLAY_LIST+=("$AGENTLANE_OVERLAY")
elif [[ -z "$AGENTLANE_OVERLAY" && " ${NANO_OVERLAY_LIST[*]-} " == *" docker-compose.agentlane.yml "* ]]; then
    fail "NANO_COMPOSE_OVERLAYS names docker-compose.agentlane.yml, but Agent Lane is off. install.sh manages that overlay: remove it from NANO_COMPOSE_OVERLAYS."
fi
if [[ -n "$METRICS_EXPOSE_OVERLAY" && " ${NANO_OVERLAY_LIST[*]-} " != *" $METRICS_EXPOSE_OVERLAY "* ]]; then
    NANO_OVERLAY_LIST+=("$METRICS_EXPOSE_OVERLAY")
elif [[ -z "$METRICS_EXPOSE_OVERLAY" && " ${NANO_OVERLAY_LIST[*]-} " == *" docker-compose.metrics-expose.yml "* ]]; then
    fail "NANO_COMPOSE_OVERLAYS names docker-compose.metrics-expose.yml, but NANO_METRICS_BIND_ADDRESS is not set. install.sh manages that overlay: set NANO_METRICS_BIND_ADDRESS in .env instead."
fi
for overlay in ${NANO_OVERLAY_LIST[@]+"${NANO_OVERLAY_LIST[@]}"}; do
    if [[ ! "$overlay" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*\.ya?ml$ ]]; then
        fail "NANO_COMPOSE_OVERLAYS: '$overlay' is not a compose file name in the install directory"
    fi
    [[ -f "$overlay" ]] || fail "NANO_COMPOSE_OVERLAYS: '$overlay' does not exist in $NANO_INSTALL_DIR"
done
# NAN-5508: an overlay list given to this run (the portal's TLS command sets
# docker-compose.tls.yml) is kept in .env, which a plain re-run, scripts/nano
# and nano upgrade read. Before, it applied to this run only and the next
# restart silently went back to plain HTTP.
# A converted pre-v2 host's docker-compose.legacy-preserved.yml stays recorded.
overlays_to_record="${NANO_OVERLAY_LIST[*]-}"
if [[ " $(env_value NANO_COMPOSE_OVERLAYS) " == *" docker-compose.legacy-preserved.yml "* \
    && " $overlays_to_record " != *" docker-compose.legacy-preserved.yml "* ]]; then
    overlays_to_record="docker-compose.legacy-preserved.yml${overlays_to_record:+ $overlays_to_record}"
fi
if [[ "$MULTI_NODE" != "1" && -n "${NANO_COMPOSE_OVERLAYS+set}" ]] \
    && [[ "$overlays_to_record" != "$(env_value NANO_COMPOSE_OVERLAYS)" ]]; then
    nano_env_set_keys .env "NANO_COMPOSE_OVERLAYS=$overlays_to_record" \
        || fail "Could not record NANO_COMPOSE_OVERLAYS in .env."
    log "Recorded NANO_COMPOSE_OVERLAYS=$overlays_to_record in .env; later runs, scripts/nano and upgrades keep it."
fi

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
    # NAN-5250: the optional monitoring profile keeps its fixed limits out of
    # the budget the nano services share.
    [[ ",$(env_value COMPOSE_PROFILES)," == *,monitoring,* ]] && sizing_roles+=,monitoring
    sizing_defaults=$(mktemp .nano-sizing.defaults.XXXXXX)
    # NAN-5822: the operator's own lines (below the managed block) count in
    # this pass, so a value derived from an overridden key (PostgreSQL's
    # shared_buffers, max_connections and pools from POSTGRES_MEM_LIMIT) is
    # written into the block Docker Compose reads, matching that override.
    sizing_operator_env=()
    [[ -f .env ]] && sizing_operator_env=(--operator-env .env)
    "$RESOURCE_SIZING" \
        --topology single \
        --roles "$sizing_roles" \
        --edition "$NANO_EDITION" \
        --shards 1 \
        --planned-gb-per-day "$PLANNED_GB_PER_DAY" \
        --ingest-path "$PLANNED_INGEST_PATH" \
        --avg-event-bytes "$PLANNED_AVG_EVENT_BYTES" \
        ${sizing_operator_env[@]+"${sizing_operator_env[@]}"} \
        --format env </dev/null > "$sizing_defaults" \
        || { rm -f "$sizing_defaults"; fail "Resource sizing refused this host (the reason is above). Nothing was started."; }

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
        --edition "$NANO_EDITION" \
        --shards 1 \
        --planned-gb-per-day "$PLANNED_GB_PER_DAY" \
        --ingest-path "$PLANNED_INGEST_PATH" \
        --avg-event-bytes "$PLANNED_AVG_EVENT_BYTES" \
        --override-env .env \
        --server-output .nano-generated/sizing/clickhouse-config.xml \
        --users-output .nano-generated/sizing/clickhouse-users.xml \
        --format env </dev/null > "$new_sizing_env" \
        || { rm -f "$new_sizing_env"; fail "Resource sizing refused these settings (the reason is above). Nothing was started."; }
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
    report_planned_ingest_capacity .nano-generated/sizing/host.env
    report_retention_fit .nano-generated/sizing/host.env
fi

# NAN-3322 / NAN-4909: the unauthenticated ingest ports (raw OTLP
# :4317/:4318, Fluent :24224, bundled Tenzir :9095) bind 127.0.0.1 unless the
# operator opts in. NAN-5515: Vector native :6000 is mutual-TLS only and binds
# the ingest interface; NANO_VECTOR_NATIVE_BIND_ADDRESS only narrows it. A
# bind override given to the installer must survive a later plain
# `docker compose up`, which reads only .env, so persist it there.
for key in NANO_VECTOR_NATIVE_BIND_ADDRESS NANO_VECTOR_NATIVE_SANS NANO_VECTOR_NATIVE_PUBLIC_HOST NANO_OTLP_BIND_ADDRESS NANO_FLUENT_BIND_ADDRESS NANO_TENZIR_BIND_ADDRESS; do
    if [[ -n "${!key:-}" ]]; then
        # Set in place (NAN-5251): re-runs used to append one more line each.
        nano_env_set_keys .env "$key=${!key}" || fail "Could not record $key in .env."
        case "$key" in
            NANO_VECTOR_NATIVE_*) log "Persisted $key=${!key} to .env (Vector native :6000, mutual TLS)" ;;
            *) log "Persisted $key=${!key} to .env (re-exposes an unauthenticated ingest port)" ;;
        esac
    fi
done

# NAN-5250: the single-node monitoring profile scrapes nano-jobs over the
# install's private Compose network, so jobs must leave loopback. Persist the
# widening once (an operator value in .env always wins); /metrics still needs
# NANO_SERVICE_TOKEN from every non-loopback caller.
if [[ "$MULTI_NODE" != "1" && ",$(env_value COMPOSE_PROFILES)," == *,monitoring,* \
      && -z "$(env_value NANO_JOBS_BIND_ADDR)" ]]; then
    nano_env_set_keys .env "NANO_JOBS_BIND_ADDR=0.0.0.0" \
        || fail "Could not record NANO_JOBS_BIND_ADDR in .env."
    log "Persisted NANO_JOBS_BIND_ADDR=0.0.0.0 to .env (monitoring profile scrapes nano-jobs)"
fi

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
    # NAN-5472: switching a ClickHouse host to cluster-secret-only must not
    # leave a peer that still sends (and so only accepts) password hops.
    if [[ ",$ROLE_ARG," == *,clickhouse,* ]]; then
        python3 -I deploy/compose/render-inventory.py --check-cluster-auth \
            --inventory "$INVENTORY_PATH" --roles "$ROLE_ARG" --override-env .env \
            </dev/null >&2 \
            || fail "The ClickHouse cluster secret check failed (see above). No services have started."
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
    # NAN-5361: a host the inventory gives the Agent Lane listener binds it
    # (host network) as soon as ClickHouse restarts with the rendered config,
    # so its firewall and certificate must be in place first.
    if [[ "${NANO_AGENTLANE_HOST:-}" == "true" ]]; then
        agentlane_require_applied
        ok "Agent Lane listener on this host: port ${NANO_AGENTLANE_PORT}, allow-listed sources only"
    elif [[ ",${ROLE_ARG}," == *,clickhouse,* ]]; then
        agentlane_warn_leftover
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
        nano_env_set_keys .env "NANO_DEPLOYMENT_IDENTITY_SHA256=$candidate_identity" \
            || fail "Could not record NANO_DEPLOYMENT_IDENTITY_SHA256 in .env."
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
    EDGE_PROBE_HOST=$(edge_probe_host "${NANO_CLUSTER_BIND_ADDRESS:-}")
    API_BASE="http://${EDGE_PROBE_HOST}:${HOST_PORT}"
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
        | grep -x clickhouse >/dev/null || return 0
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

# NAN-5387: nano's Compose network is pinned to one subnet, so ClickHouse's
# user network check admits that subnet instead of Docker's whole address pools
# (unconfigured, 172.16.0.0/12 AND 192.168.0.0/16: every host on a 192.168.x
# LAN). install.sh creates the network itself (scripts/lib/network-pin.sh): an
# existing install keeps the subnet it runs on, a fresh one takes the subnet
# Docker allocates next, recorded as NANO_COMPOSE_SUBNET. Every Compose command
# then reuses that network unchanged. Compose files that manage the network
# themselves (an IPAM subnet, an external or extra network) are left alone; the
# allow-list then stays the Docker pools plus their subnets, as before. Moving
# onto (or off) the pinned network happens right before the stack starts
# (nano_network_pin_apply below), never in a prepare-only run.
COMPOSE_SUBNET=""
NETWORK_PIN_ACTION=none
if [[ "$MULTI_NODE" != "1" && -r scripts/lib/network-pin.sh && -r scripts/lib/compose_network_pin.py ]]; then
    # shellcheck source=scripts/lib/network-pin.sh
    . scripts/lib/network-pin.sh
    nano_network_pin_plan "$(env_value NANO_COMPOSE_SUBNET)"
    if [[ -n "$NETWORK_PIN_SUBNET" ]]; then
        COMPOSE_SUBNET=$NETWORK_PIN_SUBNET
        [[ "$(env_value NANO_COMPOSE_SUBNET)" == "$COMPOSE_SUBNET" ]] \
            || nano_env_set_keys .env "NANO_COMPOSE_SUBNET=$COMPOSE_SUBNET" \
            || fail "Could not record NANO_COMPOSE_SUBNET in .env."
        log "nano's Compose network $NETWORK_PIN_NAME is pinned to $COMPOSE_SUBNET"
    else
        warn "nano's Compose network is not pinned (${NETWORK_PIN_REASON:-unknown reason}); ClickHouse keeps admitting Docker's address pools."
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
# Export the recorded profiles: the shell environment wins over .env, and
# .env may also carry the `backup` profile (NAN-5204).
COMPOSE_PROFILES_RECORDED=$(env_value COMPOSE_PROFILES)
if [[ "${BUNDLE_TENZIR:-0}" == "1" && ",$COMPOSE_PROFILES_RECORDED," != *",tenzir,"* ]]; then
    COMPOSE_PROFILES_RECORDED="${COMPOSE_PROFILES_RECORDED:+$COMPOSE_PROFILES_RECORDED,}tenzir"
fi
# NAN-5215: a role-split host takes its profiles from the rendered role env
# alone (roles plus app duties such as backup and pull-feeds). Exporting the
# .env value here would beat that file and, with only `backup` recorded,
# start nothing but the backup service on an app host.
if [[ "$MULTI_NODE" == "1" ]]; then
    unset COMPOSE_PROFILES
elif [[ -n "$COMPOSE_PROFILES_RECORDED" ]]; then
    export COMPOSE_PROFILES="$COMPOSE_PROFILES_RECORDED"
fi

# Record the resolved release + image source in .env (a re-run upgrades an
# existing install to this checkout's release) and export them, since the shell
# environment wins over .env during compose interpolation.
# Replace, never append: re-runs used to add a duplicate block each time, so
# .env grew and the copies on different hosts drifted apart. The rewrite is
# atomic and resolves a symlinked .env, which therefore stays a link.
nano_env_set_keys .env "NANO_EDITION=$NANO_EDITION" "NANO_VERSION=$NANO_VERSION" "NANO_IMAGE_PREFIX=$NANO_IMAGE_PREFIX" \
    || fail "Could not record NANO_EDITION/NANO_VERSION/NANO_IMAGE_PREFIX in .env."
export NANO_VERSION NANO_IMAGE_PREFIX

# NAN-5515: Vector native :6000 always requires mutual TLS. Two trust paths:
# a listener CA (verifies nano for senders; never rotated) and one small
# anchor CA per sender, bundled as the listener's client-ca.crt, so revoking a
# sender only removes its anchor. Single host: .nano-pki/vector-native holds
# the listener CA and the anchors (keys 0600, never in .env, never mounted into
# a container); config/vector-native (listener certificate re-issued when its
# SANs or the CA change, and the bundle) is mounted read-only into Vector.
# Role split: no CA key leaves the first app host. An ingest host's listener is
# the cluster's staged private TLS certificate (the cluster CA verifies it) and
# its bundle comes from the shared .env (NANO_VECTOR_NATIVE_CLIENT_ANCHORS,
# public certificates), so enabling it needs nothing beyond the existing TLS
# staging and .env distribution. Without cluster TLS (a plaintext lab) the
# listener is locked: it refuses every sender, never runs plaintext.
VECTOR_NATIVE_PKI_DIR=.nano-pki/vector-native
VECTOR_NATIVE_TLS_DIR=config/vector-native
VECTOR_NATIVE_STATE=""
VECTOR_NATIVE_CUTOVER=0
VECTOR_NATIVE_RESTART=0
VECTOR_NATIVE_RECENT_EVENTS=""
vector_native_recent_events() {
    # Best effort, read-only: events the running stack took on :6000 in the
    # last 24 h. Senders without a client certificate are refused from now on.
    local query count
    [[ "$MULTI_NODE" != "1" ]] || return 0
    docker compose "${COMPOSE_ARGS[@]}" ps --status running --services 2>/dev/null </dev/null \
        | grep -x clickhouse >/dev/null || return 0
    # NAN-5523: OCSF profiles (the default) store events in nanosiem.ocsf_logs.
    query=$(bash scripts/lib/vector-native-pki.sh events-query \
        --profile "$(env_value NANO_SCHEMA_PROFILE)" </dev/null 2>/dev/null) || return 0
    # The admin password is already in the ClickHouse container's environment;
    # it never appears on this host's command line.
    # shellcheck disable=SC2016
    count=$(docker compose "${COMPOSE_ARGS[@]}" exec -T clickhouse sh -c \
        'clickhouse-client --user nanosiem_admin --password "$CLICKHOUSE_ADMIN_PASSWORD" --query "$1"' \
        sh "$query" </dev/null 2>/dev/null) || return 0
    [[ "$count" =~ ^[0-9]+$ ]] && VECTOR_NATIVE_RECENT_EVENTS=$count
    return 0
}
# NAN-5526: did this host run the pre-mTLS (v2.0.29 or older) plaintext :6000
# listener? Only then is "port 6000 now REQUIRES mutual TLS" news. The .env
# records the release this install ran before this run; a role-split ingest
# host's .env is copied from the app host, so Vector state this host already
# has (the step runs before anything starts) also counts: a Vector container,
# or its data volume (it survives `docker compose down`). A fresh install (no
# .env, or a copied v2.0.30+ one, and no Vector container or volume) never.
vector_native_had_plaintext_listener() {
    local v=${PRE_RUN_NANO_VERSION:-}
    if [[ "$v" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
        if (( BASH_REMATCH[1] < 2 || (BASH_REMATCH[1] == 2 && BASH_REMATCH[2] == 0 && BASH_REMATCH[3] < 30) )); then
            return 0
        fi
    elif [[ "${REUSE_ENV:-0}" == "1" ]]; then
        # A reused .env without a release recorded predates the key.
        return 0
    fi
    docker compose "${COMPOSE_ARGS[@]}" ps -a --services 2>/dev/null </dev/null | grep -x vector >/dev/null \
        || docker volume ls -q --filter label=com.docker.compose.volume=nano-vector-data 2>/dev/null </dev/null \
            | grep . >/dev/null
}
vector_native_pki_step() {
    local had=0 anchor_count result bind status=0 new_ca_args=() san_args=() sans_env expiring line
    [[ -r scripts/lib/vector-native-pki.sh ]] \
        || fail "scripts/lib/vector-native-pki.sh not found in $NANO_INSTALL_DIR. The source tree or release bundle is incomplete."
    if [[ "$MULTI_NODE" == "1" ]]; then
        # Vector runs on ingest hosts only.
        [[ ",${ROLE_ARG}," == *,ingest,* ]] || return 0
        [[ -s "$VECTOR_NATIVE_TLS_DIR/client-ca.crt" ]] && had=1
        result=$(bash scripts/lib/vector-native-pki.sh ensure-ingest \
            --tls-dir "$VECTOR_NATIVE_TLS_DIR" --env-file .env </dev/null) \
            || fail "Could not prepare the Vector-native sender anchors in $NANO_INSTALL_DIR/$VECTOR_NATIVE_TLS_DIR (above). Nothing was started."
        VECTOR_NATIVE_STATE=$result
        if [[ "$had" == 0 ]] && vector_native_had_plaintext_listener; then
            VECTOR_NATIVE_CUTOVER=1
        fi
        [[ "$result" != *changed=1* || "$had" == 0 ]] || VECTOR_NATIVE_RESTART=1
        if [[ "${NANO_PRIVATE_TLS:-}" != "true" ]]; then
            VECTOR_NATIVE_STATE="$result server=locked"
            warn "Vector native :6000 is locked on this host (refuses every sender): this cluster has no private TLS, and the listener certificate is the cluster's TLS certificate. Plaintext lab clusters have no Vector-native listener."
        else
            # ensure-ingest prints `anchors=<count> changed=<0|1>`.
            anchor_count=${result%% *}
            anchor_count=${anchor_count#anchors=}
            if [[ "$anchor_count" == 1 ]]; then
                ok "Vector native :6000: mutual TLS with the cluster certificate; 1 sender anchor from the shared .env"
            else
                ok "Vector native :6000: mutual TLS with the cluster certificate; $anchor_count sender anchors from the shared .env"
            fi
        fi
        return 0
    fi
    [[ -s "$VECTOR_NATIVE_TLS_DIR/server.crt" ]] && had=1
    if [[ "$had" == 0 ]] && vector_native_had_plaintext_listener; then
        VECTOR_NATIVE_CUTOVER=1
        vector_native_recent_events
    fi
    # A specific bind address is one senders connect to (a wildcard adds
    # nothing). Same rule as scripts/nano-upgrade.py.
    bind=${NANO_VECTOR_NATIVE_BIND_ADDRESS:-$(env_value NANO_VECTOR_NATIVE_BIND_ADDRESS)}
    [[ -z "$bind" ]] || san_args+=(--san "$bind")
    [[ "${NANO_VECTOR_NATIVE_NEW_CA:-0}" != "1" ]] || new_ca_args=(--new-ca)
    sans_env=${NANO_VECTOR_NATIVE_SANS:-$(env_value NANO_VECTOR_NATIVE_SANS)}
    result=$(NANO_VECTOR_NATIVE_SANS="$sans_env" bash scripts/lib/vector-native-pki.sh ensure \
        --pki-dir "$VECTOR_NATIVE_PKI_DIR" --tls-dir "$VECTOR_NATIVE_TLS_DIR" \
        --base-url "$BASE_URL" "${new_ca_args[@]}" "${san_args[@]}" </dev/null) || status=$?
    if [[ "$status" == 3 ]]; then
        fail "The Vector-native listener CA is missing but this install already issued certificates (above). Restore $VECTOR_NATIVE_PKI_DIR from a backup (scripts/nano restore), or re-run with NANO_VECTOR_NATIVE_NEW_CA=1 to start over (every sender then needs a new certificate). Nothing was started."
    elif [[ "$status" != 0 ]]; then
        fail "Could not prepare the Vector-native TLS files in $NANO_INSTALL_DIR/$VECTOR_NATIVE_TLS_DIR (above). Nothing was started."
    fi
    VECTOR_NATIVE_STATE=$result
    if [[ "$had" == 1 && ( "$result" == *server=issued* || "$result" == *anchors=changed* ) ]]; then
        VECTOR_NATIVE_RESTART=1
    fi
    [[ "$result" != *server=issued* ]] \
        || ok "Vector native :6000 listener certificate issued (mutual TLS; SANs in $VECTOR_NATIVE_TLS_DIR/.sans)"
    expiring=$(bash scripts/lib/vector-native-pki.sh expiring --pki-dir "$VECTOR_NATIVE_PKI_DIR" \
        --tls-dir "$VECTOR_NATIVE_TLS_DIR" </dev/null 2>/dev/null) || expiring=""
    while IFS= read -r line; do
        [[ -z "$line" ]] || warn "$line"
    done <<< "$expiring"
}
vector_native_pki_step

# NAN-5559: the legacy cutover for Vector-to-Vector senders. A 0.1.x :6000
# listener was plaintext; from here it is mutual TLS only. When the 0.1.x
# Vector took :6000 traffic (legacy_vector_native_probe) or the operator named
# the senders, one client certificate bundle per sender is issued now, before
# the stack starts (the listener then starts with every new anchor, so no
# restart): <install>/vector-client-bundles/<name>/ (0700, files 0600) with
# vector-sink.toml, the sender's sink config with a disk buffer. Bundles
# staged before the window (vector-native-pki.sh bundle --ensure on the 0.1.x
# host) are kept, not re-issued.
#
# HOOK (NAN-5559, pending the live check that it reproduces 0.1.702 routing):
# 0.1.x routed every :6000 event on the source_type its sender declared; 2.x
# routes them all to the fixed `vector_native` source unless
# NANO_VECTOR_NATIVE_TRUST_SOURCE_TYPE=true. Only a sender holding a client
# certificate from this install can connect now, so an upgraded install with
# :6000 senders keeps trusting the declared type and those events keep reaching
# the parsers they reached on 0.1.x. An explicit
# NANO_VECTOR_NATIVE_TRUST_SOURCE_TYPE already in .env is never changed;
# NANO_LEGACY_VECTOR_NATIVE_TRUST_SOURCE_TYPE=false skips this.
LEGACY_VN_TRUST_SOURCE_TYPE="${NANO_LEGACY_VECTOR_NATIVE_TRUST_SOURCE_TYPE:-true}"
LEGACY_VN_TRUST_SET=0
LEGACY_VN_BUNDLES=""
LEGACY_VN_BUNDLE_FAILED=0
legacy_vector_native_cutover() {
    local senders out status=0 kind name dir
    local -a names=()
    [[ "$LEGACY_UPGRADE" == 1 || "$LEGACY_SUMMARY" == 1 ]] || return 0
    [[ "$MULTI_NODE" != "1" ]] || return 0
    senders=$LEGACY_VN_SENDERS
    if [[ -n "${NANO_VECTOR_NATIVE_SENDERS:-}" ]]; then
        senders=$(legacy_vector_native_names "$NANO_VECTOR_NATIVE_SENDERS") \
            || fail "NANO_VECTOR_NATIVE_SENDERS='$NANO_VECTOR_NATIVE_SENDERS' is not a list of sender names (1-63 letters, digits, dots, underscores or hyphens each, separated by commas). Nothing was started."
        LEGACY_VN_SENDERS=$senders
    fi
    [[ "$LEGACY_VN_USED" == 1 || -n "$senders" ]] || return 0
    if [[ "$LEGACY_VN_TRUST_SOURCE_TYPE" == true ]] && ! grep -q '^NANO_VECTOR_NATIVE_TRUST_SOURCE_TYPE=' .env; then
        nano_env_set_keys .env "NANO_VECTOR_NATIVE_TRUST_SOURCE_TYPE=true" \
            || fail "Could not record NANO_VECTOR_NATIVE_TRUST_SOURCE_TYPE in .env."
        LEGACY_VN_TRUST_SET=1
        log "Set NANO_VECTOR_NATIVE_TRUST_SOURCE_TYPE=true in .env: port 6000 now admits only senders with a client certificate from this install, so their declared source_type keeps routing their events to the same parsers as on 0.1.x."
    fi
    [[ -n "$senders" ]] || return 0
    [[ -r scripts/lib/vector-native-pki.sh ]] \
        || fail "scripts/lib/vector-native-pki.sh not found in $NANO_INSTALL_DIR. The source tree or release bundle is incomplete."
    read -r -a names <<< "${senders//,/ }"
    out=$(bash scripts/lib/vector-native-pki.sh bundle --install-dir "$NANO_INSTALL_DIR" "${names[@]}" </dev/null) || status=$?
    while read -r kind name dir; do
        [[ "$kind" == bundle && -n "$dir" ]] || continue
        LEGACY_VN_BUNDLES+="$name $dir"$'\n'
        ok "Vector-native client certificate bundle for '$name': $dir (sink config: $dir/vector-sink.toml)"
    done <<< "$out"
    if [[ "$status" != 0 ]]; then
        LEGACY_VN_BUNDLE_FAILED=1
        warn "Not every Vector-native client certificate bundle could be issued (above). After the upgrade, per missing sender: cd $NANO_INSTALL_DIR && scripts/nano vector-client-cert <name> --out $NANO_INSTALL_DIR/vector-client-bundles/<name>"
    fi
    return 0
}
legacy_vector_native_cutover

if [[ "${NANO_PREPARE_ONLY:-0}" == "1" ]]; then
    ok "Prepared .env and role configuration without pulling the application stack or starting services (the pinned Vector image may be cached/pulled for the storage-capacity probe)"
    if [[ "$MULTI_NODE" == "1" ]]; then
        printf 'Securely copy %s/.env and %s to every inventory host, then install the data roles before the app role.\n' \
            "$NANO_INSTALL_DIR" "$INVENTORY_PATH"
    fi
    exit 0
fi

# NAN-5411: tenzir/pipeline.tql is meant to be edited (see the summary at the
# end), and extracting a release package over the install directory replaces
# it. The running Tenzir node still reads the operator's version until it is
# recreated below (a new image, or the stale-mount recreate), so check now:
# an edited pipeline the package replaced is saved to tenzir/pipeline.tql.bak
# and the install stops once, before anything is pulled or restarted.
if [[ -f scripts/lib/compose_stale_mounts.py ]]; then
    tenzir_container=$(docker compose "${COMPOSE_ARGS[@]}" ps -q tenzir </dev/null 2>/dev/null || true)
    if [[ -n "$tenzir_container" ]]; then
        python3 -I scripts/lib/compose_stale_mounts.py --root "$NANO_INSTALL_DIR" \
            --guard-tenzir-pipeline "$tenzir_container" </dev/null \
            || fail "Stopped before replacing your edited Tenzir pipeline (see above). Nothing has been pulled or restarted."
    fi
fi

ACTIVE_IMAGES=$(docker compose "${COMPOSE_ARGS[@]}" config --images </dev/null)

# NAN-5509: the host ports this graph publishes (overlays and profiles
# included). A port another process holds failed `up` after the whole pull,
# and nginx's :80 only after the migrations. Also feeds the summary's firewall
# line. NANO_SKIP_PORT_CHECK=1 skips the in-use check.
# The early check before the questions saw only the base graph; this one
# covers the overlays and profiles the answers chose.
PUBLISHED_PORTS=""
if [[ "$MULTI_NODE" != "1" ]]; then
    rendered_config=$(docker compose "${COMPOSE_ARGS[@]}" config --format json </dev/null 2>/dev/null) || rendered_config=""
    PUBLISHED_PORTS=$(printf '%s' "$rendered_config" | nano_published_ports 2>/dev/null) || PUBLISHED_PORTS=""
    fail_on_port_conflicts "$rendered_config" "$PUBLISHED_PORTS" "Nothing was pulled or started."
fi

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
# NAN-5505: enterprise images are in a private registry. Right before the
# pull (the license credential lasts one hour), log docker in with a credential
# from the license API, unless every private image is already local at its pin
# or this host's own docker login already reads the registry. Offline and
# air-gapped installs never call the API.
REGISTRY_LICENSE_MODE="" REGISTRY_LOGIN_FAILED=0
# NAN-5524: a login this run made lives in a private, temporary docker config
# (never the user's ~/.docker; scripts/lib/image-pull.sh) and is not needed
# once the images are local (every later run or upgrade gets a fresh one).
# Drop it right after the pull; the EXIT trap (cleanup_env_temp) also drops
# it on every failure and on an interrupt. No `docker logout`: that would
# delete a customer's own entry for the registry.
registry_forget_ours() {
    if [[ -n "${NANO_REGISTRY_LOGGED_IN_AT:-}" ]]; then
        log "Dropped this run's registry pull credential"
    fi
    nano_registry_cleanup
}
if [[ "$NANO_EDITION" == "enterprise" ]]; then
    REGISTRY_LICENSE_MODE="${LICENSE_MODE:-$(env_value NANO_LICENSE_MODE)}"
    if [[ "$REGISTRY_LICENSE_MODE" != offline && "$REGISTRY_LICENSE_MODE" != airgap ]] \
        && is_truthy "${AIRGAP_MODE:-$(env_value AIRGAP_MODE)}"; then
        REGISTRY_LICENSE_MODE=airgap
    fi
    # Read by nano_registry_login_if_needed (scripts/lib/image-pull.sh); not
    # exported, so the token stays out of every child's environment.
    # shellcheck disable=SC2034
    NANO_REGISTRY_LICENSE_MODE="$REGISTRY_LICENSE_MODE"
    while :; do
        # shellcheck disable=SC2034
        NANO_REGISTRY_LICENSE_URL="$(env_value LICENSE_URL)"
        NANO_REGISTRY_LICENSE_TOKEN="$(env_value LICENSE_TOKEN)"
        [[ -n "$NANO_REGISTRY_LICENSE_TOKEN" ]] || NANO_REGISTRY_LICENSE_TOKEN="$(env_value DEPLOYMENT_TOKEN)"
        # shellcheck disable=SC2034
        NANO_REGISTRY_DEPLOYMENT_ID="$(env_value NANO_DEPLOYMENT_ID)"
        # shellcheck disable=SC2034
        NANO_REGISTRY_PROXY="$(env_value HTTPS_PROXY)"
        REGISTRY_LOGIN_FAILED=0
        NANO_PULL_LOCK="$NANO_PULL_LOCK" NANO_PULL_TRUST_TAGS="${NANO_SKIP_IMAGE_VERIFY:-0}" \
            nano_registry_login_if_needed "$ACTIVE_IMAGES" || REGISTRY_LOGIN_FAILED=1
        # NAN-5508: the license values typed at this run's prompts were first
        # used just now (the check-in needs the network). On a terminal, a
        # refusal asks them again instead of ending the install.
        [[ "$REGISTRY_LOGIN_FAILED" == 1 && "${WANT_license:-0}" == 1 && "${ANS_LIC_MODE:-}" == online ]] \
            && have_controlling_tty || break
        answer_yes_no "Enter the license values again? (n stops here; nothing has started)" true || ANSWER_REPLY=true
        [[ "$ANSWER_REPLY" == true ]] || break
        answer_run_steps "$(answer_step_index lic_url)" "$(answer_step_index lic_id)"
        LICENSE_MODE=online LICENSE_DEPLOYMENT_ID="$ANS_LIC_ID"
        LICENSE_ENV_LINES="LICENSE_URL=$ANS_LIC_URL"$'\n'"LICENSE_TOKEN=$ANS_LIC_TOKEN"$'\n'"NANO_DEPLOYMENT_ID=$ANS_LIC_ID"$'\n'
        record_license .env
    done
    if [[ "$REGISTRY_LOGIN_FAILED" == 1 ]]; then
        registry_forget_ours
        fail "Could not get a registry pull credential from the license API (see above). Nothing was pulled or restarted."
    fi
fi
# NANO_SKIP_IMAGE_VERIFY=1 is the escape hatch for a store whose digest
# readback is unusable; presence then falls back to a plain inspect.
if ! NANO_PULL_LOCK="$NANO_PULL_LOCK" NANO_PULL_TRUST_TAGS="${NANO_SKIP_IMAGE_VERIFY:-0}" \
    nano_pull_images "$ACTIVE_IMAGES"; then
    registry_forget_ours
    if [[ "$NANO_EDITION" == "enterprise" ]]; then
        case "$REGISTRY_LICENSE_MODE" in
            offline|airgap)
                fail "Image pull failed. Enterprise images are in a private registry and this install's license is $REGISTRY_LICENSE_MODE, so the installer does not request a pull credential. Either load the offline image bundle first (scripts/nano bundle load <nano-enterprise images bundle>), or log in with a registry pull credential from app.nano.rs: docker login ${NANO_IMAGE_PREFIX%%/*} -u oauth2accesstoken --password-stdin (paste it, then Ctrl-D; it lasts about an hour). Run docker login as the same user that runs install.sh, not with sudo: root's docker login is not this user's. Then re-run." ;;
            *)
                fail "Image pull failed (see above). Enterprise images are in a private registry. With an online license (LICENSE_TOKEN and NANO_DEPLOYMENT_ID in .env) the installer logs in with a one-hour credential from the license API before pulling; without one, log in with a registry pull credential from app.nano.rs (docker login ${NANO_IMAGE_PREFIX%%/*} -u oauth2accesstoken --password-stdin, as the same user that runs install.sh, not with sudo) or load the offline image bundle (scripts/nano bundle load). Then re-run." ;;
        esac
    fi
    fail "Image pull failed (see above). The open edition's images are public on ghcr.io and Docker Hub, so this is usually the network: check that this host reaches ghcr.io and registry-1.docker.io (DNS, firewall, proxy). For Docker Hub rate limits (429 / toomanyrequests), run docker login as the same user that runs install.sh (not with sudo), then re-run."
fi

registry_forget_ours

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

# NAN-5213: scaling a role-split cluster from one app host to several moves
# its Valkey from that app host to the shared one beside PostgreSQL. Carry the
# JWT revocation denylist across, so an access token revoked in the last 15
# minutes (logout) is not valid again after the move. Everything else in
# Valkey is transient (search jobs, admission leases).
VALKEY_REVOCATIONS_FILE=""
if [[ "$MULTI_NODE" == "1" && ",${ROLE_ARG}," == *,app,* && "${NANO_LOCAL_VALKEY_REPLICAS:-1}" == "0" ]] \
    && [[ -n "$(docker compose "${COMPOSE_ARGS[@]}" ps -q --status running dragonfly 2>/dev/null </dev/null)" ]]; then
    VALKEY_REVOCATIONS_FILE=$(mktemp "${TMPDIR:-/tmp}/nano-valkey-revocations.XXXXXX")
    chmod 600 "$VALKEY_REVOCATIONS_FILE"
    log "Saving the JWT revocation denylist from this host's Valkey before moving to the shared Valkey"
    # shellcheck disable=SC2016
    docker compose "${COMPOSE_ARGS[@]}" exec -T dragonfly sh -ec '
        valkey-cli --scan --pattern "auth:revoked_jti:*" | while IFS= read -r key; do
            ttl=$(valkey-cli PTTL "$key")
            value=$(valkey-cli --raw GET "$key")
            [ "$ttl" -gt 0 ] 2>/dev/null && printf "%s %s %s\n" "$key" "$value" "$ttl"
        done' </dev/null > "$VALKEY_REVOCATIONS_FILE" \
        || warn "Could not read the local Valkey revocation denylist; tokens revoked in the last 15 minutes stay valid until they expire."
fi

# NAN-5214: the shared Valkey endpoint on an app host is the Sentinel-routed
# HAProxy with two or more postgres hosts, otherwise NAN-5213's nginx proxy.
# Decided from the rendered role env (exported above), not COMPOSE_PROFILES,
# which this script rewrites/unsets for the backup-profile merge.
# nano-valkey-endpoint:begin
VALKEY_SHARED_ENDPOINT=valkey-proxy
[[ -n "${NANO_VALKEY_SENTINELS:-}" ]] && VALKEY_SHARED_ENDPOINT=valkey-router
# nano-valkey-endpoint:end

# NAN-5214: with two or more postgres hosts the Patroni member owns this
# host's PostgreSQL data volume. Stop and remove the standalone container
# first (a single-postgres install converting to HA), so two postmasters
# can never run on one data directory. The member then adopts the data
# directory in place (first postgres host) or clones from the leader.
if [[ "$MULTI_NODE" == "1" && "${NANO_POSTGRES_HA:-false}" == "true" && ",${ROLE_ARG}," == *,postgres,* ]]; then
    if [[ -n "$(docker compose "${COMPOSE_ARGS[@]}" ps -aq postgres 2>/dev/null </dev/null)" ]]; then
        log "PostgreSQL HA: stopping the standalone PostgreSQL container; Patroni takes over its data volume"
        docker compose "${COMPOSE_ARGS[@]}" stop --timeout 120 postgres </dev/null \
            || fail "Could not stop the standalone PostgreSQL container cleanly; refusing to start Patroni on its data volume."
        docker compose "${COMPOSE_ARGS[@]}" rm -f postgres </dev/null >/dev/null
    fi
fi

# NAN-5263: the rerun below recreates this host's Patroni member. When it is
# the LEADER, move leadership to a healthy standby first (a planned switchover
# of about a second) instead of costing the cluster a failover (the 20 s
# leader timeout plus promotion). A leader with no healthy standby (the first
# postgres host before the others join) is recreated as before.
if [[ "$MULTI_NODE" == "1" && "${NANO_POSTGRES_HA:-false}" == "true" && ",${ROLE_ARG}," == *,postgres,* \
        && -n "${NANO_HOST_ID:-}" \
        && -n "$(docker compose "${COMPOSE_ARGS[@]}" ps -q --status running postgres-ha 2>/dev/null </dev/null)" ]]; then
    pg_leader_plan=$(docker compose "${COMPOSE_ARGS[@]}" exec -T postgres-ha \
            patronictl -c /run/patroni/patroni.yml list -f json 2>/dev/null </dev/null \
        | python3 -I scripts/lib/pg_ha_leader_guard.py "$NANO_HOST_ID" 2>/dev/null) || pg_leader_plan=""
    case "$pg_leader_plan" in
        "switch "*)
            pg_candidate=${pg_leader_plan#switch }
            log "This host's PostgreSQL member ($NANO_HOST_ID) is the leader: switching over to $pg_candidate before recreating it"
            docker compose "${COMPOSE_ARGS[@]}" exec -T postgres-ha patronictl -c /run/patroni/patroni.yml \
                    switchover --leader "$NANO_HOST_ID" --candidate "$pg_candidate" --force </dev/null >/dev/null \
                || fail "PostgreSQL switchover from $NANO_HOST_ID to $pg_candidate failed; nothing was recreated. Check 'patronictl list' and retry."
            switch_deadline=$(( $(date +%s) + 90 ))
            pg_leader_plan=""
            while (( $(date +%s) < switch_deadline )); do
                pg_leader_plan=$(docker compose "${COMPOSE_ARGS[@]}" exec -T postgres-ha \
                        patronictl -c /run/patroni/patroni.yml list -f json 2>/dev/null </dev/null \
                    | python3 -I scripts/lib/pg_ha_leader_guard.py "$NANO_HOST_ID" 2>/dev/null) || pg_leader_plan=""
                [[ "$pg_leader_plan" == keep ]] && break
                sleep 2
            done
            [[ "$pg_leader_plan" == keep ]] \
                || fail "PostgreSQL leadership did not move off $NANO_HOST_ID within 90 s; nothing was recreated. Check 'patronictl list' before retrying."
            ok "PostgreSQL leader moved to $pg_candidate" ;;
        alone)
            warn "This host's PostgreSQL member ($NANO_HOST_ID) is the leader and no healthy streaming standby is available for a planned switchover. Recreating it stops the leader unplanned: Patroni fails over to another member if one is eligible (about 20-25 s of failed writes), otherwise writes pause until this member is back." ;;
        keep) ;;
        *)
            warn "Could not read the Patroni member list on this host; if its member is the leader, recreating it costs a failover (about 20-25 s of failed writes). Check 'patronictl list' and switch over first if needed." ;;
    esac
fi

# NAN-5367: ClickHouse users accept connections only from the networks the
# Compose stack runs on. Render the per-user <networks> override from the
# subnet nano's network is pinned to (NAN-5387, above) or, when nothing is
# pinned, the Docker address pools the Compose network is allocated from
# (stable across `docker compose down && up`, unlike the network's current
# subnet); plus the current subnet when a custom IPAM config placed it elsewhere. An external
# direct-OCSF writer (Tenzir/Cribl on another host) is admitted as
# nanosiem_ingest only, through NANO_CLICKHOUSE_INGEST_ALLOWED_NETWORKS.
# Role-split hosts get theirs from render-inventory.py instead.
if [[ "$MULTI_NODE" != "1" ]]; then
    ch_ingest_networks=${NANO_CLICKHOUSE_INGEST_ALLOWED_NETWORKS:-$(env_value NANO_CLICKHOUSE_INGEST_ALLOWED_NETWORKS)}
fi
if [[ "$MULTI_NODE" != "1" ]] \
    && { [[ ! -r scripts/lib/clickhouse_networks.py || ! -r clickhouse/users.d/nanosiem-users.xml \
        || ! -r clickhouse/workload-users/nanosiem-workload-users.xml ]]; }; then
    # A partial tree (tests, a hand-copied install): the checked-in
    # loopback + private-range lists apply. Never an any-address fallback.
    [[ -z "$ch_ingest_networks" ]] \
        || fail "NANO_CLICKHOUSE_INGEST_ALLOWED_NETWORKS is set but scripts/lib/clickhouse_networks.py or clickhouse/users.d/nanosiem-users.xml is missing from $NANO_INSTALL_DIR."
    warn "scripts/lib/clickhouse_networks.py or clickhouse/users.d is missing; ClickHouse users keep the built-in loopback + private-network lists."
elif [[ "$MULTI_NODE" != "1" ]]; then
    # The Docker inputs (address pools, ClickHouse's live subnets, the
    # effective Compose config's IPAM subnets) are read by the renderer, the
    # same way `scripts/nano upgrade` renders this list (NAN-5435).
    python3 -I scripts/lib/clickhouse_networks.py \
        --users-xml clickhouse/users.d/nanosiem-users.xml \
        --output .nano-generated/clickhouse/networks.xml \
        --workload-template clickhouse/workload-users/nanosiem-workload-users.xml \
        --workload-env-file .env --users-dir-output .nano-generated/clickhouse/users.d \
        --compose-subnet "${COMPOSE_SUBNET:-}" \
        --ingest-networks "$ch_ingest_networks" \
        --from-docker -- "${COMPOSE_ARGS[@]}" </dev/null >/dev/null \
        || fail "Could not render the ClickHouse network allow-list (NANO_CLICKHOUSE_INGEST_ALLOWED_NETWORKS='$ch_ingest_networks')."
    if [[ -n "${NANO_CLICKHOUSE_INGEST_ALLOWED_NETWORKS:-}" ]]; then
        nano_env_set_keys .env "NANO_CLICKHOUSE_INGEST_ALLOWED_NETWORKS=$NANO_CLICKHOUSE_INGEST_ALLOWED_NETWORKS" \
            || fail "Could not record NANO_CLICKHOUSE_INGEST_ALLOWED_NETWORKS in .env."
    fi
    [[ "$(env_value NANO_CLICKHOUSE_NETWORKS_FILE)" == "./.nano-generated/clickhouse/networks.xml" ]] \
        || nano_env_set_keys .env "NANO_CLICKHOUSE_NETWORKS_FILE=./.nano-generated/clickhouse/networks.xml" \
        || fail "Could not record NANO_CLICKHOUSE_NETWORKS_FILE in .env."
    # NAN-5470: the rendered users.d (shipped users + the workload identities
    # with password_sha256_hex), outside every installer package so an
    # extract never changes the users ClickHouse runs.
    [[ "$(env_value NANO_CLICKHOUSE_USERS_DIR)" == "./.nano-generated/clickhouse/users.d" ]] \
        || nano_env_set_keys .env "NANO_CLICKHOUSE_USERS_DIR=./.nano-generated/clickhouse/users.d" \
        || fail "Could not record NANO_CLICKHOUSE_USERS_DIR in .env."
    log "ClickHouse users accept connections from loopback and ${COMPOSE_SUBNET:-the Docker networks} only${ch_ingest_networks:+ (nanosiem_ingest also from $ch_ingest_networks)}"
    # NAN-5361: that lock is what refuses nano's own users on the Agent Lane
    # port, so an Agent Lane allow-list must not overlap it.
    if [[ -n "$AGENTLANE_OVERLAY" ]] \
        && ! python3 -I deploy/compose/agentlane.py check-networks --env-file .env \
            --networks-xml .nano-generated/clickhouse/networks.xml </dev/null; then
        agentlane_unpublish
        fail "Agent Lane was not published (above). Nothing was started."
    fi
fi

# NAN-5445: render ClickHouse storage tiering (config.d/zzz-nano-tiering.xml)
# from the NANO_TIERING* keys. The file's digest goes into .env as
# NANO_TIERING_CONFIG_SHA256, which the clickhouse service carries in its
# environment: a changed tiering config changes the service definition, so the
# `up` below recreates ClickHouse before clickhouse-migrate runs and switches
# the event tables to the policy. Once a table uses nano_tiered the renderer
# refuses to drop the policy (ClickHouse would not start); pause with
# NANO_TIERING_MOVE_FACTOR=0 instead. Role-split hosts get theirs from
# render-inventory.py.
if [[ "$MULTI_NODE" != "1" && "$NANO_EDITION" == enterprise && -f scripts/lib/clickhouse_tiering.py ]]; then
    mkdir -p .nano-generated/clickhouse
    tiering_render=$(python3 -I scripts/lib/clickhouse_tiering.py render --env-file .env \
        --output .nano-generated/clickhouse/tiering.xml </dev/null) \
        || fail "Could not render the ClickHouse storage tiering config (above). Nothing was started."
    tiering_state=$(sed -n 's/^state=//p' <<<"$tiering_render")
    tiering_sha=$(sed -n 's/^sha256=//p' <<<"$tiering_render")
    # NAN-5509: settings this run turns on or changes (vs. the last recorded
    # render) must prove the store works now; an unchanged one only warns.
    tiering_prev_sha=$(env_value NANO_TIERING_CONFIG_SHA256)
    [[ "$(env_value NANO_CLICKHOUSE_TIERING_FILE)" == "./.nano-generated/clickhouse/tiering.xml" ]] \
        || nano_env_set_keys .env "NANO_CLICKHOUSE_TIERING_FILE=./.nano-generated/clickhouse/tiering.xml" \
        || fail "Could not record NANO_CLICKHOUSE_TIERING_FILE in .env."
    [[ "$(env_value NANO_TIERING_CONFIG_SHA256)" == "$tiering_sha" ]] \
        || nano_env_set_keys .env "NANO_TIERING_CONFIG_SHA256=$tiering_sha" \
        || fail "Could not record NANO_TIERING_CONFIG_SHA256 in .env."
    if [[ "$tiering_state" == "active" ]]; then
        python3 -I scripts/lib/clickhouse_tiering.py check --env-file .env </dev/null 2>/dev/null \
            | sed 's/^/    /' >&2 || true
        if [[ "${NANO_TIERING_SKIP_PROBE:-}" != "1" && "${TIERING_PROBED:-0}" != 1 ]]; then
            # Host-side write/read/delete probe; a store only the Compose
            # network can resolve (http://rustfs:9000) cannot be probed here.
            if tiering_probe=$(python3 -I scripts/lib/clickhouse_tiering.py probe --env-file .env </dev/null 2>&1); then
                ok "Object store check from this host: $tiering_probe"
            else
                tiering_probe="${tiering_probe#tiering: }"
                tiering_cause=$(tiering_probe_cause "$tiering_probe" "$(env_value NANO_TIERING_PROVIDER)")
                if [[ "$tiering_sha" != "$tiering_prev_sha" ]]; then
                    # Put the previous digest back so a re-run probes again.
                    nano_env_set_keys .env "NANO_TIERING_CONFIG_SHA256=$tiering_prev_sha" || true
                    fail "Storage tiering is on, but writing a test object to the bucket from this host failed: ${tiering_probe}.${tiering_cause} Without a working store the local disk fills up later instead of moving old data. Fix the credentials or bucket and re-run, set NANO_TIERING=off, or (for a store only the Compose network can reach) re-run with NANO_TIERING_SKIP_PROBE=1."
                fi
                warn "Object store check from this host failed: ${tiering_probe}.${tiering_cause} ClickHouse still starts (cold parts wait for the store); check with: scripts/nano tiering test"
            fi
        fi
        log "ClickHouse storage tiering on (policy nano_tiered); clickhouse-migrate switches the event tables. Status: scripts/nano tiering status"
    fi
fi

# NAN-5494: ClickHouse mounts two rendered DIRECTORIES and nothing inside
# them: .nano-generated/clickhouse/config.d and users.d, the shipped
# directories plus the sizing, tiering and network allow-list rendered above,
# copied in as plain files. No installer package contains them, so a later
# package extract never changes what ClickHouse runs (a file bind-mounted over
# a shipped placeholder was detached by the extract, and ClickHouse reloaded
# the empty placeholder: every user widened to all private ranges).
if [[ "$MULTI_NODE" != "1" && -r scripts/lib/clickhouse_config_dirs.py ]]; then
    # --record-env: NANO_CLICKHOUSE_CONFIG_DIR / NANO_CLICKHOUSE_USERS_DIR and
    # NANO_CLICKHOUSE_CONFIG_SHA256, the trees' digest the clickhouse service
    # carries, so changed sizing or networks recreate ClickHouse on `up`.
    python3 -I scripts/lib/clickhouse_config_dirs.py --root . --env-file .env --record-env </dev/null >/dev/null \
        || fail "Could not assemble the ClickHouse config.d / users.d directories (above). Nothing was started."
fi

# NAN-5408: `up` leaves a service that left the Compose graph running, with its
# ports still published. With NANO_METRICS_BIND_ADDRESS gone, remove the
# metrics edge, and the node-exporter it started unless the monitoring
# profile runs one.
if [[ "$MULTI_NODE" != "1" && -z "$METRICS_EXPOSE_OVERLAY" ]]; then
    stale_metrics=(nano-metrics-edge)
    [[ ",${COMPOSE_PROFILES:-}," == *,monitoring,* ]] || stale_metrics+=(nano-node-exporter)
    for container in "${stale_metrics[@]}"; do
        if docker container inspect "$container" >/dev/null 2>&1; then
            docker rm -f "$container" >/dev/null </dev/null \
                || fail "Could not remove $container. Its metrics ports may still be published: docker rm -f $container"
            log "Removed $container (metrics are no longer published for an external Prometheus)"
        fi
    done
fi

# NAN-5564: a Vector that keeps running while the new nano-api renders its
# config is hot-reloaded onto it, and a change to a sink's disk buffer (every
# 0.1.x upgrade: acks off and drop_newest before, block after) makes that
# reload fail and Vector exit with events in flight: acknowledged events were
# lost. So when the pipeline identity (release / ack durability / fan-in
# slots) changes, stop Vector first. `docker stop` is Vector's graceful
# shutdown (sources close, in-flight events reach the disk buffers, up to 60 s).
# Its ports then refuse connections (senders retry; nothing is acknowledged)
# until the new Vector's entrypoint sees the new api's render
# (config/vector/.nano/vector-entrypoint.sh, pipeline gate).
# BEGIN nano-vector-pipeline-stop
stop_vector_for_pipeline_change() {
    local target cid have running
    target=$(docker compose "${COMPOSE_ARGS[@]}" config --format json </dev/null 2>/dev/null \
        | python3 -I -c 'import json, sys
env = json.load(sys.stdin).get("services", {}).get("vector", {}).get("environment") or {}
print(env.get("NANO_PIPELINE_IDENTITY") or "")' 2>/dev/null) || target=""
    [[ -n "$target" ]] || return 0
    cid=$(docker compose "${COMPOSE_ARGS[@]}" ps -q vector </dev/null 2>/dev/null | awk 'NR == 1') || cid=""
    # A 0.1.x install's Vector may belong to another Compose project.
    [[ -n "$cid" ]] || cid=$(docker ps -q --filter name='^/nano-vector$' </dev/null 2>/dev/null | awk 'NR == 1') || cid=""
    [[ -n "$cid" ]] || return 0
    running=$(docker inspect --format '{{.State.Running}}' "$cid" </dev/null 2>/dev/null) || return 0
    [[ "$running" == true ]] || return 0
    have=$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$cid" </dev/null 2>/dev/null \
        | awk 'sub(/^NANO_PIPELINE_IDENTITY=/, "") && !seen++') || have=""
    [[ "$have" == "$target" ]] && return 0
    log "Stopping Vector before the upgrade (pipeline ${have:-from before NAN-5564} -> $target): it drains to its disk buffers, and ingest refuses connections until the new pipeline is rendered and running"
    # NAN-5566: a Vector without an identity predates the ingest gate (2.0.31
    # or older): its direct senders cannot be closed, so they are paused first.
    if [[ -z "$have" && "$(type -t nano_vq_confirm_senders_paused)" == function ]]; then
        nano_vq_confirm_senders_paused
    fi
    # NAN-5566: close ingest at nginx and let Vector deliver what it accepted
    # first (this project's Vector only; a 0.1.x one in another project is
    # stopped as is). The stop timeout exceeds Vector's 60 s graceful limit.
    if [[ "$(type -t nano_vq_close)" == function ]] \
        && docker compose "${COMPOSE_ARGS[@]}" ps -q vector </dev/null 2>/dev/null | grep -x "$cid" >/dev/null; then
        nano_vq_close
        nano_vq_drain "${NANO_VECTOR_DRAIN_SECS:-120}"
    fi
    docker stop --time 120 "$cid" </dev/null >/dev/null \
        || fail "Could not stop Vector ($cid) before the upgrade (above). Stop it (docker stop --time 120 $cid) and re-run install.sh; re-runs are safe."
}
# END nano-vector-pipeline-stop
if [[ "$MULTI_NODE" != "1" ]]; then
    if [[ -r scripts/lib/vector-quiesce.sh ]]; then
        # shellcheck source=scripts/lib/vector-quiesce.sh
        . scripts/lib/vector-quiesce.sh
        nano_vq_compose() { docker compose "${COMPOSE_ARGS[@]}" "$@"; }
    fi
    stop_vector_for_pipeline_change
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
# NAN-5387: move the stack onto (or off) nano's pinned network. `down` first,
# so every container is recreated by the `up` below: Compose reconnects the
# containers it keeps WITHOUT their service DNS aliases when a network is
# replaced under them.
if declare -F nano_network_pin_apply >/dev/null; then
    case "$NETWORK_PIN_ACTION" in
        replace) log "Moving every service onto nano's pinned network $NETWORK_PIN_NAME ($COMPOSE_SUBNET): stopping the stack first" ;;
        release) log "Your Compose files manage nano's network now: stopping the stack to retire the pinned $NETWORK_PIN_NAME" ;;
    esac
    nano_network_pin_apply \
        || fail "Could not move nano onto its network $NETWORK_PIN_NAME (above). The stack may be stopped; fix the cause and rerun install.sh (reruns are safe)."
fi
# NAN-5269: `up -d` waits for clickhouse-migrate to complete, and a v2.0.11
# install sat there for ten minutes with nothing to show for it. The migrator
# now ends a stuck PostgreSQL snapshot itself; this bounds the whole wait too,
# so the installer never hangs forever. Stopping the wait does not stop the
# containers: a migration that is merely slow keeps running.
compose_up_timeout=${NANO_COMPOSE_UP_TIMEOUT:-3600}
[[ "$compose_up_timeout" =~ ^[0-9]+$ && "$compose_up_timeout" -ge 60 ]] || compose_up_timeout=3600
# NAN-5514: how many times the kernel killed nano-api (container CID) for
# memory since this run's `up` started. Docker's OOMKilled describes only the
# current run, so a restart loop of OOM kills read "OOMKilled false". Counts
# docker's oom events, and the kernel log where this user can read it (best
# effort: dmesg is often restricted). Prints "<count> <source>".
compose_up_started_at=""
nano_api_oom_kills() {
    local cid="$1" limit=() events=0 kernel=0 since="${compose_up_started_at:-}"
    command -v timeout >/dev/null 2>&1 && limit=(timeout 15)
    if [[ "$since" =~ ^[0-9]+$ ]]; then
        events=$(${limit[@]+"${limit[@]}"} docker events --since "$since" --until "$(date +%s)" \
            --filter "container=$cid" --filter event=oom --format '{{.Action}}' </dev/null 2>/dev/null \
            | awk 'NF { n++ } END { print n + 0 }') || events=0
        if command -v journalctl >/dev/null 2>&1; then
            kernel=$(${limit[@]+"${limit[@]}"} journalctl -k -q --no-pager --since "@$since" </dev/null 2>/dev/null \
                | awk '/[Oo]ut of memory: Killed process [0-9]+ \(nanosiem-api\)/ { n++ } END { print n + 0 }') || kernel=0
        fi
    fi
    [[ "$events" =~ ^[0-9]+$ ]] || events=0
    [[ "$kernel" =~ ^[0-9]+$ ]] || kernel=0
    if (( kernel > events )); then
        printf '%s kernel log\n' "$kernel"
    else
        printf '%s docker events\n' "$events"
    fi
}
compose_up_hint() {
    local service listing name state health code extra="" shown=" " cid inspect
    local status exit_code oom restarts memory nano_cpus limits oom_kills oom_source
    # NAN-5509: beside the usual suspects, every service that exited with an
    # error, is restarting or dead, or reports unhealthy (a password mismatch
    # on reused volumes restart-loops nano-api; a port clash stops nginx).
    listing=$(docker compose "${COMPOSE_ARGS[@]}" ps -a \
        --format '{{.Service}}|{{.State}}|{{.Health}}|{{.ExitCode}}' </dev/null 2>/dev/null || true)
    while IFS='|' read -r name state health code; do
        [[ "$name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || continue
        case "$state" in
            restarting | dead) extra+=" $name" ;;
            exited) [[ "$code" == 0 ]] || extra+=" $name" ;;
            *) [[ "$health" == unhealthy ]] && extra+=" $name" ;;
        esac
    done <<< "$listing"
    for service in clickhouse-migrate postgres-ha postgres clickhouse keeper nano-api nginx vector $extra; do
        [[ "$shown" == *" $service "* ]] && continue
        shown+="$service "
        docker compose "${COMPOSE_ARGS[@]}" ps -a --format '{{.Service}}' "$service" </dev/null 2>/dev/null \
            | grep -x "$service" >/dev/null || continue
        printf '\n--- last lines of %s ---\n' "$service" >&2
        # NAN-5499: error lines carry a long prefix (the migrator prints the
        # first 120 characters of the failing SQL) before ClickHouse's reason,
        # so a flat 400-character cut hid the one part that mattered. Keep
        # ERROR / exception lines whole (bounded) and trim only the rest.
        docker compose "${COMPOSE_ARGS[@]}" logs --no-color --tail 15 "$service" </dev/null 2>&1 \
            | sed -e 's/\x1b\[[0-9;]*m//g' \
            | awk '{ max = ($0 ~ /ERROR|Exception|Code: [0-9]+/) ? 4000 : 400
                     if (length($0) > max) print substr($0, 1, max) " ..."; else print }' >&2 || true
        if [[ "$service" == clickhouse-migrate ]]; then
            docker compose "${COMPOSE_ARGS[@]}" logs --no-color --tail 40 "$service" </dev/null 2>&1 \
                | grep -oE 'Code: [0-9]+\. DB::Exception: .*' | tail -n 1 | cut -c1-1500 \
                | sed -e 's/^/ClickHouse error: /' >&2 || true
        fi
        if [[ "$service" == clickhouse ]]; then
            # ClickHouse logs to files after startup; compose logs only show
            # the config merge, never the reason a query failed.
            printf -- '--- last lines of clickhouse-server.err.log ---\n' >&2
            # Bounded: a wedged container or a slow dockerd must not hang
            # the failure path (timeout is optional on the host).
            local hint_limit=()
            command -v timeout >/dev/null 2>&1 && hint_limit=(timeout 20)
            ${hint_limit[@]+"${hint_limit[@]}"} docker compose "${COMPOSE_ARGS[@]}" exec -T clickhouse \
                tail -n 20 /var/log/clickhouse-server/clickhouse-server.err.log </dev/null 2>&1 \
                | cut -c1-1500 >&2 || true
        fi
        if [[ "$service" == nano-api ]]; then
            # NAN-5509: an undersized host showed only a silent restart loop.
            # Say how the container ended and what it may use.
            cid=$(docker compose "${COMPOSE_ARGS[@]}" ps -a -q nano-api </dev/null 2>/dev/null | awk 'NR == 1')
            [[ -n "$cid" ]] || continue
            inspect=$(docker inspect --format '{{.State.Status}}|{{.State.ExitCode}}|{{.State.OOMKilled}}|{{.RestartCount}}|{{.HostConfig.Memory}}|{{.HostConfig.NanoCpus}}' \
                "$cid" </dev/null 2>/dev/null) || continue
            [[ "$inspect" == *"|"* ]] || continue
            IFS='|' read -r status exit_code oom restarts memory nano_cpus <<< "$inspect"
            limits=""
            [[ "$memory" =~ ^[1-9][0-9]*$ ]] && limits+="memory limit $(( memory / 1048576 )) MiB"
            if [[ "$nano_cpus" =~ ^[1-9][0-9]*$ ]]; then
                limits+="${limits:+, }CPU limit $(( nano_cpus / 1000000000 )).$(( nano_cpus % 1000000000 / 10000000 / 10 ))"
            fi
            printf 'nano-api container: %s, exit code %s, OOMKilled %s, %s restart(s)%s\n' \
                "${status:-?}" "${exit_code:-?}" "${oom:-?}" "${restarts:-?}" "${limits:+, $limits}" >&2
            read -r oom_kills oom_source <<< "$(nano_api_oom_kills "$cid")"
            [[ "$oom_kills" =~ ^[0-9]+$ ]] || oom_kills=0
            if (( oom_kills > 0 )) || [[ "$oom" == true ]]; then
                printf '%s\n' "nano-api was killed for running out of memory$( (( oom_kills > 0 )) && printf ' %s time(s) since this run started (%s)' "$oom_kills" "$oom_source")${limits:+ ($limits)}. The host is too small for nano, or NANO_API_MEM_LIMIT in .env is set too low: use a host that meets nano's minimum, then re-run install.sh." >&2
            fi
        fi
    done
}
compose_up_started_at=$(date +%s)
docker compose "${COMPOSE_ARGS[@]}" "${compose_up_args[@]}" </dev/null &
compose_up_pid=$!
# A background job of a non-interactive shell ignores Ctrl-C; pass it on so an
# interrupted install stops `up` as it did when it ran in the foreground.
trap 'kill "$compose_up_pid" 2>/dev/null; exit 130' INT
trap 'kill "$compose_up_pid" 2>/dev/null; exit 143' TERM
compose_up_deadline=$(( $(date +%s) + compose_up_timeout ))
while kill -0 "$compose_up_pid" 2>/dev/null && (( $(date +%s) < compose_up_deadline )); do
    sleep 2
done
if kill -0 "$compose_up_pid" 2>/dev/null; then
    kill "$compose_up_pid" 2>/dev/null || true
    wait "$compose_up_pid" 2>/dev/null || true
    trap - INT TERM
    compose_up_hint
    fail "Services did not finish starting within ${compose_up_timeout} s (usually the one-shot migrator, clickhouse-migrate; its last lines are above). The containers keep running. If the migrator log is still advancing, wait for it and rerun install.sh on this host; if it stopped advancing, check the PostgreSQL leader (patronictl list on a postgres host) and ClickHouse, then rerun install.sh on this host. Raise the wait with NANO_COMPOSE_UP_TIMEOUT=<seconds>."
fi
compose_up_rc=0
wait "$compose_up_pid" || compose_up_rc=$?
trap - INT TERM
if (( compose_up_rc != 0 )); then
    compose_up_hint
    fail "Starting services failed (see the docker compose output and the last log lines above). Fix the cause, then rerun install.sh on this host; reruns are safe."
fi

# NAN-5397: a single-file bind mount pins the file's inode. The update above
# (`git reset --hard`, a bundle unpack) and the sizing/network renders replace
# those files with new ones, but `up -d` recreates a container only when its
# definition changed, so nginx, Prometheus, ClickHouse and the rest kept
# reading the old file after an upgrade. Recreate every running service whose
# mounted file differs from the file now in the install directory.
recreate_stale_mount_services() {
    local container service configured
    local containers=() services=()
    [[ -f scripts/lib/compose_stale_mounts.py ]] || return 0
    # `ps` also lists orphans (services no longer in the Compose files); `up`
    # cannot recreate those, so only configured services are considered.
    configured=$(docker compose "${COMPOSE_ARGS[@]}" config --services </dev/null 2>/dev/null) || return 0
    while IFS= read -r container; do
        if [[ -n "$container" ]]; then containers+=("$container"); fi
    done < <(docker compose "${COMPOSE_ARGS[@]}" ps -q </dev/null 2>/dev/null || true)
    (( ${#containers[@]} > 0 )) || return 0
    while IFS= read -r service; do
        if [[ "$service" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] && grep -qxF -- "$service" <<<"$configured"; then
            services+=("$service")
        fi
    done < <(python3 -I scripts/lib/compose_stale_mounts.py --root "$NANO_INSTALL_DIR" \
        "${containers[@]}" </dev/null || true)
    (( ${#services[@]} > 0 )) || return 0
    log "Recreating ${services[*]} to load the updated configuration files"
    # NAN-5566: a recreate stops Vector too: close ingest, drain, long stop first.
    if [[ " ${services[*]} " == *" vector "* && "$(type -t nano_vq_close)" == function ]] && nano_vq_running vector; then
        nano_vq_close
        nano_vq_drain "${NANO_VECTOR_DRAIN_SECS:-120}"
        nano_vq_stop
    fi
    # The stack is already up: a failed recreate leaves these services on
    # their previous configuration, which is no reason to abort the install.
    docker compose "${COMPOSE_ARGS[@]}" up -d --no-deps --force-recreate "${services[@]}" </dev/null \
        || warn "Could not recreate ${services[*]} onto the updated configuration; they keep running their previous configuration files. Run: docker compose ${COMPOSE_ARGS[*]} up -d --no-deps --force-recreate ${services[*]}"
}
recreate_stale_mount_services

# NAN-5515: Vector reads its TLS files when the source starts, so a listener
# certificate re-issued in place (new SANs, a rotated CA) needs a restart of a
# Vector the `up` above did not recreate. Rare: only when the files changed.
if [[ "$VECTOR_NATIVE_RESTART" == "1" ]] \
    && docker compose "${COMPOSE_ARGS[@]}" ps --status running --services 2>/dev/null </dev/null | grep -x vector >/dev/null; then
    log "Restarting Vector to load the re-issued Vector-native listener certificate"
    vector_restart_args=(restart vector)
    if [[ "$(type -t nano_vq_close)" == function ]]; then
        # NAN-5566: a single host closes ingest and drains first; the reopen
        # below runs once the restarted Vector is healthy.
        nano_vq_close
        nano_vq_drain "${NANO_VECTOR_DRAIN_SECS:-120}"
        vector_restart_args=(restart --timeout "$NANO_VQ_STOP_TIMEOUT" vector)
    fi
    docker compose "${COMPOSE_ARGS[@]}" "${vector_restart_args[@]}" </dev/null \
        || warn "Could not restart Vector; it keeps the previous Vector-native certificate until it restarts. Run: docker compose ${COMPOSE_ARGS[*]} restart vector"
fi

# NAN-5566: reopen ingest (closed above while Vector drained, or left closed by
# an earlier run that failed) once the new Vector reports healthy.
if [[ "$(type -t nano_vq_reopen)" == function ]]; then
    nano_vq_reopen || warn "Ingest may still be closed at nginx: docker compose exec nginx rm -f /run/nano-ingest/closed"
fi

# NAN-5404: ClickHouse cannot confine a user to a listener, so with the Agent
# Lane port published EVERY ClickHouse user other than a token user must
# refuse the agent networks. The renders above lock the users nano defines;
# this reads every user ClickHouse actually has (system.users: users.d, the
# built-in `default`, SQL-created ones such as nano_backup or one added by
# hand) and withdraws the listener if any of them admits an agent source.
# Role-split hosts: the app's Agent Lane control plane runs the same check on
# every ClickHouse node before it provisions a token.
agentlane_read_users() {
    local out=$1 query
    query=$(python3 -I deploy/compose/agentlane.py users-query </dev/null)
    # ClickHouse may have just been recreated onto new config: up to ~2 min.
    for _ in $(seq 1 40); do
        # The admin password is already in the ClickHouse container's
        # environment; it never appears on this host's command line.
        # shellcheck disable=SC2016
        docker compose "${COMPOSE_ARGS[@]}" exec -T clickhouse sh -c \
            'clickhouse-client --user nanosiem_admin --password "$CLICKHOUSE_ADMIN_PASSWORD" --query "$1"' \
            sh "$query" </dev/null >"$out" 2>/dev/null && [[ -s "$out" ]] && return 0
        : >"$out"
        sleep 3
    done
    return 1
}
AGENTLANE_DEFERRED_FAILURE=""
agentlane_check_live_users() {
    local rows statement statements
    [[ -n "$AGENTLANE_OVERLAY" ]] || return 0
    rows=$(mktemp .nano-agentlane-users.XXXXXX)
    # Users nano created with SQL (nano_backup, legacy raw-SQL users) get the
    # app user's networks first, so the check below only fires on users nano
    # did not create. Older releases created them on the private ranges,
    # which overlap an agent on a private LAN.
    if agentlane_read_users "$rows"; then
        statements=$(python3 -I deploy/compose/agentlane.py align-sql --users-json "$rows" </dev/null) || statements=""
        while IFS= read -r statement; do
            [[ -n "$statement" ]] || continue
            # shellcheck disable=SC2016
            if docker compose "${COMPOSE_ARGS[@]}" exec -T clickhouse sh -c \
                'clickhouse-client --user nanosiem_admin --password "$CLICKHOUSE_ADMIN_PASSWORD" --query "$1"' \
                sh "$statement" </dev/null >/dev/null; then
                log "Agent Lane: ${statement%% HOST *} now accepts the same networks as nanosiem"
            else
                warn "Agent Lane: could not run: $statement"
            fi
        done <<<"$statements"
        [[ -z "$statements" ]] || agentlane_read_users "$rows" || :
    fi
    if python3 -I deploy/compose/agentlane.py check-users --env-file .env --users-json "$rows" </dev/null; then
        rm -f "$rows"
        ok "Agent Lane: no ClickHouse user other than token users accepts the allow-listed networks"
        return 0
    fi
    rm -f "$rows"
    # Withdraw the listener: drop the overlay and recreate ClickHouse without
    # it. The rest of the install (nginx reload, PostgreSQL HA identity, API
    # health, admin init) still runs; install.sh exits non-zero at the end.
    local args=() skip=0 item
    for item in "${COMPOSE_ARGS[@]}"; do
        if (( skip )); then skip=0; [[ "$item" == "$AGENTLANE_OVERLAY" ]] && continue; args+=(-f "$item"); continue; fi
        if [[ "$item" == -f ]]; then skip=1; continue; fi
        args+=("$item")
    done
    agentlane_unpublish
    if docker compose "${args[@]}" up -d --no-deps --force-recreate clickhouse </dev/null; then
        COMPOSE_ARGS=("${args[@]}")
        AGENTLANE_OVERLAY=""
    else
        warn "Could not recreate ClickHouse without the Agent Lane listener; stop it now: docker compose ${args[*]} up -d --no-deps --force-recreate clickhouse"
    fi
    AGENTLANE_DEFERRED_FAILURE="Agent Lane was withdrawn (see the users named above): the listener is closed and the rest of the stack is running. Restrict or drop those users, then re-run install.sh."
    warn "$AGENTLANE_DEFERRED_FAILURE"
}
agentlane_check_live_users

# On a re-run/upgrade, `up -d` recreates the app containers (new IPs) but leaves
# nginx as-is. Reload nginx so it re-reads its config (through the directory
# mount, NAN-5397) and re-resolves upstream IPs, otherwise
# it proxies dead old IPs and 502s until restarted (NAN-1237). Best-effort.
docker compose "${COMPOSE_ARGS[@]}" exec -T nginx nginx -s reload </dev/null >/dev/null 2>&1 || true

if [[ -n "$VALKEY_REVOCATIONS_FILE" ]]; then
    carried=0
    while read -r key value ttl; do
        [[ "$key" =~ ^auth:revoked_jti:[0-9A-Fa-f-]{1,64}$ && "$value" =~ ^[A-Za-z0-9:._-]{1,64}$ && "$ttl" =~ ^[0-9]{1,12}$ ]] || continue
        { printf 'SET %s %s PX %s NX\r\n' "$key" "$value" "$ttl"; sleep 1; } \
            | docker compose "${COMPOSE_ARGS[@]}" exec -T "$VALKEY_SHARED_ENDPOINT" nc -w 3 127.0.0.1 6379 2>/dev/null \
            | grep '^+OK\|^\$-1' >/dev/null && carried=$((carried + 1))
    done < "$VALKEY_REVOCATIONS_FILE"
    rm -f -- "$VALKEY_REVOCATIONS_FILE"
    ok "Carried $carried JWT revocation(s) to the shared Valkey"
fi

# NAN-5214: once this host's Patroni member holds the cluster's data, record its
# system identifier in the shared .env (never overwriting a different one). The
# first postgres host then refuses to initdb this install even if its state
# volume and every peer are lost.
if [[ "$MULTI_NODE" == "1" && "${NANO_POSTGRES_HA:-false}" == "true" && ",${ROLE_ARG}," == *,postgres,* ]]; then
    # Announce anything this run changed before the identity, so the
    # identity message below stands on its own.
    report_shared_env_change
    pg_ha_outcome=$(pg_ha_record_identity "${NANO_PG_HA_SYSTEM_ID_WAIT:-60}")
    case "$pg_ha_outcome" in
        recorded*)
            ok "Recorded the PostgreSQL cluster identity in .env (${pg_ha_outcome#recorded })"
            # NAN-5251/NAN-5263: every postgres host records the same
            # identifier at the same place, so their .env files stay
            # identical. The first postgres host's copy is the one to spread.
            if [[ "${NANO_PATRONI_BOOTSTRAP:-false}" == "true" ]]; then
                shared_env_rebaseline
                warn "The shared .env changed on this host (NANO_PG_HA_SYSTEM_ID): $PG_HA_COPY_ADVICE."
            else
                log "This postgres host recorded NANO_PG_HA_SYSTEM_ID in its own .env. The first postgres host records the same line with './install.sh --record-pg-ha-identity' (as the install user, without sudo) (run it there after the last postgres host; it restarts nothing). Then $PG_HA_COPY_ADVICE; this host's .env is then unchanged by the copy."
                shared_env_rebaseline
            fi ;;
        unchanged*) ;;
        conflict*)
            fail "PostgreSQL HA identity mismatch: ${pg_ha_outcome#conflict }. This host's database is not the cluster recorded in .env; do not continue. See 'Recovering after losing the bootstrap host and etcd' in the multi-node guide." ;;
        *)
            if [[ "${NANO_PATRONI_BOOTSTRAP:-false}" == "true" ]]; then
                log "PostgreSQL HA bootstraps once a second postgres host joins (etcd needs 2 of 3 members), so its cluster identity cannot be recorded yet. Copy this host's .env to the other postgres hosts and install them; then, on THIS host, run './install.sh --record-pg-ha-identity' (as the install user, without sudo) (it only records NANO_PG_HA_SYSTEM_ID; it restarts nothing) and copy this host's .env to every host."
            else
                warn "PostgreSQL HA is still forming on this host; that is fine. After the last postgres host, run './install.sh --record-pg-ha-identity' (as the install user, without sudo) on the FIRST postgres host and copy its .env to every host."
            fi ;;
    esac
fi

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
        # NAN-5509: show the logs here too; this is where an unhealthy API,
        # a restart loop and an nginx that cannot start all end.
        compose_up_hint
        health_note=""
        [[ "$health_code" == 000 ]] && health_note=" HTTP 000 means nothing answered at $HEALTH_URL: nginx is not running or not listening there (its last lines are above)."
        fail "API did not become healthy within 5 min (HTTP $health_code from $HEALTH_URL).${health_note} Check 'docker compose ${COMPOSE_ARGS[*]} logs nano-api nginx clickhouse-migrate'."
    fi
    if [[ "$MULTI_NODE" == "1" ]]; then
        log "Waiting for every ClickHouse asynchronous-loader object to become OK"
        nano_wait_async_loaders "${NANO_ASYNC_LOADER_TIMEOUT:-300}" 3 \
            || fail "ClickHouse asynchronous-loader readiness failed. Check ClickHouse logs and system.asynchronous_loader before retrying."
        ok "ClickHouse asynchronous loaders ready"
    fi
elif [[ "$HAS_INGEST" == "1" ]]; then
    INGEST_HEALTH_URL="http://${EDGE_PROBE_HOST}:${NANO_INGEST_PORT}/healthz"
    log "Waiting for the ingest edge at $INGEST_HEALTH_URL"
    deadline=$(( $(date +%s) + 120 ))
    while (( $(date +%s) < deadline )); do
        curl -fsS --noproxy '*' -o /dev/null "$INGEST_HEALTH_URL" </dev/null && break
        sleep 2
    done
    curl -fsS --noproxy '*' -o /dev/null "$INGEST_HEALTH_URL" </dev/null \
        || fail "Ingest edge did not become healthy. Check 'docker compose ${COMPOSE_ARGS[*]} logs vector vector-config-consumer ingest-edge'."
    ok "Ingest edge healthy"
else
    # Stateful roles have their scenario-level readiness proven by the e2e
    # harness. Here, fail quickly if the requested long-running container died.
    for role_service in ${ROLE_ARG//,/ }; do
        # NAN-5214: an HA postgres host runs the Patroni member instead.
        [[ "$role_service" == postgres && "${NANO_POSTGRES_HA:-false}" == "true" ]] && role_service=postgres-ha
        case "$role_service" in
            postgres|postgres-ha|clickhouse|keeper)
                docker compose "${COMPOSE_ARGS[@]}" ps --status running --services </dev/null | grep -x "$role_service" >/dev/null \
                    || fail "$role_service did not stay running. Check 'docker compose ${COMPOSE_ARGS[*]} logs $role_service'." ;;
            # NAN-5250: the monitoring role is Prometheus + Grafana.
            monitoring)
                for monitoring_service in prometheus grafana; do
                    docker compose "${COMPOSE_ARGS[@]}" ps --status running --services </dev/null | grep -x "$monitoring_service" >/dev/null \
                        || fail "$monitoring_service did not stay running. Check 'docker compose ${COMPOSE_ARGS[*]} logs $monitoring_service'."
                done ;;
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
    if echo "$STATUS_JSON" | grep '"initialized":true' >/dev/null; then
        warn "System is already initialized — skipping admin creation."
    else
        if [[ "$REUSE_ENV" == "1" ]]; then
            # NAN-5172: email/name come from .env (kept by the first run) or
            # the environment; with a TTY anything still missing is asked.
            # The password is never in .env unless it was autogenerated.
            if [[ -z "$ADMIN_PASSWORD" ]]; then
                ADMIN_PASSWORD=$(env_value INITIAL_ADMIN_PASSWORD)
                [[ -n "$ADMIN_PASSWORD" ]] && GENERATED_PASSWORD=1
            fi
            # Unattended: the name takes its default and every other missing
            # value is named in one message (the stack is up; no admin yet).
            if ! have_controlling_tty; then
                [[ -n "$ADMIN_NAME" ]] || ADMIN_NAME=Admin
                missing=""
                [[ -n "$ADMIN_EMAIL" ]] || missing+=$'NANO_ADMIN_EMAIL\tthe first admin\'s email address (name@domain)\n'
                [[ -n "$ADMIN_PASSWORD" ]] || missing+=$'NANO_ADMIN_PASSWORD\tthe first admin\'s password: 12+ bytes with upper and lower case, a digit and a special character\n'
                if [[ -n "$missing" ]]; then
                    not_initialized="This install has no admin account yet (nano is running)"
                    [[ "$MULTI_NODE" == "1" ]] && not_initialized+="; re-run on the app role host"
                    fail_missing_inputs "$missing" "$not_initialized. Or run install.sh in a terminal to be asked."
                fi
            fi
            if [[ -z "$ADMIN_EMAIL" ]]; then
                prompt_admin_email
                [[ -n "$ADMIN_EMAIL" ]] || fail "Admin email is required."
                if persistable_env_value "$ADMIN_EMAIL"; then
                    nano_env_set_keys .env "NANO_ADMIN_EMAIL='$ADMIN_EMAIL'" || fail "Could not record NANO_ADMIN_EMAIL in .env."
                fi
            fi
            if [[ -z "$ADMIN_NAME" ]]; then
                ADMIN_NAME=$(prompt_tty "Admin display name" "Admin" "" NANO_ADMIN_NAME) || exit
                [[ -n "$ADMIN_NAME" ]] || fail "Admin name is required."
                if persistable_env_value "$ADMIN_NAME"; then
                    nano_env_set_keys .env "NANO_ADMIN_NAME='$ADMIN_NAME'" || fail "Could not record NANO_ADMIN_NAME in .env."
                fi
            fi
            if [[ -z "$ADMIN_PASSWORD" ]]; then
                GENERATED_PASSWORD=0
                prompt_admin_password
                if [[ "$GENERATED_PASSWORD" == 1 ]]; then
                    if grep -qE '^[[:space:]]*(export[[:space:]]+)?INITIAL_ADMIN_PASSWORD=' .env; then
                        # An empty leftover line: set it in place (NAN-5251).
                        nano_env_set_keys .env "INITIAL_ADMIN_PASSWORD=$ADMIN_PASSWORD" \
                            || fail "Could not record INITIAL_ADMIN_PASSWORD in .env."
                    else
                        printf '\n# Autogenerated initial admin password — printed by install.sh on success.\n# Safe to delete once you have signed in and confirmed the credentials.\nINITIAL_ADMIN_PASSWORD=%s\n' "$ADMIN_PASSWORD" >> .env
                    fi
                fi
            fi
            validate_admin_password "$ADMIN_PASSWORD"
        fi
        # NAN-5237: nano-api accepts first-admin setup only with the setup
        # token from .env (generated with the other secrets). It is sent from
        # a 0600 header file, never on the curl command line.
        SETUP_TOKEN=$(env_value NANO_SETUP_TOKEN)
        if [[ -n "$SETUP_TOKEN" ]]; then
            if [[ -t 1 ]]; then
                log "Setup token (only needed to finish setup in the browser if this run is interrupted): $SETUP_TOKEN"
            else
                log "Setup token: NANO_SETUP_TOKEN in $NANO_INSTALL_DIR/.env (only needed to finish setup in the browser if this run is interrupted)"
            fi
        fi
        log "Creating admin user $ADMIN_EMAIL"
        payload=$(printf '{"email":%s,"name":%s,"password":%s}' \
            "$(json_escape "$ADMIN_EMAIL")" \
            "$(json_escape "$ADMIN_NAME")" \
            "$(json_escape "$ADMIN_PASSWORD")")
        # The EXIT trap removes the header file on any exit; while it exists,
        # INT/TERM become an exit so that trap also runs on an interrupt.
        trap 'exit 130' INT
        trap 'exit 143' TERM
        SETUP_HEADER_FILE=$(mktemp "${TMPDIR:-/tmp}/nano-setup-header.XXXXXX")
        SETUP_RESPONSE_FILE=$(mktemp "${TMPDIR:-/tmp}/nano-setup-response.XXXXXX")
        [[ -z "$SETUP_TOKEN" ]] || printf 'Authorization: Bearer %s\n' "$SETUP_TOKEN" > "$SETUP_HEADER_FILE"
        init_ok=1
        init_code=$(api_call "$SETUP_RESPONSE_FILE" -X POST \
            -H "Content-Type: application/json" \
            -H "@$SETUP_HEADER_FILE" \
            -d "$payload" \
            "${API_BASE}/api/setup/initialize") || init_ok=0
        rm -f -- "$SETUP_HEADER_FILE"
        SETUP_HEADER_FILE=""
        trap - INT TERM
        init_already_done=0
        # Another app host can finish setup between the status check above
        # and this call; nano-api then answers 409 already_initialized (or
        # users_exist). That is the same outcome as the status check.
        if [[ "$init_ok" == 0 && "$init_code" == 409 ]] \
            && grep -Eq '"error"[[:space:]]*:[[:space:]]*"(already_initialized|users_exist)"' "$SETUP_RESPONSE_FILE"; then
            init_already_done=1
        fi
        rm -f -- "$SETUP_RESPONSE_FILE"
        SETUP_RESPONSE_FILE=""
        if [[ "$init_already_done" == 1 ]]; then
            warn "System is already initialized — skipping admin creation."
        elif [[ "$init_ok" == 0 ]]; then
            case "$init_code" in
                401|403) fail "Admin initialization was refused (HTTP $init_code): nano-api did not accept the setup token. Check that NANO_SETUP_TOKEN in $NANO_INSTALL_DIR/.env is set and that nano-api was started with this .env, then re-run." ;;
            esac
            fail "Admin initialization failed (HTTP $init_code from ${API_BASE}/api/setup/initialize). Check 'docker compose ${COMPOSE_ARGS[*]} logs nano-api nginx'."
        else
            ok "Admin user created"
        fi
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
# NAN-5263: a PostgreSQL/Keeper/ClickHouse-only host serves no ingest edge;
# the app and ingest hosts print the ingest endpoints.
SHOW_INGEST_SUMMARY=1
if [[ "$MULTI_NODE" == "1" && ",${ROLE_ARG}," != *,app,* && ",${ROLE_ARG}," != *,ingest,* ]]; then
    SHOW_INGEST_SUMMARY=0
    echo
    printf "  Ingest:   not on this host (roles %s); the app and ingest hosts print the endpoints\n" "$ROLE_ARG"
fi
if [[ "${VECTOR_AUTH_TOKEN_PRESENT:-0}" == "1" && "$SHOW_INGEST_SUMMARY" == "1" ]]; then
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
    printf "  Ingest tokens: issue one per sender under Ingestion → Log Sources → Credentials (%s/ingestion/log-sources/credentials)\n" "$BASE_URL"
    printf "              (bound to one log source, which it decides; shown once)\n"
    if [[ "${REUSE_ENV:-0}" == "1" ]] && ! is_line_release "${PRE_RUN_NANO_VERSION:-}"; then
        printf "  Install token: VECTOR_AUTH_TOKEN in %s/.env  ← legacy multiplex (deprecated), kept for senders set up before v2\n" "$NANO_INSTALL_DIR"
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
    # NAN-5515: always mutual TLS; the client certificate is the credential.
    if [[ "$VECTOR_NATIVE_STATE" == *server=locked* ]]; then
        printf "  Vector:   %s:6000  (Vector native protocol v2, mTLS required; LOCKED on this host, see the warning above)\n" "$INGEST_HOST"
    else
        printf "  Vector:   %s:6000  (Vector native protocol v2, mTLS required)\n" "$INGEST_HOST"
    fi
    if [[ "$MULTI_NODE" == "1" ]]; then
        printf "              issue a client certificate per sender on the first app host: scripts/nano vector-client-cert <name>\n"
    else
        printf "              issue a client certificate per sender: scripts/nano vector-client-cert <name>\n"
    fi
    if [[ "$(env_value NANO_VECTOR_NATIVE_TRUST_SOURCE_TYPE)" == true ]]; then
        printf "              (prints the Vector sink config; events keep the source_type their sender declares)\n"
    else
        printf "              (prints the Vector sink config; events land as source_type=vector_native)\n"
    fi
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
            if [[ "$MULTI_NODE" == "1" ]]; then
                printf "            Native client (Tenzir ≥ 6.4.0): configure TLS to match the inventory transport mode\n"
            else
                printf "            Native client (Tenzir ≥ 6.4.0): run it as a container on nano's Docker network (the native port is not published on the host)\n"
            fi
        fi
    fi
fi
# NAN-5509: which inbound ports the customer must open, and the ufw trap.
firewall_ports=$(nano_firewall_summary "${PUBLISHED_PORTS:-}")
if [[ -n "$firewall_ports" ]]; then
    echo
    printf "  Firewall: allow inbound %s\n" "$firewall_ports"
    printf "            in your firewall or cloud security group, only from your users and log sources.\n"
    printf "            Docker publishes these ports itself: ufw rules do not filter them. Restrict them\n"
    printf "            with the DOCKER-USER chain or bind addresses: https://docs.docker.com/engine/network/packet-filtering-firewalls/\n"
fi
# NAN-5515: an existing install whose :6000 listener just became mTLS-only.
# NAN-5526: only an upgrade from a plaintext listener, never a fresh install.
if [[ "$VECTOR_NATIVE_CUTOVER" == "1" ]]; then
    echo
    printf "  %b!! Vector native port 6000 now REQUIRES mutual TLS.%b\n" "$c_bold" "$c_reset"
    printf "  !! Senders without a client certificate signed by this install's Vector-native CA are refused.\n"
    # 0.1.x stored the declared source_type, so this count means nothing there;
    # the legacy summary below reports what the 0.1.x Vector took instead.
    if [[ -n "$VECTOR_NATIVE_RECENT_EVENTS" && "$LEGACY_UPGRADE" != 1 && "$LEGACY_SUMMARY" != 1 ]]; then
        printf "  !! In the last 24 hours this install took %s event(s) on :6000 (source_type=vector_native);\n" "$VECTOR_NATIVE_RECENT_EVENTS"
        printf "  !! senders that sent them without a client certificate are refused from now on.\n"
    fi
    if [[ -n "${LEGACY_VN_BUNDLES:-}" ]]; then
        printf "  !! Client certificate bundles were issued for your senders (below); others: scripts/nano vector-client-cert <name>\n"
    else
        printf "  !! Issue one per sender: scripts/nano vector-client-cert <name>  (prints the Vector sink config)\n"
    fi
fi
# NAN-5559: what a 0.1.x install still needs after the upgrade.
if [[ "$LEGACY_UPGRADE" == 1 || "$LEGACY_SUMMARY" == 1 ]]; then
    echo
    printf "  %bUpgraded from nano %s. Next:%b\n" "$c_bold" "$LEGACY_FROM" "$c_reset"
    printf "    1. Make the OCSF history from before the upgrade searchable again:\n"
    printf "         cd %s && scripts/nano ocsf-backfill --order newest-first\n" "$NANO_INSTALL_DIR"
    printf "    2. Optionally, once it reports done, free the legacy table's disk (a dry run first):\n"
    printf "         cd %s && scripts/nano ocsf-legacy-drop\n" "$NANO_INSTALL_DIR"
    printf "         cd %s && scripts/nano ocsf-legacy-drop --confirm\n" "$NANO_INSTALL_DIR"
    if [[ -n "$LEGACY_SENDER_STOP_NOTICE" ]]; then
        printf "    3. Start your log senders again (or reopen the ingest ports).\n"
    fi
    if [[ -n "${LEGACY_VN_BUNDLES:-}" ]]; then
        printf "  %bVector-to-Vector senders: port 6000 now requires mutual TLS.%b For each sender, copy its\n" "$c_bold" "$c_reset"
        printf "  bundle's three certificate files to it, merge its sink config into that Vector's config and\n"
        printf "  restart it. Then delete the bundles here (each holds the sender's private key).\n"
        while read -r vn_name vn_dir; do
            [[ -n "$vn_name" ]] || continue
            printf "    %s: %s\n" "$vn_name" "$vn_dir"
            if [[ -r "$vn_dir/vector-sink.toml" ]]; then
                sed 's/^/      /' "$vn_dir/vector-sink.toml"
            fi
        done <<< "$LEGACY_VN_BUNDLES"
    fi
    if [[ "${LEGACY_VN_USED:-0}" == 1 && -z "${LEGACY_VN_BUNDLES:-}" ]] || [[ "${LEGACY_VN_BUNDLE_FAILED:-0}" == 1 ]]; then
        printf "  %b!! Vector-to-Vector senders on port 6000 are refused until each has a client certificate.%b\n" "$c_bold" "$c_reset"
        printf "  !! Per sender: cd %s && scripts/nano vector-client-cert <name> --out %s/vector-client-bundles/<name>\n" \
            "$NANO_INSTALL_DIR" "$NANO_INSTALL_DIR"
    fi
    if [[ "${LEGACY_VN_TRUST_SET:-0}" == 1 ]]; then
        printf "  NANO_VECTOR_NATIVE_TRUST_SOURCE_TYPE=true is set in .env: :6000 events keep the source_type\n"
        printf "  their sender declares (as on 0.1.x); only senders with a client certificate can connect.\n"
    fi
    [[ -z "$LEGACY_BACKUP_DIR" ]] || printf "  Backup:   %s (keep it until the upgrade is verified)\n" "$LEGACY_BACKUP_DIR"
    rm -f -- "$LEGACY_MARKER"
fi
echo
echo "  Logs:     cd $NANO_INSTALL_DIR && docker compose ${COMPOSE_ARGS[*]} logs -f"
echo "  Stop:     cd $NANO_INSTALL_DIR && docker compose ${COMPOSE_ARGS[*]} down"
echo "  Reset:    cd $NANO_INSTALL_DIR && docker compose ${COMPOSE_ARGS[*]} down -v   (DELETES ALL DATA)"
echo
# NAN-5404: reported last, after every other step ran.
[[ -z "$AGENTLANE_DEFERRED_FAILURE" ]] || fail "$AGENTLANE_DEFERRED_FAILURE"
}

# Keep this invocation as the final parsed command. When install.sh arrives via
# `curl ... | bash`, Bash must read the complete function body before any child
# can inherit stdin, so Docker or another CLI cannot consume unparsed source.
# The top-level BASH_SOURCE is empty for a streamed script and the file path
# for direct execution; read it here, never from inside main().
NANO_INSTALLER_SCRIPT_PATH="${BASH_SOURCE[0]:-}"
main "$@"
