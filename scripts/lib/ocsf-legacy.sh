#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# NAN-5559: the two operator steps after a 0.1.x -> 2.x upgrade moved the OCSF
# 1.8 table aside (migration 180: ocsf_logs -> ocsf_logs_legacy_v179), on a
# single-host compose install. Run through scripts/nano:
#
#   scripts/nano ocsf-backfill [--order newest-first|oldest-first] [--from DAY]
#                              [--to DAY] [--dry-run] [--break-lock]
#       Copies the legacy rows into ocsf_logs (scripts/ocsf-legacy-backfill.py)
#       so they are searchable again. ClickHouse's HTTP port is not published
#       on the host: this runs the script with the host's python3 against the
#       ClickHouse container's address on the Compose network, as
#       nanosiem_admin. The password goes to the script in its environment,
#       never on a command line.
#   scripts/nano ocsf-legacy-drop [--confirm]
#       clickhouse_migrator drop-ocsf-legacy in a one-off clickhouse-migrate
#       container: without --confirm a dry run that re-checks every day was
#       copied; with it, drops the legacy table.
#
# Role-split hosts are refused (the legacy table is per ClickHouse shard there;
# nano support runs the script once per shard), and so is a restored legacy
# managed layout, which does not run docker-compose.opensource.yml.
set -euo pipefail
umask 077

die() { printf 'nano: %s\n' "$*" >&2; exit 1; }
log() { printf '==> %s\n' "$*" >&2; }

[[ $# -ge 3 && "$2" == --install-dir ]] || die "usage: ocsf-legacy.sh backfill|drop --install-dir DIR [args]"
subcommand=$1 install_dir=$3
shift 3
[[ -d "$install_dir" ]] || die "install directory not found: $install_dir"
install_dir=$(cd "$install_dir" && pwd -P)
env_file="$install_dir/.env"

usage() {
    case "$subcommand" in
        backfill) printf '%s\n' "usage: scripts/nano ocsf-backfill [--order newest-first|oldest-first] [--from YYYY-MM-DD] [--to YYYY-MM-DD] [--dry-run] [--break-lock]" >&2 ;;
        *) printf '%s\n' "usage: scripts/nano ocsf-legacy-drop [--confirm]" >&2 ;;
    esac
    exit 2
}

# One value of .env (KEY=value; surrounding quotes and CR stripped, last wins).
env_value() {
    awk -v k="$1" '
        index($0, k "=") == 1 {
            v = substr($0, length(k) + 2)
            sub(/\r$/, "", v)
            if (length(v) >= 2 && (v ~ /^".*"$/ || v ~ /^'"'"'.*'"'"'$/)) v = substr(v, 2, length(v) - 2)
        }
        END { print v }
    ' "$env_file"
}

command -v docker >/dev/null 2>&1 || die "docker is required"
[[ -f "$env_file" && -r "$env_file" ]] || die "$env_file is missing or unreadable; run this on the host that runs nano, as the install's owner"
if [[ -f "$install_dir/.nano-role.env" ]]; then
    die "this host is part of a role-split cluster, where the legacy OCSF table is kept per ClickHouse shard. scripts/nano ocsf-backfill and ocsf-legacy-drop handle single-host installs only; contact nano support for the per-shard steps."
fi
if [[ -e "$install_dir/.nano-legacy-layout-restored" ]]; then
    die "this install runs the restored legacy managed layout, not docker-compose.opensource.yml; finish its upgrade to v2 first (docs/administration/upgrades.md, \"Managed v0.1.702 bridge\"), then re-run."
fi
compose_file="$install_dir/docker-compose.opensource.yml"
[[ -f "$compose_file" && ! -L "$compose_file" ]] || die "$compose_file is missing or a symbolic link"
compose_args=(--project-directory "$install_dir" --env-file "$env_file" -f "$compose_file")
read -r -a overlays <<< "$(env_value NANO_COMPOSE_OVERLAYS)"
for overlay in ${overlays[@]+"${overlays[@]}"}; do
    [[ "$overlay" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*\.ya?ml$ && -f "$install_dir/$overlay" && ! -L "$install_dir/$overlay" ]] \
        || die "NANO_COMPOSE_OVERLAYS in .env names a missing, symbolic or invalid file: $overlay"
    compose_args+=(-f "$install_dir/$overlay")
done

case "$subcommand" in
    backfill)
        for arg in "$@"; do
            case "$arg" in -h | --help) usage ;; esac
        done
        command -v python3 >/dev/null 2>&1 || die "python3 is required"
        script="$install_dir/scripts/ocsf-legacy-backfill.py"
        [[ -f "$script" ]] || die "$script is missing; this install's tree is older than the backfill tool"
        cid=$(docker compose "${compose_args[@]}" ps -q clickhouse </dev/null 2>/dev/null || true)
        [[ -n "$cid" && "$cid" != *$'\n'* ]] || die "the clickhouse service is not running (start the stack, then re-run)"
        [[ "$(docker inspect --format '{{.State.Running}}' "$cid" </dev/null 2>/dev/null)" == true ]] \
            || die "the clickhouse container is not running (start the stack, then re-run)"
        # NAN-5880: ClickHouse joins the clickhouse-netns anchor's namespace,
        # which holds the address; an install not yet moved onto it has it on
        # ClickHouse itself.
        netns_cid=$(docker compose "${compose_args[@]}" ps -q clickhouse-netns </dev/null 2>/dev/null || true)
        address=""
        for addr_cid in $netns_cid "$cid"; do
            [[ -n "$address" ]] && break
            address=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{println .IPAddress}}{{end}}' "$addr_cid" </dev/null \
                | awk 'NF && !found { print; found = 1 }')
        done
        [[ "$address" =~ ^[0-9.]+$ ]] || die "could not read the clickhouse container's address on the Compose network"
        password=$(env_value CLICKHOUSE_ADMIN_PASSWORD)
        [[ -n "$password" ]] || die "CLICKHOUSE_ADMIN_PASSWORD is missing from $env_file"
        url="http://$address:8123"
        if ! CH_URL="$url" python3 -I -c '
import os, sys, urllib.request
try:
    urllib.request.urlopen(os.environ["CH_URL"] + "/ping", timeout=5).read()
except Exception as e:
    sys.exit(str(e))
' </dev/null; then
            die "cannot reach ClickHouse at $url from this host. Run this on the Linux host that runs nano (Docker Desktop does not route to container addresses)."
        fi
        log "Backfilling the legacy OCSF table through ClickHouse at $url (nanosiem_admin)"
        # Prefix assignments: the password reaches the script's environment only.
        CH_URL="$url" CH_USER=nanosiem_admin CH_PASSWORD="$password" CLICKHOUSE_CLUSTER="" \
            exec python3 -I -u "$script" "$@"
        ;;
    drop)
        confirm=()
        for arg in "$@"; do
            case "$arg" in
                --confirm) confirm=(--confirm) ;;
                *) usage ;;
            esac
        done
        if ((${#confirm[@]} == 0)); then
            log "Dry run: checking that every legacy day was copied (add --confirm to drop the legacy table)"
        else
            log "Dropping the legacy OCSF table once every day is confirmed copied"
        fi
        exec docker compose "${compose_args[@]}" run --rm --no-deps clickhouse-migrate \
            clickhouse_migrator drop-ocsf-legacy ${confirm[@]+"${confirm[@]}"}
        ;;
    *) die "unknown command: $subcommand" ;;
esac
