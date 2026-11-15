# shellcheck shell=bash disable=SC2034  # NETWORK_PIN_* are read by the caller
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# NAN-5387: nano's single-host Compose network, pinned to one subnet.
#
# ClickHouse admits nano's users only from loopback and the networks nano runs
# on (scripts/lib/clickhouse_networks.py). To admit ONE subnet instead of
# Docker's whole address pools (unconfigured: 172.16.0.0/12 and
# 192.168.0.0/16, i.e. every host on a 192.168.x LAN), the subnet must never
# move. So install.sh creates nano's default network itself, with a fixed
# subnet and no Compose config hash:
#
#   * every Compose command (install.sh, scripts/nano, nano upgrade, a bare
#     `docker compose -f docker-compose.opensource.yml up -d`) reuses it as is.
#     Compose only replaces a network whose recorded config hash differs, and
#     this one has none, so no command can move nano off the allow-list;
#   * `docker compose down` leaves it alone (it has no project label);
#   * no overlay file is involved, so nothing has to be remembered for later.
#
# Moving to or from the pinned network is the one time Compose's own network
# must go away, and that happens only in nano_network_pin_apply, right before
# install.sh starts the stack: `docker compose down` (every container goes,
# nothing is reconnected without its DNS aliases), replace the network, and the
# following `up` recreates every service. The state lives in Docker (the
# network and its sh.nano.network-pin label) plus NANO_COMPOSE_SUBNET in .env,
# so an interrupted, failed or prepare-only run is simply re-planned next time.
#
# Usage (install.sh): set COMPOSE_ARGS, source this file, then
#   nano_network_pin_plan "<recorded NANO_COMPOSE_SUBNET>"   # early, before the allow-list render
#   nano_network_pin_apply                                   # right before `compose up`
# Usage (scripts/nano, nano upgrade):
#   bash scripts/lib/network-pin.sh ensure <subnet> <compose args...>
#     recreates a pinned network that has gone missing (an interrupted
#     install.sh, `docker network prune`), so Compose does not make an
#     unpinned one in its place. Never removes or replaces anything.
# Usage (single-node `scripts/nano upgrade`, NAN-5435: the same two steps
# install.sh runs, as commands):
#   bash scripts/lib/network-pin.sh plan <recorded subnet> <compose args...>
#     nano_network_pin_plan; prints
#     "<action>\t<subnet>\t<network>\t<reason>\t<status>" (status: pinnable,
#     managed, or empty when the Compose config could not be read).
#     The caller records <subnet> as NANO_COMPOSE_SUBNET and renders the
#     ClickHouse allow-list from it before ClickHouse restarts.
#   bash scripts/lib/network-pin.sh apply <recorded subnet> <compose args...>
#     plans again from the recorded subnet, then nano_network_pin_apply (a
#     replace or release stops the stack); prints the action it carried out.
#     The caller then starts the whole stack (`up -d`), as install.sh does.
#   bash scripts/lib/network-pin.sh preview <recorded subnet> <compose args...>
#     plan without creating anything (a read-only preflight); a missing
#     network with nothing recorded gives no subnet.

NANO_NETWORK_PIN_HELPER=${NANO_NETWORK_PIN_HELPER:-$(dirname "${BASH_SOURCE[0]}")/compose_network_pin.py}
NANO_NETWORK_PIN_LABEL=sh.nano.network-pin

nano_network_pin_say() { printf '%s\n' "$*" >&2; }

# "<pin label>|<compose config hash>|<subnets>"; empty when the network is absent.
nano_network_pin_inspect() {
    docker network inspect "$1" --format \
        '{{index .Labels "sh.nano.network-pin"}}|{{index .Labels "com.docker.compose.config-hash"}}|{{range .IPAM.Config}}{{.Subnet}} {{end}}' \
        </dev/null 2>/dev/null || true
}

nano_network_pin_create() { # <name> [subnet]
    local args=(network create
        --label "$NANO_NETWORK_PIN_LABEL=install.sh"
        --label com.docker.compose.network=default)
    [[ -n "${2:-}" ]] && args+=(--subnet "$2")
    docker "${args[@]}" "$1" </dev/null >/dev/null
}

nano_network_pin_choose() { # choose args... -> stdout subnet; NETWORK_PIN_REASON on failure
    local out err
    err=$(mktemp "${TMPDIR:-/tmp}/nano-network-pin.XXXXXX")
    if out=$(python3 -I "$NANO_NETWORK_PIN_HELPER" choose "$@" </dev/null 2>"$err"); then
        rm -f "$err"
        printf '%s\n' "$out"
        return 0
    fi
    NETWORK_PIN_REASON=$(sed 's/^compose network pin: //' "$err" | head -1)
    rm -f "$err"
    return 1
}

# Reads the effective Compose graph (COMPOSE_ARGS) and sets NETWORK_PIN_STATUS
# (pinnable|managed|""), NETWORK_PIN_NAME, NETWORK_PIN_PROJECT, NETWORK_PIN_REASON.
nano_network_pin_read_config() {
    local cfg plan
    NETWORK_PIN_STATUS=""; NETWORK_PIN_NAME=""; NETWORK_PIN_PROJECT=""
    NETWORK_PIN_REASON="could not read the Compose config"
    cfg=$(mktemp "${TMPDIR:-/tmp}/nano-compose-config.XXXXXX")
    if docker compose "${COMPOSE_ARGS[@]}" config --format json </dev/null >"$cfg" 2>/dev/null; then
        plan=$(python3 -I "$NANO_NETWORK_PIN_HELPER" plan-config --compose-config "$cfg" </dev/null 2>/dev/null) || plan=""
        if [[ -n "$plan" ]]; then
            NETWORK_PIN_REASON=""
            IFS=$'\t' read -r NETWORK_PIN_STATUS NETWORK_PIN_NAME NETWORK_PIN_PROJECT NETWORK_PIN_REASON <<<"$plan"
        fi
    fi
    rm -f "$cfg"
}

# nano_network_pin_plan <recorded subnet>
# Sets NETWORK_PIN_SUBNET (the pinned subnet, "" when nothing is pinned),
# NETWORK_PIN_ACTION (keep|replace|release|none) and NETWORK_PIN_REASON.
# Creates nano's network when it does not exist yet (a fresh install): nothing
# is attached to a missing network, so that is safe even for a prepare-only run.
nano_network_pin_plan() {
    local recorded="${1:-}" info label hash live allocated
    NETWORK_PIN_SUBNET=""; NETWORK_PIN_ACTION=none
    nano_network_pin_read_config
    [[ -n "$NETWORK_PIN_NAME" ]] || return 0
    info=$(nano_network_pin_inspect "$NETWORK_PIN_NAME")
    IFS='|' read -r label hash live <<<"$info"
    if [[ "$NETWORK_PIN_STATUS" != pinnable ]]; then
        # The operator's Compose files manage the network now. A network nano
        # pinned earlier must go, or Compose would keep reusing it unchanged.
        [[ -n "$info" && -n "$label" ]] && NETWORK_PIN_ACTION=release
        return 0
    fi
    if [[ -z "$info" ]]; then
        if [[ "${NETWORK_PIN_PREVIEW:-0}" == "1" ]]; then
            # Read-only: never create the network.
            if [[ -n "$recorded" ]]; then
                NETWORK_PIN_SUBNET=$(nano_network_pin_choose --recorded "$recorded") || NETWORK_PIN_SUBNET=""
            else
                NETWORK_PIN_REASON="$NETWORK_PIN_NAME does not exist yet"
            fi
            [[ -n "$NETWORK_PIN_SUBNET" ]] && NETWORK_PIN_ACTION=keep
            return 0
        fi
        if [[ -n "$recorded" ]]; then
            NETWORK_PIN_SUBNET=$(nano_network_pin_choose --recorded "$recorded") || { NETWORK_PIN_SUBNET=""; return 0; }
            if ! nano_network_pin_create "$NETWORK_PIN_NAME" "$NETWORK_PIN_SUBNET"; then
                NETWORK_PIN_REASON="could not create $NETWORK_PIN_NAME on $NETWORK_PIN_SUBNET (does another network or route overlap it?)"
                NETWORK_PIN_SUBNET=""
                return 0
            fi
        else
            # Docker picks the subnet: the next one its pools give a new
            # network, clear of every network and route it already knows.
            if ! nano_network_pin_create "$NETWORK_PIN_NAME"; then
                NETWORK_PIN_REASON="could not create $NETWORK_PIN_NAME"
                return 0
            fi
            allocated=$(nano_network_pin_inspect "$NETWORK_PIN_NAME")
            allocated=${allocated##*|}
            if ! NETWORK_PIN_SUBNET=$(nano_network_pin_choose --allocated "$allocated"); then
                NETWORK_PIN_SUBNET=""
                docker network rm "$NETWORK_PIN_NAME" </dev/null >/dev/null 2>&1 || true
                return 0
            fi
        fi
        NETWORK_PIN_ACTION=keep
        return 0
    fi
    NETWORK_PIN_SUBNET=$(nano_network_pin_choose --recorded "$recorded" --existing "$live") || { NETWORK_PIN_SUBNET=""; return 0; }
    if [[ -n "$label" && -z "$hash" && "${live// /}" == "$NETWORK_PIN_SUBNET" ]]; then
        NETWORK_PIN_ACTION=keep
    else
        # Compose's own network (an install from before the pin), or a pin on
        # another subnet: replaced right before the stack starts.
        NETWORK_PIN_ACTION=replace
    fi
}

# Containers still on the network after `docker compose down`: services of
# this project outside the active profiles are removed (Compose would only
# orphan them), anything else is disconnected with a warning.
nano_network_pin_detach() { # <network>
    local id project name
    for id in $(docker network inspect "$1" --format '{{range $id, $c := .Containers}}{{$id}} {{end}}' </dev/null 2>/dev/null); do
        project=$(docker inspect "$id" --format '{{index .Config.Labels "com.docker.compose.project"}}' </dev/null 2>/dev/null || true)
        name=$(docker inspect "$id" --format '{{.Name}}' </dev/null 2>/dev/null || true)
        if [[ -n "$NETWORK_PIN_PROJECT" && "$project" == "$NETWORK_PIN_PROJECT" ]]; then
            docker rm -f "$id" </dev/null >/dev/null || return 1
        else
            nano_network_pin_say "Disconnecting ${name#/} (not part of nano) from $1; reconnect it to the new $1 if it needs nano."
            docker network disconnect -f "$1" "$id" </dev/null >/dev/null || return 1
        fi
    done
}

# Carries out a replace or release (see nano_network_pin_plan). Call it right
# before `docker compose up`, with the same COMPOSE_ARGS and profiles.
nano_network_pin_apply() {
    case "$NETWORK_PIN_ACTION" in
        replace|release) ;;
        *) return 0 ;;
    esac
    docker compose "${COMPOSE_ARGS[@]}" down </dev/null || return 1
    if [[ -n "$(nano_network_pin_inspect "$NETWORK_PIN_NAME")" ]]; then
        nano_network_pin_detach "$NETWORK_PIN_NAME" || return 1
        docker network rm "$NETWORK_PIN_NAME" </dev/null >/dev/null || return 1
    fi
    if [[ "$NETWORK_PIN_ACTION" == replace ]]; then
        nano_network_pin_create "$NETWORK_PIN_NAME" "$NETWORK_PIN_SUBNET" || return 1
        NETWORK_PIN_ACTION=keep
    else
        NETWORK_PIN_ACTION=none
    fi
}

# ensure <subnet> <compose args...>: recreate a missing pinned network.
nano_network_pin_ensure() {
    local subnet="$1"
    shift
    [[ -n "$subnet" ]] || return 0
    COMPOSE_ARGS=("$@")
    nano_network_pin_read_config
    [[ "$NETWORK_PIN_STATUS" == pinnable && -n "$NETWORK_PIN_NAME" ]] || return 0
    [[ -z "$(nano_network_pin_inspect "$NETWORK_PIN_NAME")" ]] || return 0
    subnet=$(nano_network_pin_choose --recorded "$subnet") || return 0
    nano_network_pin_create "$NETWORK_PIN_NAME" "$subnet" \
        && nano_network_pin_say "Recreated nano's pinned network $NETWORK_PIN_NAME on $subnet"
}

# plan|preview|apply <recorded subnet> <compose args...> (see Usage above).
nano_network_pin_command() {
    local command="$1" recorded="$2" planned
    shift 2
    COMPOSE_ARGS=("$@")
    [[ "$command" == preview ]] && NETWORK_PIN_PREVIEW=1
    nano_network_pin_plan "$recorded"
    planned=$NETWORK_PIN_ACTION
    if [[ "$command" == apply ]]; then
        nano_network_pin_apply || return 1
    fi
    printf '%s\t%s\t%s\t%s\t%s\n' "$planned" "$NETWORK_PIN_SUBNET" "$NETWORK_PIN_NAME" \
        "${NETWORK_PIN_REASON:-}" "${NETWORK_PIN_STATUS:-}"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    set -u
    case "${1:-}" in
        ensure) shift; nano_network_pin_ensure "$@" ;;
        plan|preview|apply)
            [[ $# -ge 2 ]] || { nano_network_pin_say "usage: network-pin.sh $1 <recorded subnet> <compose args...>"; exit 2; }
            nano_network_pin_command "$@" ;;
        *) nano_network_pin_say "usage: network-pin.sh ensure|plan|preview|apply <subnet> <compose args...>"; exit 2 ;;
    esac
fi
