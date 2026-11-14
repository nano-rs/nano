# shellcheck shell=bash
# NAN-5408: the one rule for NANO_METRICS_BIND_ADDRESS, the address
# docker-compose.metrics-expose.yml publishes nano's metrics on. Sourced by
# install.sh and scripts/nano; scripts/nano-upgrade.py applies the same rule
# (metrics_bind_error). Keep the three in step.
#
# Docker publishes in front of the host firewall, so the address must be a
# private one unless the operator says otherwise with
# NANO_METRICS_ALLOW_PUBLIC=1: on a single-NIC public VM the unauthenticated
# Vector, ClickHouse and node-exporter metrics would otherwise be on the
# internet.

# nano_metrics_bind_error <address> <allow_public>
# Prints why <address> may not be used and returns 1; prints nothing and
# returns 0 when it may. Plain dotted-quad IPv4 only, no leading zeros (so
# 010.0.0.5 or 00.0.0.0 never reach Docker). Private means 10/8, 172.16/12,
# 192.168/16, 100.64/10 (carrier-grade NAT, e.g. Tailscale) or 127/8.
nano_metrics_bind_error() {
    local addr="$1" allow_public="${2:-}"
    local octet='(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])'
    local a b
    if [[ ! "$addr" =~ ^${octet}\.${octet}\.${octet}\.${octet}$ ]]; then
        printf "'%s' is not a plain IPv4 address (four decimal numbers 0-255, no leading zeros)" "$addr"
        return 1
    fi
    a=${BASH_REMATCH[1]} b=${BASH_REMATCH[2]}
    if (( a == 0 )); then
        printf "'%s' is not a host address (0.0.0.0 would publish on every interface)" "$addr"
        return 1
    fi
    if (( a == 10 || a == 127 || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168) \
          || (a == 100 && b >= 64 && b <= 127) )); then
        return 0
    fi
    case "$(printf '%s' "$allow_public" | tr '[:upper:]' '[:lower:]')" in
        1|true|yes|on) return 0 ;;
    esac
    printf "'%s' is a public address: Vector, ClickHouse and node-exporter metrics have no login, and Docker publishes in front of the host firewall. Use the host's private address, or set NANO_METRICS_ALLOW_PUBLIC=1 if a network firewall already limits these ports to your Prometheus" "$addr"
    return 1
}

# nano_metrics_bind_on_host <address>
# Returns 0 when <address> is one of this host's IPv4 addresses (any 127/8
# address binds on Linux). Returns 2 when it cannot tell (no `ip` command).
nano_metrics_bind_on_host() {
    local addr="$1" addrs
    [[ "$addr" == 127.* ]] && return 0
    command -v ip >/dev/null 2>&1 || return 2
    # Collect first: `grep -q` closing a pipe early would fail the pipeline
    # under the installer's pipefail.
    addrs=$(ip -4 -o addr show 2>/dev/null | awk '{ split($4, a, "/"); print a[1] }') || return 2
    grep -qxF -- "$addr" <<< "$addrs"
}
