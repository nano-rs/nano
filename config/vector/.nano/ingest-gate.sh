#!/bin/sh
# nano single-node ingest gate (NAN-5566): close or open Vector's directly
# published push listeners WITHOUT restarting Vector.
#
#   sh /etc/vector/.nano/ingest-gate.sh close|open|status
#
# The Vector entrypoint (vector-entrypoint.sh, NANO_VECTOR_INGEST_GATE=on) points
# the listen addresses of http_ingest (:8080), splunk_hec_ingest (:8088), OTLP
# (:4317/:4318) and vector_native (:6000) at a Vector `file` secret backend. Closing
# rewrites that file with loopback-only addresses on other ports and reloads
# Vector (SIGHUP to PID 1 after checking it is the Vector binary). Only those
# sources are rebuilt; no sink or buffer changes. A sender on a published port then
# gets "connection refused" (nothing is acknowledged; it retries), while requests
# already in flight finish normally. Opening restores the published addresses.
#
# `close` and `open` wait (NANO_INGEST_GATE_WAIT, default 180 s: a reload compiles
# the config) until the :8080 listener is gone or back, read from /proc/net/tcp*.
# Exit status: 0 done, 1 timed out, 2 this Vector runs without the gate (started
# before it existed, or its setup failed), 3 Vector is still starting (status and
# open answer at once; close waits first; nothing listens yet).
set -u

G="${NANO_INGEST_GATE_DIR:-/tmp/nano-ingest-gate}"
VECTOR=/usr/bin/vector
WAIT="${NANO_INGEST_GATE_WAIT:-180}"
case "$WAIT" in ''|*[!0-9]*) WAIT=180 ;; esac

# Is anything listening on all interfaces on :8080 (0x1F90)?
http_listening() {
    awk 'FNR > 1 && $4 == "0A" && ($2 == "00000000:1F90" || $2 == "00000000000000000000000000000000:1F90") { found = 1 }
         END { exit !found }' /proc/net/tcp /proc/net/tcp6 2>/dev/null
}

# The entrypoint writes the backend config LAST (after open.json, closed.json
# and the open addresses.json), so a close never races its open copy.
gate_ready() {
    [ -f "$G/open.json" ] && [ -f "$G/closed.json" ] && [ -f "$G/config/nano-ingest-gate.toml" ]
}

waited=0
if ! gate_ready; then
    if [ "${NANO_VECTOR_INGEST_GATE:-}" != on ]; then
        echo "nano-ingest-gate: this Vector was started without the ingest gate" >&2
        exit 2
    fi
    # The container's entrypoint sets the gate up just before it starts Vector
    # (after the pipeline gate and the cold-start checks); until then nothing
    # listens. status/open answer at once; close waits (bounded) so it is not
    # lost to a Vector that starts listening right after.
    case "${1:-}" in
        status) echo starting; exit 3 ;;
        open) echo "nano-ingest-gate: Vector is still starting; it starts open" >&2; exit 3 ;;
    esac
    while ! gate_ready; do
        if [ "$waited" -ge "$WAIT" ]; then
            if [ "$(readlink /proc/1/exe 2>/dev/null)" = "$VECTOR" ] || http_listening; then
                # Vector runs, but its gate was never set up: it cannot be closed.
                echo "nano-ingest-gate: Vector runs without its ingest gate (setup failed at start)" >&2
                exit 2
            fi
            echo "nano-ingest-gate: Vector is still starting after ${WAIT}s (its ports are not listening yet)" >&2
            exit 3
        fi
        sleep 1
        waited=$((waited + 1))
    done
fi

apply() {
    cp "$G/$1.json" "$G/.addresses.tmp" && mv -f "$G/.addresses.tmp" "$G/addresses.json" || exit 1
    if [ "$(readlink /proc/1/exe 2>/dev/null)" != "$VECTOR" ]; then
        echo "nano-ingest-gate: PID 1 is not Vector (still starting); it applies the $1 state when it starts" >&2
        return 0
    fi
    kill -HUP 1 || exit 1
    # One deadline for the whole call (the gate wait above counts against it).
    while :; do
        if [ "$1" = closed ]; then http_listening || return 0; else http_listening && return 0; fi
        [ "$waited" -ge "$WAIT" ] && {
            echo "nano-ingest-gate: Vector did not apply the $1 state within ${WAIT}s" >&2
            exit 1
        }
        sleep 1
        waited=$((waited + 1))
    done
}

case "${1:-}" in
    close) apply closed; echo "nano-ingest-gate: closed (published ingest ports refuse connections)" ;;
    open) apply open; echo "nano-ingest-gate: open" ;;
    status) if [ "$(cat "$G/addresses.json" 2>/dev/null)" = "$(cat "$G/closed.json")" ]; then echo closed; else echo open; fi ;;
    *) echo "usage: $0 close|open|status" >&2; exit 64 ;;
esac
