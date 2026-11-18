# shellcheck shell=bash
# NAN-5566: stop a single node's Vector without losing acknowledged events.
#
# Sourced by scripts/nano (backup, restore, convert) and install.sh. The caller
# defines `nano_vq_compose` (its `docker compose ...` with the right project and
# files) and `log` / `warn`.
#
#   nano_vq_close       Vector moves its published listeners (:8080, :8088, OTLP,
#                       :6000) to loopback-only ports by a hot reload (direct
#                       senders get "connection refused"), and nginx answers every
#                       ingest route (/ingest, /enrichment, /otlp) with 503 +
#                       Retry-After (marker on a tmpfs, so a restart of nginx
#                       reopens it). Nothing new reaches Vector.
#   nano_vq_drain SECS  wait until Vector's buffers hold no event AND its
#                       ClickHouse sinks settled every event they took (a buffer's
#                       count falls when the sink reads, not when it delivers),
#                       with the counters still on two scrapes; bounded, logged.
#   nano_vq_stop        `docker compose stop` Vector with a timeout longer than
#                       its graceful-shutdown limit (60 s): sources close, the
#                       rest reaches its disk buffers.
#   nano_vq_reopen [SECS]  open Vector's gate if it reports closed and remove the
#                       nginx marker whenever nginx runs (after a bounded wait for
#                       Vector's health when this shell closed it). Idempotent and
#                       independent of this shell's state; safe in an EXIT trap.
#
# A Vector started before the gate existed cannot close its own ports (warned);
# for its direct senders the stop itself is the close. The drain is bounded.

NANO_VQ_MARKER=/run/nano-ingest/closed
NANO_VQ_STOP_TIMEOUT="${NANO_VQ_STOP_TIMEOUT:-120}"
NANO_VQ_CLOSED=0
# Set once this shell started closing ingest: its exit paths must reopen.
NANO_VQ_ENGAGED=0
# Set when nginx had to be stopped to close ingest (its config ignores the marker).
NANO_VQ_NGINX_STOPPED=0

# Vector's metrics, from inside its container (curl, wget or bash /dev/tcp).
NANO_VQ_METRICS='
if command -v curl >/dev/null 2>&1; then curl -fsS http://127.0.0.1:9598/metrics
elif command -v wget >/dev/null 2>&1; then wget -qO- http://127.0.0.1:9598/metrics
else exec 3<>/dev/tcp/127.0.0.1/9598
printf "GET /metrics HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n" >&3
cat <&3
fi'

nano_vq_running() {
    nano_vq_compose ps --status running --services </dev/null 2>/dev/null | grep -x "$1" >/dev/null
}

nano_vq_close() {
    # shellcheck disable=SC2034  # read by the scripts that source this file (install.sh, scripts/nano)
    NANO_VQ_ENGAGED=1
    nano_vq_close_vector
    nano_vq_running nginx || return 0
    if ! nano_vq_compose exec -T nginx sh -c "mkdir -p /run/nano-ingest && touch $NANO_VQ_MARKER" \
        </dev/null >/dev/null 2>&1; then
        warn "could not close ingest at nginx; Vector drains under live ingest (its own shutdown closes its sources first)"
        return 0
    fi
    # Set as soon as the marker exists, so every exit path reopens it.
    NANO_VQ_CLOSED=1
    # Load the current config: one from before NAN-5566 has no marker check.
    nano_vq_compose exec -T nginx nginx -s reload </dev/null >/dev/null 2>&1 || true
    if ! nano_vq_closed_answer; then
        # A bundle upgrade replaces config/nginx with a new directory: the
        # running nginx keeps the old one and a reload re-reads the old config.
        # Recreate it onto the current files (with the marker's tmpfs), close again.
        log "nginx did not answer the closed 503 (its running config predates the marker); recreating it"
        nano_vq_compose up -d --no-deps --force-recreate nginx </dev/null >/dev/null 2>&1 || true
        local tries=0
        until nano_vq_compose exec -T nginx sh -c "mkdir -p /run/nano-ingest && touch $NANO_VQ_MARKER" \
                </dev/null >/dev/null 2>&1 && nano_vq_closed_answer; do
            tries=$((tries + 1))
            ((tries < 30)) || break
            sleep 2
        done
    fi
    if nano_vq_closed_answer; then
        log "closed ingest at nginx (503 + Retry-After) while Vector drains and restarts"
        return 0
    fi
    # Last resort (the install tree's nginx config predates the marker, e.g. the
    # release package was not extracted over the install): stop nginx for the
    # window so ingest through it is refused; every reopen path starts it.
    NANO_VQ_NGINX_STOPPED=1
    nano_vq_compose stop --timeout 10 nginx </dev/null >/dev/null 2>&1 || true
    if nano_vq_running nginx; then
        warn "nginx still accepts ingest after the close: the drain runs under live ingest, and events in flight when Vector stops can be lost. Pause senders for this step."
    else
        warn "nginx's config does not honor the ingest-closed marker (was the release package extracted over the install directory?): stopped nginx while Vector drains and restarts, so ingest through it is refused"
    fi
}

# NAN-5566: a Vector from 2.0.31 or older has no ingest gate, so senders that post to
# its published ports directly (:8080, :8088, OTLP, :6000) cannot be closed before
# it stops; an event in flight then can be lost (NAN-5567). The operator pauses them
# first: confirmed on a terminal, or for automation NANO_CONFIRM_SENDERS_PAUSED=1
# (NANO_CONFIRM_UPGRADE=1 and NANO_CONFIRM_LEGACY_UPGRADE=1 confirm it too).
# Anything else stops here, before Vector is touched.
NANO_VQ_SENDERS_CONFIRMED=0
nano_vq_confirm_senders_paused() {
    local answer=""
    ((NANO_VQ_SENDERS_CONFIRMED)) && return 0
    warn "Vector here predates the ingest gate (nano 2.0.31 or older): pause every sender that posts to its ports directly (:8080, :8088, OTLP, :6000) before it is stopped, or events in flight can be lost. Senders through nginx (/ingest) are closed automatically."
    local flag
    # The installer's and upgrader's existing unattended confirmations count too.
    for flag in NANO_CONFIRM_SENDERS_PAUSED NANO_CONFIRM_UPGRADE NANO_CONFIRM_LEGACY_UPGRADE; do
        if [[ "${!flag:-}" == 1 ]]; then
            log "$flag=1: going on with the senders that post to Vector directly paused"
            NANO_VQ_SENDERS_CONFIRMED=1
            return 0
        fi
    done
    if (exec </dev/tty) 2>/dev/null; then
        printf 'Are senders that post to Vector directly paused? [y/N] ' >/dev/tty
        IFS= read -r answer </dev/tty || answer=""
        case "$answer" in
            y|Y|yes|YES|Yes) NANO_VQ_SENDERS_CONFIRMED=1; return 0 ;;
        esac
    fi
    printf '%s\n' "Stopped before touching Vector: pause the senders that post to its ports directly, then re-run (non-interactive: set NANO_CONFIRM_SENDERS_PAUSED=1; NANO_CONFIRM_UPGRADE=1 or NANO_CONFIRM_LEGACY_UPGRADE=1 confirm it too)." >&2
    exit 1
}

# Does nginx answer /ingest with its closed 503 on the published port (what a
# sender sees; the TLS edge redirects :80 to :443)? Asked from the host.
declare -F nano_vq_closed_answer >/dev/null || nano_vq_closed_answer() {
    python3 -I - <<'PY' >/dev/null 2>&1
import ssl, sys, urllib.error, urllib.request
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None
context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE
opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), NoRedirect())
for url in ("http://127.0.0.1/ingest", "https://127.0.0.1/ingest"):
    request = urllib.request.Request(url, data=b"{}", method="POST", headers={"Content-Type": "application/json"})
    try:
        with opener.open(request, timeout=5) as response:
            status, headers = response.status, response.headers
    except urllib.error.HTTPError as error:
        status, headers = error.code, error.headers
    except (OSError, ValueError):
        continue
    if status == 503 and str(headers.get("X-Nano-Ingest", "")).lower() == "closed":
        sys.exit(0)
    if status not in (301, 302, 307, 308):
        sys.exit(1)
sys.exit(1)
PY
}

# Vector's own published listeners (:8080, :8088, OTLP, :6000): moved to loopback-only
# ports by a hot reload (config/vector/.nano/ingest-gate.sh), so a sender posting to them
# directly gets "connection refused" instead of a 200.
nano_vq_close_vector() {
    local rc=0
    nano_vq_running vector || return 0
    nano_vq_compose exec -T vector sh /etc/vector/.nano/ingest-gate.sh close </dev/null >/dev/null 2>&1 || rc=$?
    case "$rc" in
        0) log "closed Vector's published ingest ports (senders get connection refused and retry)" ;;
        3) log "Vector is still starting: its ports are not listening yet, nothing to close" ;;
        2|126|127) warn "this Vector was started before the ingest gate (NAN-5566): senders posting to its ports directly are closed only by its own shutdown"
           nano_vq_confirm_senders_paused ;;
        *) warn "Vector did not confirm closing its published ingest ports; draining anyway" ;;
    esac
}

# One scrape of Vector's metrics, reduced to "<buffered> <sink received> <sink sent>":
# events in its buffers (all but the metrics exporter), and the events its ClickHouse
# sinks took and settled (delivered, or discarded after an error, which no wait
# changes). Nothing when Vector cannot be asked.
nano_vq_counters() {
    nano_vq_compose exec -T vector bash -c "$NANO_VQ_METRICS" </dev/null 2>/dev/null \
        | awk '
            $0 ~ /^#/ { next }
            { v = (NF >= 3 ? $(NF-1) : $NF) }
            ($1 ~ /(^|_)vector_buffer_events(\{|$)/ || $1 ~ /(^|_)vector_buffer_size_events(\{|$)/) \
                && $0 !~ /component_id="prometheus_metrics"/ { b += v; n++ }
            $1 ~ /(^|_)component_received_events_total\{/ && /component_kind="sink"/ && /component_type="clickhouse"/ { r += v }
            ($1 ~ /(^|_)component_sent_events_total\{/ || $1 ~ /(^|_)component_discarded_events_total\{/) \
                && /component_kind="sink"/ && /component_type="clickhouse"/ { t += v }
            END { if (n) printf "%d %d %d\n", b, r, t }'
}

# Drained = nothing in any buffer AND every event the ClickHouse sinks took was
# delivered (a disk buffer's count falls when the sink reads, not when it delivers),
# on two scrapes in a row with the counters standing still.
nano_vq_drain() {
    local limit="${1:-120}" started now line prev="" buffered received sent stable=0
    nano_vq_running vector || return 0
    started=$(date +%s)
    while :; do
        line=$(nano_vq_counters) || line=""
        if [[ -z "$line" ]]; then
            warn "cannot read Vector's buffer metrics; stopping it without a drain check"
            return 0
        fi
        read -r buffered received sent <<<"$line"
        if [[ "$buffered" == 0 && "$received" == "$sent" && "$line" == "$prev" ]]; then
            stable=$((stable + 1))
            ((stable >= 1)) && { log "Vector is drained: its buffers are empty and its sinks delivered every event they took"; return 0; }
        else
            stable=0
        fi
        prev="$line"
        now=$(date +%s)
        if ((now - started >= limit)); then
            warn "Vector is not drained after ${limit}s ($buffered buffered, $((received - sent)) taken but not yet delivered): buffered events stay in its disk buffers across the restart"
            return 0
        fi
        (((now - started) % 10 == 0)) && log "draining Vector: $buffered buffered, $((received - sent)) in flight to ClickHouse"
        sleep 1
    done
}

nano_vq_stop() {
    nano_vq_running vector || return 0
    nano_vq_compose stop --timeout "$NANO_VQ_STOP_TIMEOUT" vector </dev/null >/dev/null
}

# Idempotent and independent of this shell's state (a failed earlier run may have
# left ingest closed): opens Vector's gate when it reports closed, and removes the
# nginx marker whenever nginx runs. Waits (bounded) for Vector's health first only
# when this shell closed ingest.
nano_vq_reopen() {
    local limit="${1:-180}" started rc=0
    if nano_vq_running vector \
        && [[ "$(nano_vq_compose exec -T vector sh /etc/vector/.nano/ingest-gate.sh status </dev/null 2>/dev/null)" == closed* ]]; then
        nano_vq_compose exec -T vector sh /etc/vector/.nano/ingest-gate.sh open </dev/null >/dev/null 2>&1 || rc=$?
        if ((rc == 0)); then
            log "reopened Vector's published ingest ports"
        else
            warn "could not confirm Vector reopened its published ports; run: docker compose exec vector sh /etc/vector/.nano/ingest-gate.sh open"
        fi
    fi
    if ((NANO_VQ_CLOSED)); then
        started=$(date +%s)
        while nano_vq_running vector && (( $(date +%s) - started < limit )); do
            nano_vq_compose exec -T vector bash -c \
                "exec 3<>/dev/tcp/127.0.0.1/8686 && printf 'GET /health HTTP/1.0\r\n\r\n' >&3 && grep -q ' 200 ' <&3" \
                </dev/null >/dev/null 2>&1 && break
            sleep 2
        done
    fi
    if ((NANO_VQ_NGINX_STOPPED)); then
        nano_vq_compose start nginx </dev/null >/dev/null 2>&1 \
            || nano_vq_compose up -d --no-deps nginx </dev/null >/dev/null 2>&1 || true
        if nano_vq_running nginx; then
            NANO_VQ_NGINX_STOPPED=0
            log "started nginx again"
        else
            warn "could not start nginx again; run: docker compose up -d nginx"
            return 1
        fi
    fi
    nano_vq_running nginx || { NANO_VQ_CLOSED=0; return 0; }
    if nano_vq_compose exec -T nginx rm -f "$NANO_VQ_MARKER" </dev/null >/dev/null 2>&1; then
        ((NANO_VQ_CLOSED)) && log "reopened ingest at nginx"
        NANO_VQ_CLOSED=0
    else
        warn "could not reopen ingest at nginx; run: docker compose exec nginx rm -f $NANO_VQ_MARKER"
        return 1
    fi
}
