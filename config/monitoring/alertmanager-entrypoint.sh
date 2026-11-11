#!/bin/sh
# nano monitoring Alertmanager (NAN-5250): renders its config, then runs it.
#
# Alertmanager receives the alerts the monitoring Prometheus evaluates
# (config/prometheus/rules). Self-ingest is off by default. With
# NANO_SELF_INGEST_TOKEN set (a source-bound nano ingest token), every alert
# notification is POSTed, as one JSON event, to nano's HTTP ingest
# (NANO_SELF_INGEST_URL), so nano's own health alerts are searchable in nano
# and detections can run on them. The always-firing NanoHeartbeat alert is
# re-sent every 5 minutes, so a detection can tell "healthy" from "stopped".
# Without a token, alerts go to a receiver that sends nothing.
#
# The token reaches Alertmanager as a file on a private tmpfs, never in the
# rendered config or on a command line.
#
#   alertmanager-entrypoint.sh                run Alertmanager
#   alertmanager-entrypoint.sh --render-only  print the rendered config (tests)
set -eu
umask 077
dir=/run/nano-alertmanager
config="$dir/alertmanager.yml"
token="${NANO_SELF_INGEST_TOKEN:-}"
url="${NANO_SELF_INGEST_URL:-}"
unset NANO_SELF_INGEST_TOKEN

if [ -n "$token" ]; then
    case "$url" in
        http://*|https://*) ;;
        *) echo "NANO_SELF_INGEST_URL must be an http(s) URL to nano's ingest (got '$url')" >&2; exit 1 ;;
    esac
    case "$url" in
        *"'"*|*'"'*|*' '*) echo "NANO_SELF_INGEST_URL must not contain quotes or spaces" >&2; exit 1 ;;
    esac
    printf '%s' "$token" > "$dir/self-ingest-token"
    receiver=$(cat <<EOF
  - name: nano
    webhook_configs:
      - url: '$url'
        send_resolved: true
        max_alerts: 50
        http_config:
          authorization:
            type: Bearer
            credentials_file: $dir/self-ingest-token
EOF
)
else
    receiver="  - name: nano"
fi
token=""

cat > "$config" <<EOF
# Rendered by alertmanager-entrypoint.sh at start; edits are overwritten.
route:
  receiver: nano
  group_by: [alertname, host]
  group_wait: 30s
  group_interval: 1m
  repeat_interval: 4h
  routes:
    - matchers: ['alertname="NanoHeartbeat"']
      receiver: nano
      repeat_interval: 5m
receivers:
$receiver
EOF

if [ "${1:-}" = "--render-only" ]; then
    cat "$config"
    exit 0
fi
exec /bin/alertmanager \
    --config.file="$config" \
    --storage.path=/alertmanager \
    --cluster.listen-address= \
    --web.listen-address=0.0.0.0:9093
