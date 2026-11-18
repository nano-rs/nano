#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# nano public benchmark: thin run script. Everything heavy is existing nano
# tooling: the enterprise bundle's install.sh and role-split renderer, the
# nano-deploy helpers (fetch-bundle, make-private-ca, admin-credentials),
# tools/log-blaster, and k6. This script only sequences them over SSH and
# turns the run into one results JSON (lib/collect.py).
#
#   benchmarks/public/run.sh <step> --topology benchmarks/public/topology/<name>/hosts.env [options]
#
# Steps (in order; each is safe to re-run):
#   prep        data disk -> /var/lib/docker, host firewall (cluster + operator only)
#   install     enterprise bundle, inventory, private TLS, shared .env, install.sh by role
#   content     parsers + log sources + ingest tokens + detection set + API key (+ Agent Lane tokens)
#   tools       build log-blaster (seeded) and install k6 on the blaster host(s)
#   smoke       one marker through every source; checks ingest -> searchable
#   socday      steady ingest at --gb-per-day + k6 SOC mix, for --duration
#   ceiling     stepped ramp until an SLO breaks (lag p99 > 60 s, loss, or errors)
#   collect     pull run artifacts + ClickHouse metrics -> results/<run>.json
#   all-dry     prep install content tools smoke socday ceiling (dry-run sizes)
#
# Secrets (license, admin password, ingest/API/Agent Lane tokens, registry
# credential) live only on the hosts in 0600 files. They are streamed host to
# host through this workstation's SSH pipes and are never printed or written
# locally. The private CA key stays in --pki (keep it out of the repo).
# Paths like "~/nano/.env" are expanded on the remote host, not here.
# shellcheck disable=SC2088
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
DEPLOY="$REPO/skills/nano-deploy/scripts"

STEP="${1:-}"; shift || true
TOPOLOGY="" ; PKI="" ; ENROLL_FROM="" ; RUN_ID="" ; DURATION="10m" ; GBPD="50"
PROFILE="" ; AGENTS=0 ; OUT_DIR="$HERE/results" ; DURATION_SET=0 ; GBPD_SET=0 ; AGENTS_SET=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --topology) TOPOLOGY="$2"; shift 2 ;;
    --pki) PKI="$2"; shift 2 ;;
    --enrollment-cmd) ENROLL_FROM="$2"; shift 2 ;;   # a command that prints enrollment.env to stdout
    --run-id) RUN_ID="$2"; shift 2 ;;
    --duration) DURATION="$2"; DURATION_SET=1; shift 2 ;;
    --gb-per-day) GBPD="$2"; GBPD_SET=1; shift 2 ;;
    --profile) PROFILE="$2"; shift 2 ;;
    --agents) AGENTS="$2"; AGENTS_SET=1; shift 2 ;;
    --out) OUT_DIR="$2"; shift 2 ;;
    -h|--help) sed -n 2,30p "$0"; exit 0 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
[[ -n "$STEP" && -n "$TOPOLOGY" ]] || { sed -n 2,30p "$0"; exit 2; }
# shellcheck disable=SC1090
. "$TOPOLOGY"
: "${BENCH_NAME:?}" "${SSH_KEY:?}" "${APP:?}" "${CH:?}" "${INGEST:?}" "${BLASTER:?}"
# A profile (profiles/*.json) sets the seeded blaster and load parameters;
# explicit CLI flags still win.
if [[ -n "$PROFILE" ]]; then
  [[ -f "$PROFILE" ]] || PROFILE="$HERE/profiles/$PROFILE.json"
  CLI_DURATION="$DURATION"; CLI_AGENTS="$AGENTS"
  eval "$(python3 -c 'import json,shlex,sys
for k, v in json.load(open(sys.argv[1])).items():
    if k.isupper(): print(f"{k}={shlex.quote(str(v))}")' "$PROFILE")"
  [[ "$DURATION_SET" == 1 ]] && DURATION="$CLI_DURATION"
  [[ "$AGENTS_SET" == 1 ]] && AGENTS="$CLI_AGENTS"
  [[ "$GBPD_SET" == 1 ]] || GBPD="${GB_PER_DAY:-$GBPD}"
fi
NANO_VERSION="${NANO_VERSION:-2.0.23}"
SEED="${SEED:-20261114}"
RUN_ID="${RUN_ID:-${BENCH_NAME}-$(date -u +%Y%m%dT%H%M%SZ)}"
# The run id lands in file names and ClickHouse string literals: keep it plain.
[[ "$RUN_ID" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "--run-id may only use letters, digits, '.', '_' and '-'" >&2; exit 2; }
# prep + install (and the SSH, private-address and inventory helpers below them)
# live in the nano-deploy skill, shared with `scripts/nano cluster`.
# shellcheck source=../../skills/nano-deploy/scripts/role-split-install.sh
. "$DEPLOY/role-split-install.sh"
rsi_load

# ---------------------------------------------------------------------------
step_content() {
  say "content (parsers, sources, tokens, $(python3 -c "import json;print(json.load(open('$HERE/detections/rules.json'))['count'])") rules, API key)"
  r "$APP" 'mkdir -p ~/bench && chmod 700 ~/bench'
  r "$APP" 'cat > ~/bench/setup_content.py' < "$HERE/lib/setup_content.py"
  r "$APP" 'cat > ~/bench/rules.json' < "$HERE/detections/rules.json"
  r "$APP" "python3 -I ~/bench/setup_content.py --out ~/bench --rules ~/bench/rules.json --agentlane $AGENTS --run-tag ${RUN_ID//[^A-Za-z0-9]/}"
  for b in "${BLASTERS[@]}"; do
    r "$b" 'mkdir -p ~/bench && chmod 700 ~/bench'
    for f in tokens.json api.env; do pipe "$APP" "~/bench/$f" "$b" "~/bench/$f"; done
    [[ "$AGENTS" -gt 0 ]] && pipe "$APP" "~/bench/agentlane.json" "$b" "~/bench/agentlane.json" || true
  done
  mkdir -p "$OUT_DIR/$RUN_ID"
  r "$APP" 'cat ~/bench/content.json' > "$OUT_DIR/$RUN_ID/content.json"
  r "$APP" 'cat ~/bench/content-rules.json 2>/dev/null' > "$OUT_DIR/$RUN_ID/content-rules.json" || rm -f "$OUT_DIR/$RUN_ID/content-rules.json"
}

# ---------------------------------------------------------------------------
step_tools() {
  local src; src="$(mktemp -d)"
  export COPYFILE_DISABLE=1   # macOS tar: no extended-attribute headers
  # Minimal two-crate workspace: the root manifest's [workspace.*] tables plus
  # event-core and log-blaster, so the blaster builds without the whole repo.
  python3 - "$REPO/Cargo.toml" > "$src/Cargo.toml" <<'PY'
import re, sys
text = open(sys.argv[1]).read()
keep, out, cur = ("workspace.package", "workspace.dependencies", "profile.release"), [], None
for line in text.splitlines():
    m = re.match(r"^\[([^\]]+)\]\s*$", line)
    if m:
        cur = m.group(1)
        if cur in keep:
            out.append(line)
        continue
    if cur in keep:
        out.append(line)
print('[workspace]\nresolver = "2"\nmembers = ["tools/event-core", "tools/log-blaster"]\n')
print("\n".join(out))
PY
  for b in "${BLASTERS[@]}"; do
    say "build log-blaster on $b (rust:1 container) + k6"
    tar -C "$REPO" -czf - Cargo.lock rust-toolchain.toml tools/event-core tools/log-blaster -C "$src" Cargo.toml \
      | r "$b" 'rm -rf ~/lb && mkdir -p ~/lb && tar -xzf - -C ~/lb'
    r "$b" 'set -e; cd ~/lb && docker run --rm -v "$PWD":/src -w /src -e CARGO_HOME=/src/.cargo rust:1-bookworm \
        bash -c "rustup show >/dev/null 2>&1; cargo build --release -p log-blaster 2>&1 | tail -2" &&
      sudo install -m 0755 target/release/log-blaster /usr/local/bin/log-blaster && log-blaster --help | head -1'
    r "$b" 'set -e; command -v k6 >/dev/null || { curl -fsSL https://github.com/grafana/k6/releases/download/v0.54.0/k6-v0.54.0-linux-amd64.tar.gz | tar -xz -C /tmp && sudo install -m 0755 /tmp/k6-v0.54.0-linux-amd64/k6 /usr/local/bin/k6; }; k6 version'
    tar -C "$REPO" -czf - benchmarks/public/k6 benchmarks/public/dashboards benchmarks/results/soc_ir_corpus.json skills/nano-agentlane/references/recipes.sql \
      | r "$b" 'rm -rf ~/k6w && mkdir -p ~/k6w && tar -xzf - -C ~/k6w'
  done
  rm -rf "$src"
}

# ---------------------------------------------------------------------------
# hoststat: 5 s samples of CPU busy %, memory used %, docker disk used %, load.
start_hoststat() {
  for h in "${ALL_HOSTS[@]}"; do
    r "$h" "mkdir -p ~/bench && pkill -f '[n]ano-bench-hoststat' || true; nohup bash ~/bench/hoststat.sh ~/bench/hoststat-$RUN_ID-$SCENARIO.csv >/dev/null 2>&1 &" < /dev/null
  done
}
push_hoststat() { for h in "${ALL_HOSTS[@]}"; do r "$h" 'mkdir -p ~/bench && cat > ~/bench/hoststat.sh' < "$HERE/lib/hoststat.sh"; done; }
stop_hoststat() { for h in "${ALL_HOSTS[@]}"; do r "$h" 'pkill -f "[n]ano-bench-hoststat" || true'; done; }

# Run one blast phase on every blaster process, spread across ingest hosts.
# $1 eps (total), $2 seconds, $3 phase label
blast() {
  local eps="$1" secs="$2" label="$3" procs="${BLAST_PROCS:-1}" n=0 total
  total=$(( ${#BLASTERS[@]} * procs ))
  for b in "${BLASTERS[@]}"; do
    for ((p = 0; p < procs; p++)); do
      # ACTIVE_INGEST=N sends to the first N ingest hosts only (the "add one
      # ingest host" comparison without reinstalling the cluster).
      local active="${ACTIVE_INGEST:-${#INGEST_HOSTS[@]}}"
      local ing; ing="$(priv "${INGEST_HOSTS[$(( n % active ))]}")"
      local rid="$RUN_ID-$label-p$n"
      r "$b" "nohup log-blaster --vector http://$ing/ingest/ --tokens-file ~/bench/tokens.json --blast \
          --eps $(( eps / total )) --threads ${BLAST_THREADS:-8} --batch-size ${BLAST_BATCH:-500} \
          --assets ${ASSETS:-5000} --chain-interval-secs 0 --seed $(( SEED + n )) --run-id $rid --duration-secs $secs \
          --summary-json ~/bench/blaster-$rid.json --max-retries 3 -q > ~/bench/blaster-$rid.log 2>&1 &" < /dev/null
      n=$((n + 1))
    done
  done
}

# Poll in short SSH sessions: a dropped connection during a 4 h run must not
# end the wait (the senders and k6 run under nohup on the hosts).
wait_remote() { # host, shell test that is true while the work is still running
  local h="$1" t="$2"
  while :; do
    r "$h" "for i in \$(seq 1 60); do $t || exit 0; sleep 5; done; exit 3" < /dev/null && return 0
    sleep 5
  done
}
wait_blasters() { local b; for b in "${BLASTERS[@]}"; do wait_remote "$b" 'pgrep -x log-blaster >/dev/null'; done; }

step_smoke() {
  say "smoke: 30 s at 50 eps through every source, then marker count"
  push_hoststat
  blast 50 30 smoke
  wait_blasters
  sleep 20
  python3 "$HERE/lib/collect.py" --topology "$TOPOLOGY" --run-id "$RUN_ID" --phases smoke --out "$OUT_DIR" --quick
}

step_socday() {
  SCENARIO=socday
  local eps; eps=$(python3 -c "print(round($GBPD * 1e9 / 86400 / ${AVG_EVENT_BYTES:-980}))")
  local secs; secs=$(python3 -c "import re;m=re.fullmatch(r'(\d+)([smh])','$DURATION');print(int(m[1])*{'s':1,'m':60,'h':3600}[m[2]])")
  say "socday: $GBPD GB/day ~= $eps eps for $DURATION, k6 SOC mix (agents=$AGENTS)"
  push_hoststat; start_hoststat
  date -u +%FT%TZ > "$OUT_DIR/.socday-start-$RUN_ID"
  blast "$eps" "$secs" "socday"
  local b="${BLASTERS[0]}"
  # k6 runs detached on the load generator (the run lasts hours); we poll it.
  r "$b" "cd ~/k6w/benchmarks/public/k6 && set -a && . ~/bench/api.env && set +a &&
    { APP_URL=http://$(priv "$APP") DURATION=$DURATION ANALYSTS=${ANALYSTS:-5} DASHBOARDS=${DASHBOARD_VIEWERS:-3} AGENTS=$AGENTS \
    NAL_TOKENS_FILE=\$( [ $AGENTS -gt 0 ] && echo ~/bench/agentlane.json ) NAL_TABLE_SUFFIX=${NAL_TABLE_SUFFIX:-} \
    RESULTS_FILE=\$HOME/bench/k6-socday-$RUN_ID.json nohup setsid k6 run --quiet soc_mix.js > ~/bench/k6-socday-$RUN_ID.log 2>&1 < /dev/null &
    echo \$! > ~/bench/k6-socday-$RUN_ID.pid; }" < /dev/null
  wait_remote "$b" "kill -0 \$(cat ~/bench/k6-socday-$RUN_ID.pid) 2>/dev/null"
  wait_blasters
  stop_hoststat
  python3 "$HERE/lib/collect.py" --topology "$TOPOLOGY" --run-id "$RUN_ID" --phases socday --scenario socday \
    --gb-per-day "$GBPD" --out "$OUT_DIR"
}

step_ceiling() {
  SCENARIO=ceiling
  # Stepped ramp. Each step holds STEP_SECS, then 60 s of drain before the
  # step's SLO check; the first failed step ends the ramp.
  local eps="${START_EPS:-2000}" step="${STEP_EPS:-2000}" secs="${STEP_SECS:-300}" max="${MAX_EPS:-500000}" i=0 phases=()
  push_hoststat; start_hoststat
  while (( eps <= max )); do
    i=$((i + 1)); local label; label="ceil$(printf %02d $i)-$eps"
    say "ceiling step $i: $eps eps for ${secs}s"
    blast "$eps" "$secs" "$label"
    # Analysts keep hunting during every step: query latency at this load.
    r "${BLASTERS[0]}" "cd ~/k6w/benchmarks/public/k6 && set -a && . ~/bench/api.env && set +a &&
      APP_URL=http://$(priv "$APP") DURATION=${secs}s ANALYSTS=${CEILING_ANALYSTS:-2} DASHBOARDS=0 AGENTS=0 \
      RESULTS_FILE=\$HOME/bench/k6-$RUN_ID-$label.json k6 run --quiet soc_mix.js > ~/bench/k6-$RUN_ID-$label.log 2>&1 || true"
    wait_blasters; sleep "${DRAIN_SECS:-60}"
    phases+=("$label")
    if ! python3 "$HERE/lib/collect.py" --topology "$TOPOLOGY" --run-id "$RUN_ID" --phases "$label" --out "$OUT_DIR" --slo-check; then
      say "SLO broke at $eps eps: ramp ends"; break
    fi
    eps=$((eps + step))
  done
  stop_hoststat
  python3 "$HERE/lib/collect.py" --topology "$TOPOLOGY" --run-id "$RUN_ID" --phases "$(IFS=,; echo "${phases[*]}")" \
    --scenario ceiling --out "$OUT_DIR"
}

# shellcheck disable=SC2120  # extra collect.py flags, when called from another step
step_collect() { python3 "$HERE/lib/collect.py" --topology "$TOPOLOGY" --run-id "$RUN_ID" --out "$OUT_DIR" "$@"; }

mkdir -p "$OUT_DIR"
case "$STEP" in
  prep) step_prep ;;
  install) step_install ;;
  content) step_content ;;
  tools) step_tools ;;
  smoke) step_smoke ;;
  socday) step_socday ;;
  ceiling) step_ceiling ;;
  collect) step_collect ;;
  all-dry) step_prep; step_install; step_content; step_tools; step_smoke
           DURATION=10m step_socday; START_EPS=1000 STEP_EPS=1000 STEP_SECS=120 MAX_EPS=4000 step_ceiling ;;
  *) echo "unknown step $STEP" >&2; exit 2 ;;
esac
say "done (run id $RUN_ID)"
