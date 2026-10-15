#!/usr/bin/env bash
# shellcheck disable=SC2329
# SC2329: the predicates handed to wait_for are invoked through "$@".
#
# Open-core prevalence smoke for the lean runtime (NAN-3451, NAN-3492).
# WRITES to the deployment: it creates (once) and deploys a
# `nano_smoke_prevalence` log source and ingests a few synthetic OCSF File
# System Activity events. Opt-in only; run it from
# `scripts/smoke-open-core.sh --prevalence` or directly.
#
# WHY THIS EXISTS
# Open-core prevalence spans ingest stamping, the tenant's prevalence state,
# the lean query path, the durable rare-list job and the API. NAN-3449 (a
# struct drift that broke the prevalence build) shipped because nothing
# exercised that chain end to end.
#
# WHAT IT CHECKS
#   1. a COMMON sha256 seen on 4 hosts and a RARE one seen on 1 host become
#      searchable, and GET /api/prevalence/hash/<sha256> counts 4 / 1 hosts;
#   2. probe events ingested after that are stamped at ingest: their
#      `enrichments[]` entry (name "prevalence", value = the hash) carries
#      data.host_count 4 / 1 and data.is_rare false / true, and
#      `| where prevalence_min <= 3` returns only the rare probe;
#   3. `| prevalence file_hash` (a query-time lookup) reports host_count 4 / 1
#      on the base events. Their `prevalence_file_hash` column is not the
#      command's output: it is the as-of-ingest stamp, 1 for a first sighting;
#   4. the rare list (GET /api/search/prevalence/rare, a durable job: queue,
#      poll /api/search/jobs/<id>, then page the result) lists the rare hash
#      with host_count 1.
# An ingest stamp is the count as of that event's ingest (a first sighting is
# 1), which is why the stamps are read on probes sent after the base events
# are searchable. Probes reuse the base hosts, so no count moves.
#
# TIMING
# Lean stamps prevalence at ingest and an event is searchable ~12-15 s after
# it is sent; there are no generations to wait for. A rare-list job takes
# seconds to a few minutes. A healthy run takes 1-3 minutes; every wait is
# bounded.
#
# Usage:
#   scripts/smoke-open-core-prevalence.sh [-u BASE_URL] [--env-file FILE]
#
# Credentials (environment, else read from the env file, default ./.env):
#   VECTOR_AUTH_TOKEN                      ingest bearer (install.sh writes it)
#   NANO_API_KEY                           X-API-Key with search:execute,
#                                          prevalence:view, log_sources:view, log_sources:edit,
#                                          log_sources:create, log_sources:deploy; or
#   NANO_ADMIN_EMAIL / NANO_ADMIN_PASSWORD a login (falls back to
#                                          INITIAL_ADMIN_EMAIL / _PASSWORD)
# Tunables (seconds): NANO_PREV_SMOKE_POLL_SECS (10),
#   NANO_PREV_SMOKE_SEARCH_TIMEOUT_SECS (300),
#   NANO_PREV_SMOKE_JOB_TIMEOUT_SECS (600),
#   NANO_PREV_SMOKE_STAMP_ROUNDS (3), NANO_PREV_SMOKE_RUN (run id, digits).
#
# Exit codes: 0 = passed, 1 = a check failed, 2 = usage/environment.

set -uo pipefail

BASE_URL="${NANO_BASE_URL:-http://localhost}"
ENV_FILE=".env"
SOURCE_TYPE="nano_smoke_prevalence"
POLL="${NANO_PREV_SMOKE_POLL_SECS:-10}"
SEARCH_TIMEOUT="${NANO_PREV_SMOKE_SEARCH_TIMEOUT_SECS:-300}"
JOB_TIMEOUT="${NANO_PREV_SMOKE_JOB_TIMEOUT_SECS:-600}"
STAMP_ROUNDS="${NANO_PREV_SMOKE_STAMP_ROUNDS:-3}"
COMMON_HOSTS=4
RARE_PAGES=20  # rare-list pages (100 rows each) searched for the rare hash

while [[ $# -gt 0 ]]; do
    case "$1" in
        -u) BASE_URL="$2"; shift 2 ;;
        --env-file) ENV_FILE="$2"; shift 2 ;;
        -h|--help) sed -n '4,55p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

for tool in curl jq; do
    command -v "$tool" >/dev/null 2>&1 || { echo "$tool is required." >&2; exit 2; }
done

c_reset='\033[0m'; c_red='\033[31m'; c_green='\033[32m'; c_blue='\033[34m'
FAILURES=0
section() { printf "\n%b==>%b %s\n" "$c_blue" "$c_reset" "$*"; }
ok()      { printf "  %bok%b   %s\n" "$c_green" "$c_reset" "$*"; }
bad()     { printf "  %bFAIL%b %s\n" "$c_red" "$c_reset" "$*"; FAILURES=$((FAILURES + 1)); }
die()     { bad "$*"; finish; }
finish() {
    printf "\n"
    if (( FAILURES == 0 )); then
        printf "%bopen-core prevalence smoke passed.%b\n" "$c_green" "$c_reset"; exit 0
    fi
    printf "%b%s prevalence check(s) failed.%b\n" "$c_red" "$FAILURES" "$c_reset"; exit 1
}

# `KEY=value` from the env file, without sourcing it (it is not ours to run).
env_value() {
    [[ -f "$ENV_FILE" ]] || return 0
    sed -n "s/^$1=//p" "$ENV_FILE" | tail -1 | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//"
}

WORK="$(mktemp -d "${TMPDIR:-/tmp}/nano-prev-smoke.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# http METHOD URL [BODY_FILE] [HEADER...] -> response body in $WORK/body,
# status in $STATUS.
STATUS=""
http() {
    local method=$1 url=$2 data=${3:-}
    shift 3 2>/dev/null || shift $#
    local args=(-sS --max-time 60 -X "$method" -o "$WORK/body" -w '%{http_code}')
    local header
    for header in "$@"; do args+=(-H "$header"); done
    [[ -n "$data" ]] && args+=(--data-binary "@$data")
    STATUS=$(curl "${args[@]}" "$url" 2>"$WORK/curl.err") || STATUS="000"
}

AUTH_HEADER=""
LOGIN_FILE=""  # set when authenticating by login rather than API key
# login -> sets AUTH_HEADER from $LOGIN_FILE; returns 1 on failure.
login() {
    http POST "$BASE_URL/api/auth/login" "$LOGIN_FILE" "Content-Type: application/json"
    local token
    token=$(jq -r '.tokens.access_token // empty' "$WORK/body" 2>/dev/null)
    [[ "$STATUS" == "200" && -n "$token" ]] || return 1
    AUTH_HEADER="Authorization: Bearer $token"
}
api_once() {
    local method=$1 path=$2 data=${3:-}
    if [[ -n "$data" ]]; then
        http "$method" "$BASE_URL$path" "$data" "$AUTH_HEADER" "Content-Type: application/json"
    else
        http "$method" "$BASE_URL$path" "" "$AUTH_HEADER"
    fi
}
# The rare-list job wait can outlive a login's access token: on a 401, log in
# again once and retry.
api() {
    api_once "$@"
    if [[ "$STATUS" == "401" && -n "$LOGIN_FILE" ]] && login; then
        api_once "$@"
    fi
}

now() { date -u +%s; }
iso() { date -u -d "@$1" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -r "$1" +%Y-%m-%dT%H:%M:%SZ; }
sha256() {
    if command -v sha256sum >/dev/null 2>&1; then printf '%s' "$1" | sha256sum | cut -c1-64
    else printf '%s' "$1" | shasum -a 256 | cut -c1-64; fi
}

RUN="${NANO_PREV_SMOKE_RUN:-$(date -u +%s)$((RANDOM % 1000))}"
[[ "$RUN" =~ ^[0-9]+$ ]] || { echo "NANO_PREV_SMOKE_RUN must be digits." >&2; exit 2; }
COMMON=$(sha256 "nano-prevalence-smoke-common-$RUN")
RARE=$(sha256 "nano-prevalence-smoke-rare-$RUN")
HOST_PREFIX="nano-smoke-$RUN"
START_TS=$(( $(now) - 3600 ))

printf "%bopen-core prevalence smoke%b  base=%s  run=%s\n" "$c_blue" "$c_reset" "$BASE_URL" "$RUN"

# search QUERY -> first result row on stdout ('' when none); fails the check
# on a non-200.
search_row() {
    jq -n --arg q "$1" --arg s "$(iso "$START_TS")" --arg e "$(iso $(( $(now) + 300 )))" \
        '{query: $q, time_range: {start: $s, end: $e}, limit: 100, skip_histogram: true, skip_field_stats: true}' \
        > "$WORK/search.json"
    api POST /api/search "$WORK/search.json"
    if [[ "$STATUS" != "200" ]]; then
        printf 'HTTP %s: %s' "$STATUS" "$(head -c 300 "$WORK/body")" > "$WORK/search.err"
        return 1
    fi
    jq -c '.results[0] // empty' "$WORK/body"
}

# wait_for DESCRIPTION TIMEOUT COMMAND... : run COMMAND every $POLL seconds
# until it succeeds or TIMEOUT seconds pass.
wait_for() {
    local what=$1 timeout=$2 deadline
    shift 2
    deadline=$(( $(now) + timeout ))
    while true; do
        "$@" && return 0
        if (( $(now) >= deadline )); then
            bad "$what: not met after ${timeout}s${LAST:+ (last: $LAST)}"
            return 1
        fi
        sleep "$POLL"
    done
}

# --------------------------------------------------------------------------
section "credentials"
INGEST_TOKEN="${VECTOR_AUTH_TOKEN:-$(env_value VECTOR_AUTH_TOKEN)}"
[[ -n "$INGEST_TOKEN" ]] || die "VECTOR_AUTH_TOKEN is not set and not in $ENV_FILE"
if [[ -n "${NANO_API_KEY:-}" ]]; then
    AUTH_HEADER="X-API-Key: $NANO_API_KEY"
    ok "API key"
else
    email="${NANO_ADMIN_EMAIL:-$(env_value INITIAL_ADMIN_EMAIL)}"
    password="${NANO_ADMIN_PASSWORD:-$(env_value INITIAL_ADMIN_PASSWORD)}"
    [[ -n "$email" && -n "$password" ]] \
        || die "set NANO_API_KEY, or NANO_ADMIN_EMAIL and NANO_ADMIN_PASSWORD"
    LOGIN_FILE="$WORK/login.json"
    jq -n --arg e "$email" --arg p "$password" '{email: $e, password: $p}' > "$LOGIN_FILE"
    login || die "login as $email -> HTTP $STATUS"
    ok "logged in as $email"
fi

# --------------------------------------------------------------------------
section "smoke log source ($SOURCE_TYPE)"
# The parser builds a valid OCSF 1.9 File System Activity event from three
# smoke fields. Prevalence counts a file hash per device.hostname.
# Sample validation hands the raw event over as `.message`; merge it when it
# parses, as the other routed parsers do.
read -r -d '' PARSER_VRL <<'VRL'
pj = object(parse_json(string(.message) ?? "") ?? {}) ?? {}
if pj != {} { . = merge(., pj) }
host = string!(.smoke_host)
hash = string!(.smoke_hash)
marker = string!(.smoke_marker)
. = {
  "class_uid": 1001,
  "category_uid": 1,
  "activity_id": 1,
  "type_uid": 100101,
  "severity_id": 1,
  "time": to_unix_timestamp(now(), unit: "milliseconds"),
  "message": "nano prevalence smoke " + marker,
  "metadata": {"version": "1.9.0", "product": {"name": "nano smoke", "vendor_name": "nano"}},
  "actor": {"user": {"name": "nano-smoke"}},
  "device": {"hostname": host, "type_id": 0},
  "file": {"name": "nano-smoke.bin", "type_id": 1, "hashes": [{"algorithm_id": 3, "value": hash}]}
}
VRL
api GET /api/log-sources
[[ "$STATUS" == "200" ]] || die "GET /api/log-sources -> HTTP $STATUS"
# `source_type` is the transport (`routed` = HTTP ingest), not the slug: a
# routed source carries its X-Source-Type slug in `match_values` (AddFeed).
SOURCE_ID=$(jq -r --arg s "$SOURCE_TYPE" \
    '(if type == "array" then . else (.log_sources // .items // .data // []) end)[]
     | select(.source_type == "routed" and any((.match_values // [])[]; . == $s)) | .id' "$WORK/body" | head -1)
if [[ -z "$SOURCE_ID" ]]; then
    jq -n --arg s "$SOURCE_TYPE" --arg v "$PARSER_VRL" \
        '{name: "nano prevalence smoke", description: "NAN-3451 open-core prevalence smoke; safe to delete",
          source_type: "routed", parser_vrl: $v, output_fields: null, category: "endpoint",
          vendor: "nano", product: "smoke", match_values: [$s]}' > "$WORK/source.json"
    api POST /api/log-sources "$WORK/source.json"
    SOURCE_ID=$(jq -r '.id // empty' "$WORK/body" 2>/dev/null)
    [[ "$STATUS" =~ ^20[01]$ && -n "$SOURCE_ID" ]] \
        || die "create log source -> HTTP $STATUS $(head -c 200 "$WORK/body")"
    ok "created log source $SOURCE_ID"
else
    # Re-apply this script's parser so a source left by an older run is current.
    jq -n --arg v "$PARSER_VRL" '{parser_vrl: $v}' > "$WORK/source.json"
    api PUT "/api/log-sources/$SOURCE_ID" "$WORK/source.json"
    [[ "$STATUS" == "200" ]] || die "update log source $SOURCE_ID -> HTTP $STATUS $(head -c 200 "$WORK/body")"
    ok "log source $SOURCE_ID exists (parser re-applied)"
fi
# DeployLogSourceRequest: `ocsf_sample_logs` is a list of raw events (strings)
# the parser generation is validated against. Without it the deploy is refused
# (no OCSF sample-validation receipt).
jq -cn --arg h "$HOST_PREFIX-sample" --arg x "$COMMON" \
    '{ocsf_sample_logs: [{smoke_host: $h, smoke_hash: $x, smoke_marker: "sample"} | tojson]}' \
    > "$WORK/deploy.json"
api POST "/api/log-sources/$SOURCE_ID/deploy" "$WORK/deploy.json"
[[ "$STATUS" == "200" ]] || die "deploy log source -> HTTP $STATUS $(head -c 300 "$WORK/body")"
# DeploymentResult: the deploy stages, validates, promotes and reloads Vector
# before it answers, so `success` + `deployment_id` mean the parser is live.
[[ "$(jq -r '.success' "$WORK/body" 2>/dev/null)" == "true" ]] \
    || die "deploy log source -> success=false: $(jq -r '.message // empty' "$WORK/body" 2>/dev/null | head -c 300)"
DEPLOYMENT_ID=$(jq -r '.deployment_id // empty' "$WORK/body")
[[ -n "$DEPLOYMENT_ID" ]] || die "deploy log source -> no deployment_id: $(head -c 300 "$WORK/body")"
deployment_succeeded() {
    api GET "/api/log-sources/$SOURCE_ID/deployments"
    LAST=$(jq -r --arg d "$DEPLOYMENT_ID" '.[]? | select(.id == $d) | .status' "$WORK/body" 2>/dev/null | head -1)
    [[ "$STATUS" == "200" && "$LAST" == "success" ]]
}
wait_for "deployment $DEPLOYMENT_ID recorded as success" "$SEARCH_TIMEOUT" deployment_succeeded || finish
ok "parser deployed ($DEPLOYMENT_ID)"

# --------------------------------------------------------------------------
# ingest MARKER HOST:HASH... : one NDJSON event per pair.
ingest() {
    local marker=$1 pair
    shift
    : > "$WORK/events.ndjson"
    for pair in "$@"; do
        jq -cn --arg h "${pair%%:*}" --arg x "${pair#*:}" --arg m "$marker" \
            '{smoke_host: $h, smoke_hash: $x, smoke_marker: $m}' >> "$WORK/events.ndjson"
    done
    http POST "$BASE_URL/ingest" "$WORK/events.ndjson" \
        "Authorization: Bearer $INGEST_TOKEN" "X-Source-Type: $SOURCE_TYPE" "Content-Type: application/x-ndjson"
    [[ "$STATUS" =~ ^20[0-4]$ ]] || die "ingest $marker -> HTTP $STATUS"
}

# count_is QUERY N : the query's first row carries `n` == N.
count_is() {
    local row
    row=$(search_row "$1") || { LAST=$(cat "$WORK/search.err"); return 1; }
    LAST=$(jq -r '.n // 0' <<< "${row:-null}")
    [[ "$LAST" == "$2" ]]
}

section "ingest: common hash on $COMMON_HOSTS hosts, rare hash on 1"
BASE="nanosmoke${RUN}base"
pairs=()
for i in $(seq 1 "$COMMON_HOSTS"); do pairs+=("$HOST_PREFIX-$i:$COMMON"); done
pairs+=("$HOST_PREFIX-1:$RARE")
ingest "$BASE" "${pairs[@]}"
ok "sent $(( COMMON_HOSTS + 1 )) events"
wait_for "base events searchable" "$SEARCH_TIMEOUT" \
    count_is "\"$BASE\" | stats count() as n" "$(( COMMON_HOSTS + 1 ))" || finish
ok "base events searchable"

host_count_is() {
    api GET "/api/prevalence/hash/$1?window=24h"
    # PrevalenceResponse wraps the lookup: {"data": {"host_count": N, ...}}.
    LAST="HTTP $STATUS host_count=$(jq -r '.data.host_count // empty' "$WORK/body" 2>/dev/null)"
    [[ "$STATUS" == "200" && "$(jq -r '.data.host_count // 0' "$WORK/body" 2>/dev/null)" == "$2" ]]
}
wait_for "GET /api/prevalence/hash counts the common hash on $COMMON_HOSTS hosts" "$SEARCH_TIMEOUT" \
    host_count_is "$COMMON" "$COMMON_HOSTS" || finish
ok "hash lookup: common hash on $COMMON_HOSTS hosts"
if host_count_is "$RARE" 1; then ok "hash lookup: rare hash on 1 host"; else bad "rare hash lookup: $LAST"; fi

# --------------------------------------------------------------------------
section "ingest-time stamps (enrichments[]) and prevalence_min"
# stamp MARKER HASH -> "host_count is_rare" from the nano prevalence entry of
# the marker's event carrying HASH ('' when there is none). The entry is
# {name: "prevalence", value: <hash>, data: {host_count, is_rare, ...}};
# `data` may arrive as a JSON string, and a columnar answer as aligned
# `enrichments.*` arrays.
stamp() {
    local row
    row=$(search_row "\"$1\" file.hashes.value=\"$2\" | head 1") || return 0
    jq -r --arg h "$2" '
        def obj: if type == "string" then (fromjson? // {}) else (. // {}) end;
        def entries:
            ((.enrichments // []) | if type == "string" then (fromjson? // []) else . end) as $e
            | if ($e | type) == "array" and ($e | length) > 0 then $e[]
              elif (.["enrichments.name"] | type) == "array" then
                  . as $r | range(0; $r["enrichments.name"] | length) as $i
                  | {name: $r["enrichments.name"][$i], value: ($r["enrichments.value"] // [])[$i],
                     data: {host_count: ($r["enrichments.data.host_count"] // [])[$i],
                            is_rare: ($r["enrichments.data.is_rare"] // [])[$i]}}
              else empty end;
        [entries | select(.name == "prevalence" and ((.value // "") | tostring | ascii_downcase) == $h)
         | (.data | obj)] | first // empty
        | "\(.host_count // "none") \(if .is_rare == null then "none" else (.is_rare | tostring) end)"' <<< "${row:-null}" 2>/dev/null
}
# The tenant's prevalence state advances as the base events commit, which can
# trail their searchability by a moment; a probe stamped before that is retried
# under a fresh marker, a bounded number of times. Probes reuse base hosts, so
# no count moves.
stamped=""
for round in $(seq 1 "$STAMP_ROUNDS"); do
    PROBE="nanosmoke${RUN}p${round}"
    ingest "$PROBE" "$HOST_PREFIX-1:$COMMON" "$HOST_PREFIX-1:$RARE"
    wait_for "probe $round searchable" "$SEARCH_TIMEOUT" count_is "\"$PROBE\" | stats count() as n" 2 || finish
    common_stamp=$(stamp "$PROBE" "$COMMON")
    if [[ "${common_stamp%% *}" == "$COMMON_HOSTS" ]]; then stamped=$PROBE; break; fi
    printf "  …    probe %s stamped host_count=%s, retrying\n" "$round" "${common_stamp%% *}"
    sleep "$POLL"
done
if [[ -z "$stamped" ]]; then
    bad "no probe was stamped host_count=$COMMON_HOSTS in enrichments[] in $STAMP_ROUNDS rounds (last: ${common_stamp:-no prevalence entry})"
else
    ok "common probe stamped host_count=$COMMON_HOSTS"
    if [[ "${common_stamp#* }" == "false" ]]; then ok "common probe stamped is_rare=false"
    else bad "common probe is_rare=${common_stamp#* } (want false)"; fi
    rare_stamp=$(stamp "$stamped" "$RARE")
    if [[ "$rare_stamp" == "1 true" ]]; then ok "rare probe stamped host_count=1 is_rare=true"
    else bad "rare probe stamp: host_count/is_rare=${rare_stamp:-no prevalence entry} (want 1 true)"; fi
    if count_is "\"$stamped\" | where prevalence_min <= 3 | stats count() as n" 1 \
        && count_is "\"$stamped\" file.hashes.value=\"$RARE\" | where prevalence_min <= 3 | stats count() as n" 1; then
        ok "| where prevalence_min <= 3 keeps only the rare probe"
    else
        bad "| where prevalence_min <= 3: $LAST"
    fi
fi

# --------------------------------------------------------------------------
section "| prevalence file_hash"
# The command's output is host_count (with is_rare, prevalence_score, …) from
# the tenant's prevalence state now; a row's `prevalence_*` columns are its
# ingest-time stamps and are not read here.
for want in "$COMMON:$COMMON_HOSTS" "$RARE:1"; do
    err=""
    row=$(search_row "\"$BASE\" file.hashes.value=\"${want%%:*}\" | head 1 | prevalence file_hash") \
        || err=" ($(cat "$WORK/search.err"))"
    value=$(jq -r '.host_count // empty' <<< "${row:-null}" 2>/dev/null)
    if [[ "$value" == "${want#*:}" ]]; then ok "| prevalence file_hash: host_count=$value for ${want%%:*}"
    else bad "| prevalence file_hash: host_count=${value:-none} for ${want%%:*} (want ${want#*:})$err"; fi
done

# --------------------------------------------------------------------------
section "rare list (durable job)"
# GET /api/search/prevalence/rare queues a rare-list job (202 + job_id); poll
# GET /api/search/jobs/<id> until it completes, then page the result with
# job_id. `refresh=true` skips a result reused from the last ten minutes,
# which would predate this run's events.
RARE_QUERY="type=hash&window=24h&limit=100"
rare_found=""
rare_job=""
deadline=$(( $(now) + JOB_TIMEOUT ))
api GET "/api/search/prevalence/rare?$RARE_QUERY&refresh=true"
if [[ "$STATUS" != "200" && "$STATUS" != "202" ]]; then
    bad "GET /api/search/prevalence/rare -> HTTP $STATUS $(head -c 300 "$WORK/body")"
else
    rare_job=$(jq -r '.job_id // empty' "$WORK/body" 2>/dev/null)
    job_status=$(jq -r '.job_status // empty' "$WORK/body" 2>/dev/null)
    [[ -n "$rare_job" ]] || bad "GET /api/search/prevalence/rare -> no job_id: $(head -c 300 "$WORK/body")"
fi
if [[ -n "$rare_job" ]]; then
    while [[ "$job_status" != "completed" ]]; do
        case "$job_status" in
            queued|running|"") ;;
            *) bad "rare-list job $rare_job $job_status: $(jq -r '.error // empty' "$WORK/body" 2>/dev/null | head -c 300)"; break ;;
        esac
        if (( $(now) >= deadline )); then
            bad "rare-list job $rare_job: not completed after ${JOB_TIMEOUT}s (last: ${job_status:-HTTP $STATUS})"; break
        fi
        sleep "$POLL"
        api GET "/api/search/jobs/$rare_job"
        if [[ "$STATUS" == "200" ]]; then
            job_status=$(jq -r '.status // empty' "$WORK/body" 2>/dev/null)
        else
            job_status=""  # transient (503 under load): keep polling until the deadline
        fi
    done
fi
if [[ "$job_status" == "completed" ]]; then
    ok "rare-list job $rare_job completed"
    offset=0
    for _ in $(seq 1 "$RARE_PAGES"); do
        api GET "/api/search/prevalence/rare?$RARE_QUERY&offset=$offset&job_id=$rare_job"
        [[ "$STATUS" == "200" ]] || { bad "rare-list page offset=$offset -> HTTP $STATUS $(head -c 300 "$WORK/body")"; break; }
        rare_found=$(jq -r --arg h "$RARE" '.artifacts[]? | select(.artifact == $h) | .host_count' "$WORK/body" | head -1)
        [[ -n "$rare_found" || "$(jq -r '.has_more' "$WORK/body")" != "true" ]] && break
        offset=$(( offset + 100 ))
    done
    if [[ "$rare_found" == "1" ]]; then ok "rare hash listed with host_count 1"
    else bad "rare hash not in the rare list (host_count=${rare_found:-absent})"; fi
fi

finish
