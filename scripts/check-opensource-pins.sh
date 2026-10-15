#!/usr/bin/env bash
#
# Validate the open-source quickstart stack DEFINITION without standing it up.
# Catches the class of breakage that hit NAN-1260 (vector rejecting a removed
# config field after a version bump) on the PR instead of after merge.
#
# Checks (all fast; only image pulls cost time):
#   1. docker-compose.opensource.yml parses
#   2. lake and legacy storage profiles are mutually exclusive
#   3. every third-party image is digest-pinned (@sha256)
#   4. images.lock third-party section matches the compose pins (the CI
#      round-trip merge-manifests performs — catches lock/compose drift)
#   5. the committed config/vector bundle passes `vector validate` on the
#      vector version pinned in the compose (auto-tracks future bumps), using
#      the environment the COMPOSE SERVICE provides — not a hand-written list,
#      which previously supplied vars production did not (NAN-2361)
#   6. every FIRST-PARTY image the compose deploys is built by the
#      merge-manifests component loop, so it can actually be pinned (NAN-2361 —
#      the lake images were added to the compose before the loop, and
#      install.sh silently skipped what images.lock did not record)
#   7. images.lock's first-party lines are a subset of those components
#   8. the PostgreSQL major-version guard is wired into both open-core compose
#      files, and postgres pins PGDATA to its own volume mount
#   9. docker-compose.siem-only.yml parses and pins the same PostgreSQL major
#  10. every first-party image's build stage carries the nano-rs/nano OCI
#      source label, so its first GHCR push links to the public repo (NAN-3307)
#  11. nano-jobs carries nano-api's runtime environment (shared AppState,
#      NAN-3375)
#  5b. (after 5) the HTTP ingest sources answer 401 to a missing or wrong
#      token instead of 200-and-drop (NAN-3379)
#
# Run from the repo root. Needs docker + docker compose v2. Used by both CI
# (.github/workflows/opensource-stack-gate.yml) and humans before a pin bump.

set -euo pipefail

COMPOSE="docker-compose.opensource.yml"
LOCK="images.lock"

ok()   { printf '  \033[32mok\033[0m   %s\n' "$*"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }

[[ -f "$COMPOSE" ]] || fail "$COMPOSE not found — run from the repo root."
[[ -f "$LOCK" ]]    || fail "$LOCK not found — run from the repo root."
# The compose file requires NANO_VERSION (no `latest` fallback); outside an
# install it is the release images.lock pins.
NANO_VERSION="${NANO_VERSION:-$(./scripts/nano-release-pin.sh "$LOCK")}" \
  || fail "$LOCK has no '# Release:' line"
export NANO_VERSION

# ----------------------------------------------------------------------------
# 1. Compose parses (interpolation + schema). Dummy secrets satisfy the
#    `${VAR:?must be set}` guards; we only care that it resolves, not the values.
# ----------------------------------------------------------------------------
POSTGRES_PASSWORD=x CLICKHOUSE_PASSWORD=x CLICKHOUSE_ADMIN_PASSWORD=x \
  JWT_SECRET=x NANOSIEM_ENCRYPTION_KEY=x VECTOR_AUTH_TOKEN=x \
  docker compose -f "$COMPOSE" config -q 2>/dev/null \
    || fail "$COMPOSE does not parse (docker compose config)"
ok "compose parses"

# ----------------------------------------------------------------------------
# 2. Storage profiles remain mutually exclusive. A canonical lake install must
#    never start a ClickHouse server/migrator, and the maintenance-only legacy
#    profile must not accidentally start the lake control plane.
# ----------------------------------------------------------------------------
lake_services=$(POSTGRES_PASSWORD=x CLICKHOUSE_PASSWORD=x CLICKHOUSE_ADMIN_PASSWORD=x \
  JWT_SECRET=x NANOSIEM_ENCRYPTION_KEY=x VECTOR_AUTH_TOKEN=x \
  COMPOSE_PROFILES=lake docker compose -f "$COMPOSE" config --services 2>/dev/null)
legacy_services=$(POSTGRES_PASSWORD=x CLICKHOUSE_PASSWORD=x CLICKHOUSE_ADMIN_PASSWORD=x \
  JWT_SECRET=x NANOSIEM_ENCRYPTION_KEY=x VECTOR_AUTH_TOKEN=x \
  COMPOSE_PROFILES=legacy docker compose -f "$COMPOSE" config --services 2>/dev/null)

printf '%s\n' "$lake_services" | grep -qx clickhouse \
  && fail "lake profile unexpectedly includes the ClickHouse server"
printf '%s\n' "$lake_services" | grep -qx clickhouse-migrate \
  && fail "lake profile unexpectedly includes the ClickHouse migrator"
lean_services=$(POSTGRES_PASSWORD=x JWT_SECRET=x NANOSIEM_ENCRYPTION_KEY=x VECTOR_AUTH_TOKEN=x \
  COMPOSE_PROFILES=lean docker compose -f "$COMPOSE" config --services 2>/dev/null)
printf '%s\n' "$lean_services" | grep -qx lake-cell \
  || fail "lean profile does not include the lake cell"
# The gen1 lake images (control/query/maintenance) are not published for the
# open edition; no compose service may reference them.
grep -nE 'ghcr\.io/nano-rs/nano-lake-(control|query|maintenance)' "$COMPOSE" \
  && fail "compose references a gen1 lake image the open release no longer publishes"
printf '%s\n' "$legacy_services" | grep -qx clickhouse \
  || fail "legacy profile does not include the ClickHouse server"
printf '%s\n' "$legacy_services" | grep -q '^lake-' \
  && fail "legacy profile unexpectedly includes lake services"
ok "lake and legacy storage profiles are mutually exclusive"

# NAN-3807: install.sh --tenzir sets NANO_VECTOR_PROFILE=none. That lean stack
# has no Vector and no connector runner (both deliver through Vector) but keeps
# the bucket-drop converter; the default lean stack has all three. The
# bundled Tenzir node only starts on its own `tenzir` profile.
tenzir_services=$(POSTGRES_PASSWORD=x JWT_SECRET=x NANOSIEM_ENCRYPTION_KEY=x VECTOR_AUTH_TOKEN=x \
  COMPOSE_PROFILES=lean NANO_VECTOR_PROFILE=none docker compose -f "$COMPOSE" config --services 2>/dev/null) \
  || fail "the Tenzir-direct lean stack (NANO_VECTOR_PROFILE=none) does not parse"
for svc in vector connector-runner; do
  printf '%s\n' "$tenzir_services" | grep -qx "$svc" \
    && fail "Tenzir-direct lean stack unexpectedly includes $svc"
  printf '%s\n' "$lean_services" | grep -qx "$svc" \
    || fail "default lean stack does not include $svc"
done
for services in "$lean_services" "$tenzir_services"; do
  printf '%s\n' "$services" | grep -qx lean-landing \
    || fail "a lean stack does not include the bucket-drop converter (lean-landing)"
  printf '%s\n' "$services" | grep -qx tenzir \
    && fail "a lean stack starts the bundled Tenzir node without its profile"
done
ok "Tenzir-direct lean stack drops Vector and keeps the bucket drop"

# ----------------------------------------------------------------------------
# 3. Every third-party image is digest-pinned. First-party (ghcr.io/nano-rs/nano-*)
#    images track ${NANO_VERSION} and are intentionally tag-only — skip them.
#    NAN-3604: only the nano-* repositories are first-party; other nano-rs
#    images (ghcr.io/nano-rs/vector, the Vector fork) are pinned like any
#    third-party image. The same prefix is used in build-and-push.yml and install.sh.
# ----------------------------------------------------------------------------
# A YAML alias (`image: *cell-image`) repeats its anchor's definition line
# (`image: &cell-image <ref>`), which this check sees and judges on its own.
unpinned=$(grep -nE '^[[:space:]]*image:[[:space:]]' "$COMPOSE" \
  | grep -vE 'image:[[:space:]]*\*[A-Za-z0-9_-]+[[:space:]]*$' \
  | grep -vE 'ghcr\.io/nano-rs/nano-' | grep -v '@sha256:' || true)
[[ -z "$unpinned" ]] || fail "third-party image(s) not digest-pinned:
$unpinned"
ok "all third-party images digest-pinned"

# ----------------------------------------------------------------------------
# 4. images.lock third-party section == compose pins. This mirrors
#    exactly what build-and-push.yml's merge-manifests regenerates, so drift here
#    means the next release would either change the lock unexpectedly or fail
#    verification.
#
#    Profile-gated images stay in the lock. install.sh verifies only images in
#    the active Compose profile and explicitly skips an unpulled optional image,
#    while retaining a vouched digest for every supported profile. This awk MUST
#    stay identical to the one in build-and-push.yml.
# ----------------------------------------------------------------------------
extracted=$(awk '
  /^[[:space:]]*image:[ \t]*[^ \t]+@sha256:[0-9a-f]+/ {
    line=$0
    sub(/^[ \t]*image:[ \t]*/,"",line)
    sub(/@sha256:/," sha256:",line)
    sub(/[ \t]+$/,"",line)
    if (line !~ /^ghcr\.io\/nano-rs\/nano-/) print line
  }
' "$COMPOSE" | sort -u)
lock_tp=$(grep -E '[[:space:]]sha256:[0-9a-f]+$' "$LOCK" \
  | grep -vE '^ghcr\.io/nano-rs/nano-' | sort)
if ! diff <(printf '%s\n' "$extracted") <(printf '%s\n' "$lock_tp") >/dev/null; then
    printf 'compose pins vs images.lock third-party section differ:\n' >&2
    diff <(printf '%s\n' "$extracted") <(printf '%s\n' "$lock_tp") >&2 || true
    fail "images.lock out of sync with $COMPOSE (regenerate the third-party section)"
fi
ok "images.lock third-party pins match compose"

# ----------------------------------------------------------------------------
# 5. config/vector validates on the PINNED vector version. Extract the full
#    pinned ref from the compose so this auto-tracks bumps. Replicate the
#    compose's --config-dir invocation: top-level static TOMLs + the (empty at
#    boot) dynamic dirs. `--config-dir` is non-recursive (NAN-1234), so the
#    sources/parsers/_*.toml are deliberately not loaded here.
# ----------------------------------------------------------------------------
# NAN-3604: the `vector` service's own image line (upstream or the nano-rs fork).
vec=$(awk '
  /^  vector:[[:space:]]*$/ { in_vector = 1; next }
  in_vector && /^  [^[:space:]#]/ { exit }
  in_vector && /^    image:[[:space:]]/ { sub(/^    image:[[:space:]]*/, ""); sub(/[[:space:]]+$/, ""); print; exit }
' "$COMPOSE")
[[ "$vec" =~ @sha256:[0-9a-f]{64}$ ]] || fail "could not find the digest-pinned vector service image in $COMPOSE"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cp -a config/vector "$tmp/vector"
mkdir -p "$tmp/vector/dynamic/sources/parsers" "$tmp/vector/dynamic/sources/configs"
# NAN-2361: the environment comes from the COMPOSE SERVICE, not a hand-written
# list. It used to be hardcoded here, including
# `-e CLICKHOUSE_OTEL_SPANS_TABLE=… -e CLICKHOUSE_OTEL_METRICS_TABLE=…`, which
# the compose never actually set on the vector service. Vector treats an unset
# interpolation as a HARD configuration error, so it crash-looped on every fresh
# install ("Missing environment variable in config") while this gate stayed
# green — the gate was supplying exactly what production was missing.
#
# Deriving the env from `docker compose config` means the gate now fails for any
# variable config/vector needs and the compose does not provide.
envfile="$tmp/vector.env"
POSTGRES_PASSWORD=x CLICKHOUSE_PASSWORD=x CLICKHOUSE_ADMIN_PASSWORD=x \
  JWT_SECRET=x NANOSIEM_ENCRYPTION_KEY=x VECTOR_AUTH_TOKEN=x \
  COMPOSE_PROFILES=lake docker compose -f "$COMPOSE" config --format json 2>/dev/null \
  | python3 -c '
import json, sys
env = json.load(sys.stdin)["services"]["vector"].get("environment") or {}
for key, value in sorted(env.items()):
    value = "" if value is None else str(value)
    if "\n" in value:            # env-file syntax cannot carry newlines
        continue
    print(f"{key}={value}")
' > "$envfile" || fail "could not resolve the vector service environment from $COMPOSE"
[[ -s "$envfile" ]] || fail "resolved an empty environment for the vector service"
# VECTOR_DATA_DIR is a runtime path the compose supplies via its command, not env.
grep -q '^VECTOR_DATA_DIR=' "$envfile" || echo "VECTOR_DATA_DIR=/tmp/vector" >> "$envfile"

if ! docker run --rm -v "$tmp/vector:/etc/vector" --env-file "$envfile" \
        "$vec" --dangerously-allow-env-var-interpolation validate --no-environment \
        --config-dir /etc/vector \
        --config-dir /etc/vector/dynamic/sources/parsers \
        --config-dir /etc/vector/dynamic/sources/configs; then
    fail "vector ($vec) rejects the config/vector bundle using the environment $COMPOSE actually gives it"
fi
ok "config/vector validates on $vec with the compose-provided environment"

# ----------------------------------------------------------------------------
# 5b. HTTP ingest answers a bad or missing token with 401 (NAN-3379). The
#     token used to be checked only in the `auth_check` remap, AFTER the
#     http_server source had already answered 200, so a sender with a wrong
#     token saw success while every event was dropped. Boot the same bundle
#     with the same compose environment and probe both HTTP ingest sources.
# ----------------------------------------------------------------------------
# NAN-3806: :8080 accepts only tokens listed in valid_tokens_file (each bound
# to a source); the bare install token is refused until an admin binds it.
# Give the probe one bound gate token, the way nano-api renders it.
gate_token="nan3806-gate-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
mkdir -p "$tmp/vector/dynamic/ingest-tokens"
printf '{"version":1,"fallback_enabled":false,"tokens":[{"sha256":"%s","id":"6e616e6f-0000-4000-8000-0000000000ff","name":"nan3379_gate"}]}\n' \
    "$(printf '%s' "$gate_token" | sha256sum | cut -d' ' -f1)" > "$tmp/vector/dynamic/ingest-tokens/tokens.json"
probe_name="nano-gate-vector-auth-$$"
cleanup_probe() { docker rm -f "$probe_name" >/dev/null 2>&1 || true; rm -rf "$tmp"; }
trap cleanup_probe EXIT
docker run -d --name "$probe_name" -v "$tmp/vector:/etc/vector" --env-file "$envfile" \
    -p 127.0.0.1::8080 -p 127.0.0.1::8090 \
    "$vec" --dangerously-allow-env-var-interpolation \
    --config-dir /etc/vector \
    --config-dir /etc/vector/dynamic/sources/parsers \
    --config-dir /etc/vector/dynamic/sources/configs >/dev/null \
    || fail "could not start $vec to probe ingest auth"
token=$(grep '^VECTOR_AUTH_TOKEN=' "$envfile" | cut -d= -f2-)
[[ -n "$token" ]] || fail "the compose gives the vector service no VECTOR_AUTH_TOKEN"
probe() { # port, extra curl args...
    local port host_port
    port=$1; shift
    host_port=$(docker port "$probe_name" "$port/tcp" | head -1)
    curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$@" \
        -H 'X-Source-Type: nan3379_gate' -d '{"message":"gate"}' "http://$host_port/"
}
for _ in $(seq 1 60); do
    [[ "$(probe 8080 -H "Authorization: Bearer $gate_token")" == "200" ]] && break
    sleep 1
done
for port in 8080 8090; do
    # :8080 takes the bound gate token; :8090 (enrichment push) the install token.
    valid=$token; [[ "$port" == 8080 ]] && valid=$gate_token
    good=$(probe "$port" -H "Authorization: Bearer $valid")
    missing=$(probe "$port")
    wrong=$(probe "$port" -H "Authorization: Bearer wrong-$valid")
    [[ "$good" == "200" ]] || fail ":$port answered $good to a valid token (expected 200)"
    [[ "$missing" == "401" ]] || fail ":$port answered $missing to a missing token (expected 401)"
    [[ "$wrong" == "401" ]] || fail ":$port answered $wrong to a wrong token (expected 401)"
done
unbound=$(probe 8080 -H "Authorization: Bearer $token")
[[ "$unbound" == "401" ]] || fail ":8080 answered $unbound to the unbound install token (expected 401: install tokens must be bound to a source)"
docker rm -f "$probe_name" >/dev/null 2>&1 || true
ok "HTTP ingest (:8080) and enrichment push (:8090) answer 401 to a missing or wrong token; :8080 refuses the unbound install token"


# ----------------------------------------------------------------------------
# 6/7. First-party images: buildable, therefore pinnable.
#
# images.lock is regenerated at release time by build-and-push.yml's
# merge-manifests job, which loops a hardcoded component list. A first-party
# service added to the compose but missing from that loop can never get a lock
# line — and before NAN-2361 install.sh skipped such an image in silence while
# still reporting a clean verification. Compare the two lists here, on the PR.
#
# The workflow is stripped from the public mirror, so skip when it is absent.
# ----------------------------------------------------------------------------
WF=".github/workflows/build-and-push.yml"
compose_fp=$(grep -oE 'ghcr\.io/nano-rs/nano-[a-z0-9-]+' "$COMPOSE" | sort -u)
if [[ -f "$WF" ]]; then
    components=$(grep -oE 'for COMPONENT in [a-z0-9 -]+' "$WF" | head -1 | sed 's/^for COMPONENT in //')
    [[ -n "$components" ]] || fail "could not read the merge-manifests component list from $WF"
    built=$(for c in $components; do echo "ghcr.io/nano-rs/nano-${c}"; done | sort -u)
    missing=$(comm -23 <(printf '%s\n' "$compose_fp") <(printf '%s\n' "$built") || true)
    if [[ -n "$missing" ]]; then
        printf 'deployed by %s but never built/pinned by merge-manifests:\n%s\n' "$COMPOSE" "$missing" >&2
        fail "add the missing component(s) to the \`for COMPONENT in …\` loop in $WF"
    fi
    ok "every first-party compose image is built by merge-manifests"

    lock_fp=$(grep -E '^ghcr\.io/nano-rs/nano-' "$LOCK" | awk '{print $1}' | sort -u)
    if [[ -n "$lock_fp" ]]; then
        stray=$(comm -23 <(printf '%s\n' "$lock_fp") <(printf '%s\n' "$built") || true)
        [[ -z "$stray" ]] || fail "images.lock pins first-party image(s) merge-manifests does not build:
$stray"
        ok "images.lock first-party lines are all buildable components"
    fi
else
    ok "merge-manifests parity skipped ($WF not present — public mirror)"
fi

# ----------------------------------------------------------------------------
# 10. Every first-party image binds to the public repo (NAN-3307).
#
# GHCR links a NEW package to whatever `org.opencontainers.image.source` its
# first push carries, and that link is sticky. The lake images have never been
# published, so their first push decides where they show up and whose access
# they inherit. Check every first-party compose image's build stage carries
# the nano-rs/nano source label before that first push, not after.
# ----------------------------------------------------------------------------
SOURCE_LABEL='org.opencontainers.image.source="https://github.com/nano-rs/nano"'
for image in $compose_fp; do
    component=${image#ghcr.io/nano-rs/nano-}
    if [[ "$component" == web ]]; then
        dockerfile=nanosiem-web/Dockerfile
        stage=$(awk '/^FROM /{s=$0} END{print s}' "$dockerfile")
        body=$(awk '/^FROM /{buf=""} {buf=buf $0 "\n"} END{printf "%s", buf}' "$dockerfile")
    else
        dockerfile=Dockerfile
        stage="FROM … AS $component"
        body=$(awk -v t="$component" '
          /^FROM / { inside = ($NF == t) }
          inside   { print }
        ' "$dockerfile")
        [[ -n "$body" ]] || fail "$dockerfile has no \`$component\` stage for $image"
    fi
    grep -qF "$SOURCE_LABEL" <<<"$body" \
        || fail "$dockerfile stage '$stage' ($image) lacks LABEL $SOURCE_LABEL"
done
ok "every first-party image stage carries the nano-rs/nano source label"

# ----------------------------------------------------------------------------
# 8/9. PostgreSQL: one pinned major across both open-core compose files, an
#      explicit PGDATA, and the version guard wired in.
#
# PG18's image default PGDATA is /var/lib/postgresql/18/docker, NOT the
# /var/lib/postgresql/data the volume is mounted at. Without the explicit
# override a major bump silently initializes an EMPTY database outside the
# volume; with it, the server refuses to start on a foreign major — which is
# what the guard turns into an actionable message instead of a crash loop.
# ----------------------------------------------------------------------------
SIEM_ONLY="docker-compose.siem-only.yml"
for f in "$COMPOSE" "$SIEM_ONLY"; do
    [[ -f "$f" ]] || fail "$f not found — run from the repo root."

    POSTGRES_PASSWORD=x CLICKHOUSE_PASSWORD=x CLICKHOUSE_ADMIN_PASSWORD=x \
      JWT_SECRET=x NANOSIEM_ENCRYPTION_KEY=x VECTOR_AUTH_TOKEN=x \
      docker compose -f "$f" config -q 2>/dev/null \
        || fail "$f does not parse (docker compose config)"

    grep -qE '^\s+postgres-version-guard:' "$f" \
        || fail "$f has no postgres-version-guard service — a PostgreSQL major bump would crash-loop instead of failing with the migration command"

    awk '
      /^  postgres:$/       { in_pg = 1; next }
      in_pg && /^  [a-z]/   { in_pg = 0 }
      in_pg && /PGDATA: \/var\/lib\/postgresql\/data/  { pgdata = 1 }
      in_pg && /postgres-version-guard:/               { dep = 1 }
      END { exit !(pgdata && dep) }
    ' "$f" || fail "$f: the postgres service must set PGDATA=/var/lib/postgresql/data AND depend on postgres-version-guard"
done

majors=$(grep -hoE 'image:[[:space:]]*postgres:[0-9]+' "$COMPOSE" "$SIEM_ONLY" \
    | grep -oE '[0-9]+$' | sort -u)
[[ "$(printf '%s\n' "$majors" | wc -l | tr -d ' ')" == "1" ]] \
    || fail "the open-core compose files pin more than one PostgreSQL major: $(printf '%s' "$majors" | tr '\n' ' ')"
ok "PostgreSQL $majors pinned consistently, PGDATA explicit, version guard wired in both compose files"

# ----------------------------------------------------------------------------
# 11. nano-jobs carries nano-api's runtime environment (NAN-3375). Both
#     binaries build the same AppState, so a variable the shared constructor
#     requires on nano-api is required on nano-jobs too. The lake enrichment
#     coordinator URL was set only on nano-api, and nano-jobs panicked at boot
#     on every fresh lake install. Only variables that configure the HTTP
#     listener nano-api alone serves may differ.
# ----------------------------------------------------------------------------
# TRUSTED_PROXY_CIDRS: client-IP trust for inbound HTTP; jobs serves none.
API_ONLY_ENV='API_HOST API_PORT AUTH_ENABLED CORS_ORIGINS TRUSTED_PROXY_CIDRS'
lake_config_json=$(POSTGRES_PASSWORD=x CLICKHOUSE_PASSWORD=x CLICKHOUSE_ADMIN_PASSWORD=x \
  JWT_SECRET=x NANOSIEM_ENCRYPTION_KEY=x VECTOR_AUTH_TOKEN=x \
  COMPOSE_PROFILES=lake docker compose -f "$COMPOSE" config --format json 2>/dev/null) \
    || fail "$COMPOSE does not render as JSON for the lake profile"
missing_jobs_env=$(printf '%s' "$lake_config_json" | jq -r --arg allowed "$API_ONLY_ENV" '
    ($allowed | split(" ")) as $allow
    | (.services["nano-api"].environment | keys) - (.services["nano-jobs"].environment | keys)
    | map(select(. as $name | $allow | index($name) | not))
    | .[]')
[[ -z "$missing_jobs_env" ]] \
    || fail "nano-jobs lacks nano-api runtime env (shared AppState): $(printf '%s' "$missing_jobs_env" | tr '\n' ' ')"
ok "nano-jobs carries nano-api's runtime environment (except listener-only: $API_ONLY_ENV)"

# ----------------------------------------------------------------------------
# 12. Unauthenticated ingest ports bind to loopback by default (NAN-3322).
#     Vector native :6000, raw OTLP :4317/:4318 and Fluent :24224 check no
#     token; publishing them on every interface is opt-in via NANO_*_BIND_ADDRESS.
# ----------------------------------------------------------------------------
lean_config_json=$(env -u NANO_VECTOR_NATIVE_BIND_ADDRESS -u NANO_OTLP_BIND_ADDRESS -u NANO_FLUENT_BIND_ADDRESS \
  POSTGRES_PASSWORD=x JWT_SECRET=x NANOSIEM_ENCRYPTION_KEY=x VECTOR_AUTH_TOKEN=x \
  COMPOSE_PROFILES=lean docker compose -f "$COMPOSE" config --format json 2>/dev/null) \
    || fail "$COMPOSE does not render as JSON for the lean profile"
exposed=$(printf '%s' "$lean_config_json" | jq -r '
    .services | to_entries[] | .key as $svc | (.value.ports // [])[]
    | select((.target == 6000 or .target == 4317 or .target == 4318 or .target == 24224)
             and (.host_ip // "") != "127.0.0.1")
    | "\($svc):\(.target) host_ip=\(.host_ip // "all")"')
[[ -z "$exposed" ]] || fail "unauthenticated ingest port published beyond loopback by default: $(printf '%s' "$exposed" | tr '\n' ' ')"
reexposed=$(NANO_VECTOR_NATIVE_BIND_ADDRESS=0.0.0.0 NANO_FLUENT_BIND_ADDRESS=0.0.0.0 \
  POSTGRES_PASSWORD=x JWT_SECRET=x NANOSIEM_ENCRYPTION_KEY=x VECTOR_AUTH_TOKEN=x \
  COMPOSE_PROFILES=lean docker compose -f "$COMPOSE" config --format json 2>/dev/null \
  | jq -r '[.services[].ports // [] | .[] | select((.target == 6000 or .target == 24224) and .host_ip == "0.0.0.0")] | length')
[[ "$reexposed" == "2" ]] || fail "NANO_VECTOR_NATIVE_BIND_ADDRESS / NANO_FLUENT_BIND_ADDRESS do not re-expose :6000 / :24224"
ok "unauthenticated ingest ports (:6000, :4317/:4318, :24224) bind 127.0.0.1 unless NANO_*_BIND_ADDRESS is set"

printf '\n\033[32mAll open-source stack checks passed.\033[0m\n'
