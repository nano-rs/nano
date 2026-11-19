#!/bin/sh
# nano Vector container entrypoint (NAN-4936). `exec`s Vector with the arguments it is given.
#
# Lives in a dot-directory so Vector's --config-dir loader skips it (it skips dot-dirs and
# files without a config extension).
#
# Before Vector starts:
#   * creates the dynamic config dirs (a missing --config-dir is fatal on a fresh volume);
#   * ENV-ESCAPE MIGRATION: rewrites any source-config file rendered before NAN-4936, and any
#     parser file (tenant VRL) rendered before NAN-4953, with every `$` escaped (the live
#     Vector expands env vars; a tenant `${SECRET}` must stay literal);
#   * COLD-START GUARD: builds every api-rendered pull source on its own. One that cannot
#     build (a revoked or refused credential) would make Vector refuse the WHOLE config at
#     startup: a crash loop and a full ingest outage. Its original file and Vector's reason
#     go to dynamic/quarantine/, and its source table is replaced in place by an inert
#     filter of the same id (so the router and parsers that name its route still load).
#     nano-api reads the reason and shows the source as quarantined.
#
# While Vector runs, a background loop on the nano-vector-validation volume:
#   * answers isolation requests (<id>/request): `vector validate --skip-healthchecks` of the
#     candidate source with an EMPTY environment and WITHOUT env interpolation, so a
#     tenant-controlled `${SECRET}` in a rendered value stays a literal and can never expand
#     to this container's secrets (VECTOR_AUTH_TOKEN, CLICKHOUSE_PASSWORD, ...);
#   * answers reload requests (reload/<id>.request): SIGHUP to PID 1 after checking that
#     PID 1 is the Vector binary. This is how an api without a docker CLI (open compose)
#     delivers a reload without relying on the config watcher alone. Never a name pattern;
#   * answers stop requests (reload/<id>.stop, NAN-5564): SIGTERM to PID 1 (same check), a
#     graceful shutdown the restart policy follows with a fresh start;
#   * rewrites the `.responder` heartbeat every 30s.
# It starts BEFORE the pipeline gate (NAN-5564), so isolation requests are answered while
# Vector waits for nano-api to render the current pipeline.
# The validation volume is mounted OUTSIDE /etc/vector: Vector watches its config dirs
# recursively, so any write under /etc/vector reloads the topology.
set -u

D="${NANO_VECTOR_DYNAMIC_DIR:-/etc/vector/dynamic}"
V=/var/lib/nano-validation
Q="$D/quarantine"
VECTOR=/usr/bin/vector
# NAN-4953 (codex P2): the lock nano-api's deploys hold (Rust `config_lock`, `flock(2)` on the
# same file in the shared volume). Held for the migration and the cold-start guard so neither
# can interleave with an api write: no stale rename over a fresh render, no half-written read,
# no double escape. The file lives in the api's config dir (dev compose: /etc/vector).
LOCK_FILE="${NANO_VECTOR_LOCK_FILE:-$D/.nano-config.lock}"

mkdir -p "$D/sources/parsers" "$D/sources/configs" "$Q" "$V/reload" 2>/dev/null
# nano-api (uid 999) creates the requests.
chown 999:999 "$V" "$V/reload" 2>/dev/null || true

# The dynamic dirs this Vector loads, from its own --config-dir arguments, so every shipped
# topology is covered (open compose: dynamic/sources/{parsers,configs}; dev compose:
# sources/{parsers,configs}). The static base dir is never touched: its ${...} are meant.
PARSER_DIRS=""
SOURCE_DIRS=""
prev=""
for a in "$@"; do
    if [ "$prev" = "--config-dir" ] || [ "$prev" = "-C" ]; then
        d="${a%/}"
        case "$d" in
            */parsers) PARSER_DIRS="$PARSER_DIRS $d" ;;
            */configs) SOURCE_DIRS="$SOURCE_DIRS $d" ;;
        esac
    fi
    prev="$a"
done

# --- ownership of the dynamic tree (NAN-5610) --------------------------------------------
# This entrypoint runs as root, but nano-api (uid 999 in compose) writes the dynamic tree in
# place: a file this script rewrote as root:root (the env-escape migration below, the
# cold-start guard's stubs and quarantine copies) used to stay root-owned, and every later
# api write of it failed with "Permission denied" (HTTP Ingestion's routing rules never
# reached Vector again after an upgrade). Every path this script writes under the dynamic
# dir now gets the owner of the directory it is in, mode kept; and at start, root-owned
# files and dirs left by older entrypoints are re-owned the same way, each logged. Only
# when the directory owner is not root (a root-owned dynamic dir means root is the writer);
# the static /etc/vector tree is never touched. `stat -c` is GNU coreutils (the Debian
# Vector image); without it nothing is changed.
# BEGIN nano-dynamic-ownership
nano_owner_of() {
    stat -c '%u:%g' "$1" 2>/dev/null
}
# nano_own_like_dir PATH [REFERENCE_DIR [quiet]]: give PATH the owner of REFERENCE_DIR
# (default: its own directory) when that owner is not root and PATH differs. Mode is
# unchanged. `quiet` (NAN-5611): PATH is this script's own new temp file, so a successful
# re-own is routine, not a heal worth logging; a failure is still a warning.
nano_own_like_dir() {
    # Never through a symlink: nano-api (and so tenant-driven writes) can create entries
    # here, and a chown as root that followed one could re-own anything in the container.
    [ -L "$1" ] && return 0
    want=$(nano_owner_of "${2:-$(dirname "$1")}") || return 0
    case "$want" in ''|0:*) return 0 ;; esac
    have=$(nano_owner_of "$1") || return 0
    [ "$have" = "$want" ] && return 0
    if chown -h "$want" "$1" 2>/dev/null; then
        [ "${3:-}" = quiet ] && return 0
        echo "nano-vector: re-owned $1 ($have -> $want, NAN-5610): nano-api writes it" >&2
    else
        echo "nano-vector: WARNING: could not re-own $1 ($have) to $want; nano-api cannot rewrite it" >&2
    fi
}
# nano_heal_dynamic_ownership DYNAMIC_DIR DIR...: re-own root-owned entries the api writes:
# each DIR itself (to DYNAMIC_DIR's owner) and the files directly in it, dot-files included
# (the activation marker, .reason files). Idempotent: a correct tree logs nothing.
nano_heal_dynamic_ownership() {
    root_dir="$1"; shift
    owner=$(nano_owner_of "$root_dir") || return 0
    case "$owner" in ''|0:*) return 0 ;; esac
    for hd in "$@"; do
        # Only inside the dynamic dir (dev compose mounts static dirs as --config-dir too).
        case "$hd" in "$root_dir"/*) ;; *) continue ;; esac
        [ -d "$hd" ] && [ ! -L "$hd" ] || continue
        case "$(nano_owner_of "$hd")" in 0:*) nano_own_like_dir "$hd" "$root_dir" ;; esac
        for hf in "$hd"/* "$hd"/.[!.]*; do
            [ -f "$hf" ] && [ ! -L "$hf" ] || continue
            case "$(nano_owner_of "$hf")" in 0:*) nano_own_like_dir "$hf" "$hd" ;; esac
        done
    done
}
# END nano-dynamic-ownership
nano_heal_dynamic_ownership "$D" $SOURCE_DIRS $PARSER_DIRS "$Q"

# Build one standalone candidate dir: empty environment, no interpolation, bounded.
nano_validate() {
    env -i PATH=/usr/bin:/bin timeout 90 "$VECTOR" validate --skip-healthchecks --config-dir "$1" > "$2" 2>&1
}

# --- responder ----------------------------------------------------------------------------
(
    # Guard: no stray HUP may kill an in-flight validation (it inherits this).
    trap '' HUP
    n=0
    while :; do
        if [ "$n" -eq 0 ]; then
            date +%s > "$V/.responder.tmp" && mv -f "$V/.responder.tmp" "$V/.responder"
        fi
        n=$(( (n + 1) % 30 ))
        for r in "$V"/reload/*.request; do
            [ -f "$r" ] || continue
            if [ "$(readlink /proc/1/exe 2>/dev/null)" = "$VECTOR" ] && kill -HUP 1; then
                mv -f "$r" "${r%.request}.done"
            else
                mv -f "$r" "${r%.request}.refused"
            fi
        done
        # NAN-5564: a stop request (a deploy that changes a sink's buffer settings, which
        # Vector cannot hot-reload: the old topology keeps the disk buffer's lock). SIGTERM is
        # Vector's graceful shutdown: sources close, in-flight events reach the disk buffers.
        # The restart policy starts the container again, and the gate below holds it until
        # the deploy has written the new config.
        for r in "$V"/reload/*.stop; do
            [ -f "$r" ] || continue
            if [ "$(readlink /proc/1/exe 2>/dev/null)" = "$VECTOR" ]; then
                mv -f "$r" "${r%.stop}.stopping" && kill -TERM 1
            else
                mv -f "$r" "${r%.stop}.refused"
            fi
        done
        for r in "$V"/*/request; do
            [ -f "$r" ] || continue
            d=$(dirname "$r")
            [ -e "$d/result" ] && continue
            nano_validate "$d/config" "$d/output"
            echo $? > "$d/result.tmp"
            mv -f "$d/result.tmp" "$d/result"
        done
        sleep 1
    done
) &

# --- pipeline gate (NAN-5564) ------------------------------------------------------------
# After an upgrade the dynamic tree in the volume is the one the PREVIOUS release rendered
# (a 0.1.x tree acknowledges before durability: acks off, drop_newest). Running it, then
# hot-reloading onto the new one (which changes the sinks' disk buffers and crashes Vector),
# lost acknowledged events. So Vector does not start, and its ports refuse connections
# (nothing is acknowledged; senders retry), until nano-api has rendered the tree for THIS
# pipeline identity (release / ack durability / fan-in slots; compose sets
# NANO_PIPELINE_IDENTITY on both containers from the same .env). nano-api writes the identity
# to $D/.nano-pipeline-identity after it has written the tree, and retries the render in the
# background until it can (a failed boot render does not leave Vector gated). Unset: no gate
# (dev, Helm).
# A deploy that stops Vector to change a sink's buffer (the stop request above) also holds
# the restart until it has written the new tree ($V/.nano-vector-hold, epoch seconds; one
# older than NANO_VECTOR_HOLD_MAX_SECS, default 300, is from a deploy that died and is
# ignored). NANO_VECTOR_PIPELINE_WAIT_SECS bounds the identity wait (default 900 s; 0 = no
# bound): after it Vector starts on the tree it has, with a loud warning every start, so a
# broken nano-api cannot keep ingest refused indefinitely.
# BEGIN nano-pipeline-gate
nano_pipeline_gate() {
    gate_file="$D/.nano-pipeline-identity"
    hold_file="$V/.nano-vector-hold"
    gate_max="${NANO_VECTOR_PIPELINE_WAIT_SECS:-900}"
    hold_max="${NANO_VECTOR_HOLD_MAX_SECS:-300}"
    poll="${NANO_VECTOR_GATE_POLL_SECS:-1}"
    case "$gate_max" in ''|*[!0-9]*) gate_max=900 ;; esac
    case "$hold_max" in ''|*[!0-9]*) hold_max=300 ;; esac
    case "$poll" in ''|0|*[!0-9]*) poll=1 ;; esac
    waited=0
    while :; do
        reason=""
        if [ -n "${NANO_PIPELINE_IDENTITY:-}" ]; then
            have=$(head -n 1 "$gate_file" 2>/dev/null)
            if [ "$have" != "$NANO_PIPELINE_IDENTITY" ]; then
                if [ "$gate_max" -gt 0 ] && [ "$waited" -ge "$gate_max" ]; then
                    echo "nano-vector: ERROR: nano-api has not rendered the Vector config for '$NANO_PIPELINE_IDENTITY' after ${waited}s (it has '${have:-nothing}'); starting Vector on that config so ingest is not refused indefinitely. Check 'docker compose logs nano-api'. NANO_VECTOR_PIPELINE_WAIT_SECS sets this wait." >&2
                else
                    reason="the config in the volume was rendered for '${have:-nothing}', not '$NANO_PIPELINE_IDENTITY'; waiting for nano-api to render it"
                fi
            fi
        fi
        if [ -z "$reason" ] && [ -f "$hold_file" ]; then
            since=$(head -n 1 "$hold_file" 2>/dev/null | tr -cd '0-9')
            if [ -n "$since" ] && [ $(( $(date +%s) - since )) -lt "$hold_max" ]; then
                reason="a deploy is changing a sink's buffer settings; waiting for it to write the new config"
            fi
        fi
        [ -n "$reason" ] || return 0
        if [ $((waited % 30)) -lt "$poll" ]; then
            echo "nano-vector: not starting Vector yet (its ports refuse connections, so nothing is acknowledged): $reason" >&2
        fi
        sleep "$poll"
        waited=$((waited + poll))
    done
}
# END nano-pipeline-gate
nano_pipeline_gate

# --- cross-process lock -----------------------------------------------------------------
# Best effort: a lock file that cannot be opened (read-only, missing) or a holder that does
# not let go within 120s does not keep Vector down. NAN-5298: a deploy waiting on a Vector that
# died (this restart) gives up after VECTOR_RELOAD_ACK_UNREADABLE_SECS (60) of unreadable
# metrics, and its rollback reload waits only the base window (45), so it lets go inside 120s.
# (`touch` and `-r` first: a failed redirection on `exec` would end this shell.)
[ -e "$LOCK_FILE" ] || touch "$LOCK_FILE" 2>/dev/null
if [ -r "$LOCK_FILE" ]; then
    exec 9<"$LOCK_FILE"
    flock -w 120 9 || echo "nano: config lock still held after 120s; migrating without it" >&2
else
    echo "nano: no config lock at $LOCK_FILE; migrating without it" >&2
fi

# --- env-escape migration -------------------------------------------------------------
# The live Vector runs with env interpolation ON (the static config needs ${VECTOR_AUTH_TOKEN},
# ${CLICKHOUSE_*}, ...). nano-api renders every file that carries tenant text with `$` escaped
# as `$$` and ESCAPED on line 1. A file without the mark predates that (it sat in the
# persistent volume across an upgrade) and may hold a tenant value such as
# `${CLICKHOUSE_PASSWORD}` that the live Vector would expand.
#
# The migration keeps what the pre-upgrade Vector actually ran (codex P2): an existing `$$`
# already meant a literal `$` to that Vector and is kept; only a LONE `$` is doubled. So
# `$${X}` stays `$${X}`, `$1` becomes `$$1` (both deliver the same text as before), and
# `${CLICKHOUSE_PASSWORD}` becomes `$${CLICKHOUSE_PASSWORD}` (a literal, never the secret).
ESCAPED='# nano-env-escaped: v1'
TENANT_VRL='# nano-env-escaped: v1 tenant-vrl'
# awk: escape lone `$` on every line (mode=all) or only inside ''' VRL blocks (mode=vrl).
ESCAPE_AWK='
function esc(s,    out, i, n, c) {
    out = ""; n = length(s)
    for (i = 1; i <= n; i++) {
        c = substr(s, i, 1)
        if (c == "$") { out = out "$$"; if (substr(s, i + 1, 1) == "$") i++ }
        else out = out c
    }
    return out
}
mode == "all" { print esc($0); next }
inb && $0 == "'"'''"'" { inb = 0; print; next }
inb { print esc($0); next }
$0 == "source = '"'''"'" { inb = 1 }
{ print }'

# migrate FILE HEADER MODE LABEL: atomic rewrite; a file that cannot be migrated is moved out
# of the loaded dir (into its .nano-quarantine/ dot-dir, which Vector skips), never left
# unescaped.
migrate() {
    f="$1"; dir=$(dirname "$f"); base=$(basename "$f")
    m="$dir/.$base.migrate"
    # NAN-5610: never read or rewrite a symlink as root (nano-api can create entries here).
    if [ -L "$f" ]; then
        echo "nano: left $f alone: it is a symbolic link" >&2
        return 0
    fi
    # The rewrite is created with the file's mode (a umask, no chmod on a shared path) and
    # given its directory's owner BEFORE it replaces the file, so it is never visible
    # with other permissions and no root operation follows a swapped-in path.
    mode=$(stat -c '%a' "$f" 2>/dev/null) || mode=""
    case "$mode" in [0-7][0-7][0-7]|[0-7][0-7][0-7][0-7]) mask=$(printf '%03o' $(( 0777 & ~0$mode ))) ;; *) mask=022 ;; esac
    rm -f "$m"
    # noclobber: create it new (O_EXCL), never write through something put in its place.
    if ( umask "$mask"; set -C; { echo "$2"; awk -v mode="$3" "$ESCAPE_AWK" "$f"; } > "$m" ) && [ -s "$m" ] \
        && nano_own_like_dir "$m" "$dir" quiet && mv -f "$m" "$f"; then
        grep -q '\$' "$f" && echo "nano: escaped env-interpolation syntax in $f (rendered before $4)" >&2
    else
        rm -f "$m"
        mkdir -p "$dir/.nano-quarantine" && mv -f "$f" "$dir/.nano-quarantine/$base.quarantined" \
            || rm -f "$f"
        echo "nano: moved $f out of the live config: could not escape it" >&2
    fi
}

# Source configs (NAN-4936): nano's own content has no `$`, so the whole file is escaped.
for sd in $SOURCE_DIRS; do
    for f in "$sd"/*.toml; do
        [ -f "$f" ] || continue
        [ "$(head -n 1 "$f")" = "$ESCAPED" ] && continue
        migrate "$f" "$ESCAPED" all NAN-4936
    done
done

# Parser files (NAN-4953): tenant VRL (parser editor, Nano Pipe advanced VRL, pivt drafts)
# reaches the live config through the per-parser TOMLs and _router.toml.
#   * nano's own interpolating files (_pipeline, _ocsf_sink, legacy _ocsf) and the combiner
#     hold no tenant text and are left alone: they NEED ${CLICKHOUSE_*} expanded;
#   * _enrichment.toml mixes both: only its ''' VRL blocks (enrichment parsers' normalize
#     VRL) are escaped, and it gets the TENANT_VRL header;
#   * every other parser file is escaped whole.
for pd in $PARSER_DIRS; do
    for f in "$pd"/*.toml; do
        [ -f "$f" ] || continue
        first=$(head -n 1 "$f")
        [ "$first" = "$ESCAPED" ] && continue
        [ "$first" = "$TENANT_VRL" ] && continue
        case "$(basename "$f")" in
            _pipeline.toml|_ocsf_sink.toml|_ocsf.toml|_combiner.toml) continue ;;
            _enrichment.toml) migrate "$f" "$TENANT_VRL" vrl NAN-4953 ;;
            *) migrate "$f" "$ESCAPED" all NAN-4953 ;;
        esac
    done
done

# --- cold-start guard -------------------------------------------------------------------
for sd in $SOURCE_DIRS; do
for f in "$sd"/*.toml; do
    [ -f "$f" ] && [ ! -L "$f" ] || continue
    # Routing-only files (system listeners) and the activation marker have no pull source.
    grep -q '^\[sources\.' "$f" || continue
    route=$(sed -n 's/^\[transforms\.\([A-Za-z0-9_]*_route\)\]$/\1/p' "$f" | head -n 1)
    [ -n "$route" ] || continue
    t=$(mktemp -d)
    cp "$f" "$t/source.toml"
    printf '[sinks.nano_isolation_sink]\ntype = "blackhole"\ninputs = ["%s"]\nprint_interval_secs = 0\n' "$route" > "$t/zz_isolation_sink.toml"
    if ! nano_validate "$t" "$t/output"; then
        base=$(basename "$f" .toml)
        src=$(sed -n 's/^\[sources\.\([A-Za-z0-9_]*\)\]$/\1/p' "$f" | head -n 1)
        # NAN-5610: staged in the root-only temp dir, owned like $Q (nano-api reads and
        # clears these), then moved in: no root write through a path in the shared volume.
        cp "$f" "$t/q.toml" && nano_own_like_dir "$t/q.toml" "$Q" quiet && mv -f "$t/q.toml" "$Q/$base.toml"
        cp "$t/output" "$t/q.reason" && nano_own_like_dir "$t/q.reason" "$Q" quiet && mv -f "$t/q.reason" "$Q/$base.reason"
        # Keep every component id the rest of the config names (the router and
        # parser filters read `<name>_route`): replace only the source tables
        # with an inert stand-in of the same id that emits nothing.
        awk '/^\[/ { skip = ($0 ~ /^\[sources\./) } !skip' "$f" > "$t/stub.toml"
        printf '\n# nano: source quarantined at startup (cannot build); see %s\n[transforms.%s]\ntype = "filter"\ninputs = ["internal_logs"]\ncondition = "false"\n' \
            "$Q/$base.reason" "$src" >> "$t/stub.toml"
        # NAN-5610: mode and owner set in the root-only temp dir, before the move.
        mode=$(stat -c '%a' "$f" 2>/dev/null) || mode=""
        [ -z "$mode" ] || chmod "$mode" "$t/stub.toml" 2>/dev/null
        nano_own_like_dir "$t/stub.toml" "$(dirname "$f")" quiet
        mv -f "$t/stub.toml" "$f"
        echo "nano: quarantined the source in $f at startup: Vector cannot build it (reason in $Q/$base.reason)" >&2
    fi
    rm -rf "$t"
done
done
# Release the lock before Vector starts (Vector must not inherit it).
exec 9<&-

# --- public install token (NAN-5013) -----------------------------------------------------
# nano refuses a publicly known VECTOR_AUTH_TOKEN on every ingest lane: nano-api never lists
# it in the tokens file. The static fallback (NANO_INGEST_STATIC_FALLBACK=true, an explicit
# opt-in for a missing tokens file) compares against ${VECTOR_AUTH_TOKEN} directly, so it is
# switched off here for such a value. Keep this list identical to the vector_install_token
# rows of config/known-public-secrets.txt (scripts/tests/test_vector_entrypoint_public_token.py).
# BEGIN nano-public-install-token
if [ "${NANO_INGEST_STATIC_FALLBACK:-}" = true ]; then
    case "${VECTOR_AUTH_TOKEN:-}" in
        CHANGE_ME|CHANGE_ME_GENERATED|CHANGE_ME_GENERATE_WITH_OPENSSL_RAND_HEX_32|nanosiem-default-token|your-secret-token)
            echo "nano-vector: ignoring NANO_INGEST_STATIC_FALLBACK=true: VECTOR_AUTH_TOKEN is a publicly known default, which nano refuses. Set a generated token (re-run install.sh) or deliver the ingest tokens file." >&2
            NANO_INGEST_STATIC_FALLBACK=false
            export NANO_INGEST_STATIC_FALLBACK
            ;;
    esac
fi
# END nano-public-install-token

# --- Vector-native mutual TLS (NAN-5515) -------------------------------------------------
# The vector_native source (01-vector-source.toml) is mutual TLS only: it loads the listener
# certificate and key and the sender anchor bundle from NANO_VECTOR_NATIVE_{CRT,KEY,CA}_FILE
# (default /etc/nano/vector-native/, which install.sh / nano upgrade fill). A missing or
# unreadable file would make Vector refuse its WHOLE config (every ingest lane down), so
# substitute LOCKED material: an anchor whose key is deleted at once. :6000 then refuses every
# sender; it never falls back to plaintext.
NV_CRT="${NANO_VECTOR_NATIVE_CRT_FILE:-/etc/nano/vector-native/server.crt}"
NV_KEY="${NANO_VECTOR_NATIVE_KEY_FILE:-/etc/nano/vector-native/server.key}"
NV_CA="${NANO_VECTOR_NATIVE_CA_FILE:-/etc/nano/vector-native/client-ca.crt}"
NV_BAD=""
for NV_F in "$NV_CRT" "$NV_KEY" "$NV_CA"; do
    if [ ! -s "$NV_F" ]; then
        NV_BAD="$NV_BAD missing:$NV_F"
    elif [ ! -r "$NV_F" ]; then
        NV_BAD="$NV_BAD unreadable:$NV_F"
    fi
done
if [ -n "$NV_BAD" ]; then
    NV_LOCKED=/tmp/nano-vector-native-locked
    rm -rf "$NV_LOCKED"
    if (umask 077 && mkdir -p "$NV_LOCKED" \
        && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
            -subj "/O=nano/CN=nano vector-native LOCKED" \
            -keyout "$NV_LOCKED/ca.key" -out "$NV_LOCKED/client-ca.crt" \
        && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
            -subj "/O=nano/CN=nano vector-native listener" \
            -keyout "$NV_LOCKED/server.key" -out "$NV_LOCKED/server.crt") >/dev/null 2>&1; then
        rm -f "$NV_LOCKED/ca.key"
        NANO_VECTOR_NATIVE_CRT_FILE="$NV_LOCKED/server.crt"
        NANO_VECTOR_NATIVE_KEY_FILE="$NV_LOCKED/server.key"
        NANO_VECTOR_NATIVE_CA_FILE="$NV_LOCKED/client-ca.crt"
        export NANO_VECTOR_NATIVE_CRT_FILE NANO_VECTOR_NATIVE_KEY_FILE NANO_VECTOR_NATIVE_CA_FILE
        case "$NV_BAD" in
            *unreadable:*)
                echo "nano-vector: ERROR: Vector-native TLS files are not readable by Vector (${NV_BAD# }). With Docker userns-remap or a rootless daemon, container root cannot read a 0600 key owned by the install user: disable userns-remap for nano or make the key readable to the remapped root. Port 6000 refuses every sender until then." >&2 ;;
            *)
                echo "nano-vector: WARNING: no Vector-native TLS files (${NV_BAD# }); port 6000 refuses every sender until install.sh or scripts/nano upgrade issues them" >&2 ;;
        esac
    else
        rm -rf "$NV_LOCKED"
        echo "nano-vector: could not create locked Vector-native TLS material in $NV_LOCKED" >&2
    fi
fi

# --- ingest gate (NAN-5566) --------------------------------------------------------------
# Single node only (NANO_VECTOR_INGEST_GATE=on): the push listeners senders reach on the
# published ports (http_ingest :8080, splunk_hec_ingest :8088, OTLP :4317/:4318,
# vector_native :6000) take their listen address from a Vector `file` secret backend, so
# `.nano/ingest-gate.sh close|open` can move them to loopback-only ports and back with a
# hot reload (sources only; no sink or buffer is touched). scripts/nano and install.sh
# close it before they drain and stop Vector, so a direct sender gets "connection refused"
# instead of a 200 for an event the stop could lose. Every start is open.
# BEGIN nano-ingest-gate
nano_ingest_gate_setup() {
    gate="${NANO_INGEST_GATE_DIR:-/tmp/nano-ingest-gate}"
    mkdir -p "$gate/config" || return 1
    # An operator's explicit address stays the open value.
    open_addr() {
        case "$1" in ''|SECRET\[*) printf '%s' "$2" ;; *) printf '%s' "$1" ;; esac
    }
    http=$(open_addr "${NANO_HTTP_INGEST_ADDRESS:-}" 0.0.0.0:8080)
    hec=$(open_addr "${NANO_HEC_ADDRESS:-}" 0.0.0.0:8088)
    grpc=$(open_addr "${NANO_OTLP_GRPC_ADDRESS:-}" 0.0.0.0:4317)
    otlp=$(open_addr "${NANO_OTLP_HTTP_ADDRESS:-}" 0.0.0.0:4318)
    native=$(open_addr "${NANO_VECTOR_NATIVE_ADDRESS:-}" 0.0.0.0:6000)
    printf '{"http":"%s","hec":"%s","otlp_grpc":"%s","otlp_http":"%s","native":"%s"}\n' \
        "$http" "$hec" "$grpc" "$otlp" "$native" > "$gate/open.json" || return 1
    printf '{"http":"127.0.0.1:18080","hec":"127.0.0.1:18088","otlp_grpc":"127.0.0.1:14317","otlp_http":"127.0.0.1:14318","native":"127.0.0.1:16000"}\n' \
        > "$gate/closed.json" || return 1
    cp "$gate/open.json" "$gate/addresses.json" || return 1
    printf '# nano ingest gate (NAN-5566); written at every start\n[secret.nano_ingest_gate]\ntype = "file"\npath = "%s/addresses.json"\n' \
        "$gate" > "$gate/config/nano-ingest-gate.toml" || return 1
    NANO_HTTP_INGEST_ADDRESS='SECRET[nano_ingest_gate.http]'
    NANO_HEC_ADDRESS='SECRET[nano_ingest_gate.hec]'
    NANO_OTLP_GRPC_ADDRESS='SECRET[nano_ingest_gate.otlp_grpc]'
    NANO_OTLP_HTTP_ADDRESS='SECRET[nano_ingest_gate.otlp_http]'
    NANO_VECTOR_NATIVE_ADDRESS='SECRET[nano_ingest_gate.native]'
    export NANO_HTTP_INGEST_ADDRESS NANO_HEC_ADDRESS NANO_OTLP_GRPC_ADDRESS NANO_OTLP_HTTP_ADDRESS \
        NANO_VECTOR_NATIVE_ADDRESS
    NANO_INGEST_GATE_CONFIG_DIR="$gate/config"
}
# END nano-ingest-gate
NANO_INGEST_GATE_CONFIG_DIR=""
if [ "${NANO_VECTOR_INGEST_GATE:-}" = on ]; then
    nano_ingest_gate_setup \
        || echo "nano-vector: WARNING: could not set up the ingest gate; ingest stays open across backups and restarts" >&2
fi

if [ -n "$NANO_INGEST_GATE_CONFIG_DIR" ]; then
    exec "$VECTOR" "$@" --config-dir "$NANO_INGEST_GATE_CONFIG_DIR"
fi
exec "$VECTOR" "$@"
