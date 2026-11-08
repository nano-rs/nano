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
#   * rewrites the `.responder` heartbeat every 30s.
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

# Build one standalone candidate dir: empty environment, no interpolation, bounded.
nano_validate() {
    env -i PATH=/usr/bin:/bin timeout 90 "$VECTOR" validate --skip-healthchecks --config-dir "$1" > "$2" 2>&1
}

# --- cross-process lock -----------------------------------------------------------------
# Best effort: a lock file that cannot be opened (read-only, missing) or a holder that does
# not let go within 120s does not keep Vector down.
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
    if { echo "$2"; awk -v mode="$3" "$ESCAPE_AWK" "$f"; } > "$m" && [ -s "$m" ] && mv -f "$m" "$f"; then
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
    [ -f "$f" ] || continue
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
        cp -f "$f" "$Q/$base.toml"
        cp "$t/output" "$Q/$base.reason"
        # Keep every component id the rest of the config names (the router and
        # parser filters read `<name>_route`): replace only the source tables
        # with an inert stand-in of the same id that emits nothing.
        awk '/^\[/ { skip = ($0 ~ /^\[sources\./) } !skip' "$f" > "$t/stub.toml"
        printf '\n# nano: source quarantined at startup (cannot build); see %s\n[transforms.%s]\ntype = "filter"\ninputs = ["internal_logs"]\ncondition = "false"\n' \
            "$Q/$base.reason" "$src" >> "$t/stub.toml"
        mv -f "$t/stub.toml" "$f"
        echo "nano: quarantined the source in $f at startup: Vector cannot build it (reason in $Q/$base.reason)" >&2
    fi
    rm -rf "$t"
done
done
# Release the lock before Vector starts (Vector must not inherit it).
exec 9<&-

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

exec "$VECTOR" "$@"
