#!/bin/sh
# ClickHouse pre-start preflight (NAN-4906). Runs as a one-shot compose service
# (`clickhouse-preflight`) before the server container starts; the server
# depends on it with `condition: service_completed_successfully`, so any
# non-zero exit here keeps ClickHouse from starting with a config or CPU it
# would crash on. Idempotent: a second run changes nothing.
#
#   usage: clickhouse-preflight.sh <config.d dir>
#
# 1. AVX2. x86-64 ClickHouse builds since 26.6 need AVX2 and die with SIGILL
#    without it. ClickHouse publishes no amd64compat Docker image, so there is
#    no image to fall back to: stop here with a clear message instead of
#    letting the server crash-loop.
# 1a. simdjson kernel (NAN-6000). ClickHouse parses every JSON value (the
#    JSON type, so init.sql's `ext JSON DEFAULT '{}'` and every insert) with
#    simdjson. The official amd64 build compiles in only simdjson's Haswell
#    kernel (no Westmere, no scalar fallback), and simdjson picks it from
#    CPUID only when AVX2, BMI1, BMI2 and PCLMULQDQ are all reported. A VM CPU
#    model that hides one of them (Proxmox's built-in x86-64-v3 and x86-64-v4
#    types omit pclmulqdq) still RUNS ClickHouse, but every JSON parse fails:
#    "Cannot parse JSON object here: {}" (Code 117) at CREATE TABLE
#    nanosiem.logs. Refuse with a clear fix, unless the operator opted into
#    rapidjson with the shipped zz-local-no-simdjson.xml drop-in.
# 2. Obsolete s3-disk elements. Tiering storage.xml files written before
#    NAN-4906 carry <cache_enabled>, <data_cache_enabled> and <cache_path>
#    inside the s3 disk. Nothing has read them since 22.8, but 26.10 rejects
#    them at startup (Code 137, UNKNOWN_ELEMENT_IN_CONFIG). Strip them from
#    every storage_configuration file in config.d, keep a one-time backup,
#    and fail if any survive.
#
# Test seams: PREFLIGHT_CPUINFO (default /proc/cpuinfo), PREFLIGHT_ARCH
# (default `uname -m`) and PREFLIGHT_USERS_DIR (default /users.d). See clickhouse/preflight/test-clickhouse-preflight.sh.
set -eu

CONFIG_DIR="${1:-/etc/clickhouse-server/config.d}"
CPUINFO="${PREFLIGHT_CPUINFO:-/proc/cpuinfo}"
ARCH="${PREFLIGHT_ARCH:-$(uname -m)}"
OBSOLETE='cache_enabled|data_cache_enabled|cache_path'
REQUIRED_BY="${NANO_PREFLIGHT_ROLE:-ClickHouse role}"
USERS_DIR="${PREFLIGHT_USERS_DIR:-/users.d}"

die() {
    echo "clickhouse-preflight: FATAL: $*" >&2
    exit 1
}

# ---- 1. AVX2 ---------------------------------------------------------------
case "$ARCH" in
    x86_64|amd64)
        [ -r "$CPUINFO" ] || die "$REQUIRED_BY cannot establish AVX2 capability because $CPUINFO is unreadable"
        if ! grep -qw avx2 "$CPUINFO"; then
            die "$REQUIRED_BY requires AVX2, but this x86-64 CPU has no AVX2. ClickHouse 26.6+ binaries would crash with an illegal instruction. Move this tenant to an AVX2-capable host (or expose AVX2 to the VM: Proxmox CPU type 'host') before upgrading. See docs/dev/CLICKHOUSE-UPGRADE-NOTES.md."
        fi
        echo "clickhouse-preflight: AVX2 present"
        missing=""
        # Keeper-only hosts never parse JSON (NANO_PREFLIGHT_ROLE lists roles).
        case "$REQUIRED_BY" in *clickhouse*|*ClickHouse*) simd_flags="bmi1 bmi2 pclmulqdq" ;; *) simd_flags="" ;; esac
        for flag in $simd_flags; do
            grep -qw "$flag" "$CPUINFO" || missing="$missing $flag"
        done
        if [ -n "$missing" ]; then
            if grep -qs '<allow_simdjson>0</allow_simdjson>' "$USERS_DIR"/*.xml; then
                echo "clickhouse-preflight: WARNING: this CPU does not report$missing, so ClickHouse's fast JSON parser cannot run here. Continuing because allow_simdjson is 0 in $USERS_DIR (slower JSON parsing). To get it back, set the VM's CPU type to 'host'." >&2
            else
                die "This server's CPU does not report$missing to programs. Without it ClickHouse cannot read any JSON value, so setup fails with 'Cannot parse JSON object here: {}'. This usually means the virtual machine uses a limited CPU type. To fix it, give the VM its host's CPU: Proxmox CPU types x86-64-v3 and x86-64-v4 lack pclmulqdq. In Proxmox, set the VM's Processor type to 'host' (qm set <vmid> --cpu host), or use a custom CPU model that adds +pclmulqdq, then shut the VM down and start it again. (x86-64-v2-AES has pclmulqdq but no AVX2, which ClickHouse also needs.) If you cannot change the CPU type, copy clickhouse/preflight/zz-local-no-simdjson.xml into clickhouse/users.d/ and run install.sh again; ClickHouse then uses a slower JSON parser."
            fi
        elif [ -n "$simd_flags" ]; then
            echo "clickhouse-preflight: simdjson CPU features present"
        fi
        ;;
    *)
        echo "clickhouse-preflight: arch $ARCH, AVX2 check not applicable"
        ;;
esac

# ---- 1b. Assembled configuration (NAN-5494, single host) --------------------
# ClickHouse must only ever start on the config.d / users.d trees that
# scripts/lib/clickhouse_config_dirs.py assembled (they carry the rendered
# network allow-list and sizing). Anything else, e.g. an extracted package not
# yet upgraded, or a v2.0.28 users.d that still holds the empty networks
# placeholder, would start ClickHouse with every nano user open to all private
# ranges. Refuse instead.
if [ "${NANO_PREFLIGHT_REQUIRE_ASSEMBLED:-0}" = 1 ]; then
    for dir in "$CONFIG_DIR" "$USERS_DIR"; do
        [ -f "$dir/.nano-assembled" ] || die "$dir was not assembled by this release's installer, so ClickHouse would start without nano's network allow-list and sizing. Run scripts/nano upgrade (or re-run install.sh), or assemble it: python3 -I scripts/lib/clickhouse_config_dirs.py --root . --record-env, then start again. See docs/getting-started/docker-deployment.md."
    done
    echo "clickhouse-preflight: assembled config.d and users.d present"
fi

# ---- 2. Obsolete s3-disk elements -------------------------------------------
[ -d "$CONFIG_DIR" ] || die "config dir $CONFIG_DIR does not exist"

for f in "$CONFIG_DIR"/*.xml; do
    [ -f "$f" ] || continue
    grep -q '<storage_configuration>' "$f" || continue
    grep -Eq "<($OBSOLETE)[[:space:]>/]" "$f" || continue

    [ -w "$f" ] || die "$f has obsolete s3-disk elements ($OBSOLETE) but is not writable; remove them by hand before starting ClickHouse 26.10"
    backup="$f.pre-nan4906.bak"
    [ -e "$backup" ] || cp -p "$f" "$backup" || die "cannot back up $f"

    tmp="$f.preflight.tmp"
    # Drop single-line <x>...</x> and <x/> forms of the three elements.
    sed -E \
        -e "/^[[:space:]]*<($OBSOLETE)>[^<]*<\/($OBSOLETE)>[[:space:]]*\$/d" \
        -e "/^[[:space:]]*<($OBSOLETE)[[:space:]]*\/>[[:space:]]*\$/d" \
        "$f" > "$tmp" || { rm -f "$tmp"; die "cannot rewrite $f"; }
    if grep -Eq "<($OBSOLETE)[[:space:]>/]" "$tmp"; then
        rm -f "$tmp"
        die "$f still has obsolete s3-disk elements ($OBSOLETE) in a form this script cannot remove; edit it by hand (backup at $backup)"
    fi
    # Rewrite in place (cat >) so the file keeps its inode, owner and mode.
    cat "$tmp" > "$f" || { rm -f "$tmp"; die "cannot write $f"; }
    rm -f "$tmp"
    echo "clickhouse-preflight: removed obsolete s3-disk elements from $f (backup: $backup)"
done

echo "clickhouse-preflight: ok"
