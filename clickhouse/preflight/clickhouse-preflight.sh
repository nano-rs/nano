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
# 2. Obsolete s3-disk elements. Tiering storage.xml files written before
#    NAN-4906 carry <cache_enabled>, <data_cache_enabled> and <cache_path>
#    inside the s3 disk. Nothing has read them since 22.8, but 26.10 rejects
#    them at startup (Code 137, UNKNOWN_ELEMENT_IN_CONFIG). Strip them from
#    every storage_configuration file in config.d, keep a one-time backup,
#    and fail if any survive.
#
# Test seams: PREFLIGHT_CPUINFO (default /proc/cpuinfo) and PREFLIGHT_ARCH
# (default `uname -m`). See clickhouse/preflight/test-clickhouse-preflight.sh.
set -eu

CONFIG_DIR="${1:-/etc/clickhouse-server/config.d}"
CPUINFO="${PREFLIGHT_CPUINFO:-/proc/cpuinfo}"
ARCH="${PREFLIGHT_ARCH:-$(uname -m)}"
OBSOLETE='cache_enabled|data_cache_enabled|cache_path'
REQUIRED_BY="${NANO_PREFLIGHT_ROLE:-ClickHouse role}"

die() {
    echo "clickhouse-preflight: FATAL: $*" >&2
    exit 1
}

# ---- 1. AVX2 ---------------------------------------------------------------
case "$ARCH" in
    x86_64|amd64)
        [ -r "$CPUINFO" ] || die "$REQUIRED_BY cannot establish AVX2 capability because $CPUINFO is unreadable"
        if ! grep -qw avx2 "$CPUINFO"; then
            die "$REQUIRED_BY requires AVX2, but this x86-64 CPU has no AVX2. ClickHouse 26.6+ binaries would crash with an illegal instruction. Move this tenant to an AVX2-capable host (or expose AVX2 to the VM: Proxmox CPU type 'host' or x86-64-v3) before upgrading. See docs/dev/CLICKHOUSE-UPGRADE-NOTES.md."
        fi
        echo "clickhouse-preflight: AVX2 present"
        ;;
    *)
        echo "clickhouse-preflight: arch $ARCH, AVX2 check not applicable"
        ;;
esac

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
