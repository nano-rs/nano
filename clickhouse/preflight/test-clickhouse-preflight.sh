#!/bin/sh
# Tests for clickhouse-preflight.sh (NAN-4906). Run: sh clickhouse/preflight/test-clickhouse-preflight.sh
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$HERE/clickhouse-preflight.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
FAILS=0

pass() { echo "ok   - $1"; }
fail() { echo "FAIL - $1"; FAILS=$((FAILS + 1)); }

printf 'flags\t\t: fpu pclmulqdq sse4_2 avx avx2 bmi1 bmi2\n' > "$WORK/cpu_avx2"
# NAN-6000: what Proxmox's x86-64-v3 CPU type reports (qemu64 + AVX2, no pclmulqdq).
printf 'flags\t\t: fpu sse4_2 popcnt aes xsave avx f16c avx2 fma bmi1 bmi2 movbe\n' > "$WORK/cpu_pve_v3"
printf 'flags\t\t: fpu sse4_2 avx\n' > "$WORK/cpu_noavx2"

legacy_storage_xml() {
    cat <<'EOF'
<?xml version="1.0"?>
<clickhouse>
    <storage_configuration>
        <disks>
            <s3_warm>
                <type>s3</type>
                <endpoint>https://s3.example/bucket/</endpoint>
                <metadata_path>/var/lib/clickhouse/disks/s3_warm/</metadata_path>
                <cache_enabled>true</cache_enabled>
                <data_cache_enabled>true</data_cache_enabled>
                <cache_path>/var/lib/clickhouse/disks/s3_warm_cache/</cache_path>
            </s3_warm>
        </disks>
    </storage_configuration>
</clickhouse>
EOF
}

mkdir "$WORK/users_none"
run() { # run <arch> <cpuinfo> <dir> [users.d]
    PREFLIGHT_ARCH="$1" PREFLIGHT_CPUINFO="$2" PREFLIGHT_USERS_DIR="${4:-$WORK/users_none}" \
        sh "$SCRIPT" "$3" >"$WORK/out" 2>&1
}

# 1. Legacy storage.xml is rewritten, backed up, and the rest is kept.
d="$WORK/legacy"; mkdir "$d"; legacy_storage_xml > "$d/storage.xml"
if run x86_64 "$WORK/cpu_avx2" "$d" \
    && ! grep -Eq 'cache_enabled|data_cache_enabled|cache_path' "$d/storage.xml" \
    && grep -q '<metadata_path>' "$d/storage.xml" \
    && grep -q '<cache_path>' "$d/storage.xml.pre-nan4906.bak"; then
    pass "strips obsolete s3-disk elements and keeps a backup"
else
    fail "strips obsolete s3-disk elements and keeps a backup"; cat "$WORK/out"
fi

# 2. Idempotent: a second run leaves the file byte-identical.
cp "$d/storage.xml" "$WORK/after1"
if run x86_64 "$WORK/cpu_avx2" "$d" && cmp -s "$d/storage.xml" "$WORK/after1"; then
    pass "second run is a no-op"
else
    fail "second run is a no-op"
fi

# 3. Files without storage_configuration are never touched.
d="$WORK/other"; mkdir "$d"
printf '<clickhouse><query_cache><cache_path>x</cache_path></query_cache></clickhouse>\n' > "$d/other.xml"
cp "$d/other.xml" "$WORK/other_before"
if run x86_64 "$WORK/cpu_avx2" "$d" && cmp -s "$d/other.xml" "$WORK/other_before"; then
    pass "leaves non-storage config files alone"
else
    fail "leaves non-storage config files alone"
fi

# 4. A form the script cannot strip (multi-line element) fails loudly.
d="$WORK/multiline"; mkdir "$d"
printf '<clickhouse><storage_configuration><disks><s3>\n<cache_enabled>\ntrue\n</cache_enabled>\n</s3></disks></storage_configuration></clickhouse>\n' > "$d/storage.xml"
if run x86_64 "$WORK/cpu_avx2" "$d"; then
    fail "fails on an unstrippable form"
else
    if grep -q FATAL "$WORK/out"; then pass "fails on an unstrippable form"; else fail "fails on an unstrippable form (no FATAL)"; fi
fi

# 5. x86-64 without AVX2 aborts before touching config.
d="$WORK/noavx"; mkdir "$d"; legacy_storage_xml > "$d/storage.xml"
if run x86_64 "$WORK/cpu_noavx2" "$d"; then
    fail "aborts on x86-64 without AVX2"
else
    if grep -q 'no AVX2' "$WORK/out" && [ ! -e "$d/storage.xml.pre-nan4906.bak" ]; then
        pass "aborts on x86-64 without AVX2"
    else
        fail "aborts on x86-64 without AVX2 (message/side effect)"
    fi
fi

# 6. arm64 skips the AVX2 check.
d="$WORK/arm"; mkdir "$d"
if run aarch64 "$WORK/cpu_noavx2" "$d"; then
    pass "skips the AVX2 check on arm64"
else
    fail "skips the AVX2 check on arm64"; cat "$WORK/out"
fi

# 7. Missing config dir fails.
if run aarch64 "$WORK/cpu_avx2" "$WORK/does-not-exist"; then
    fail "fails on a missing config dir"
else
    pass "fails on a missing config dir"
fi

# 8. NAN-6000: AVX2 but no pclmulqdq (Proxmox x86-64-v3) refuses with a clear fix.
d="$WORK/pvev3"; mkdir "$d"
if run x86_64 "$WORK/cpu_pve_v3" "$d"; then
    fail "refuses a CPU without pclmulqdq"
else
    if grep -q 'does not report pclmulqdq' "$WORK/out" && grep -q "cpu host" "$WORK/out" \
        && grep -q 'zz-local-no-simdjson.xml' "$WORK/out"; then
        pass "refuses a CPU without pclmulqdq"
    else
        fail "refuses a CPU without pclmulqdq (message)"; cat "$WORK/out"
    fi
fi

# 9. Each simdjson flag is required on its own.
for flag in bmi1 bmi2 pclmulqdq; do
    sed -e "s/ $flag//" "$WORK/cpu_avx2" > "$WORK/cpu_no_$flag"
    if run x86_64 "$WORK/cpu_no_$flag" "$d"; then
        fail "refuses a CPU without $flag"
    elif grep -q "does not report $flag" "$WORK/out"; then
        pass "refuses a CPU without $flag"
    else
        fail "refuses a CPU without $flag (message)"; cat "$WORK/out"
    fi
done

# 9b. A keeper-only host never parses JSON, so it is not refused.
# Subshell: a POSIX shell keeps an assignment made before a function call.
if (NANO_PREFLIGHT_ROLE=keeper; export NANO_PREFLIGHT_ROLE; run x86_64 "$WORK/cpu_pve_v3" "$d"); then
    pass "keeper-only host skips the simdjson check"
else
    fail "keeper-only host skips the simdjson check"; cat "$WORK/out"
fi

# 10. The shipped allow_simdjson=0 drop-in lets it start, with a warning.
u="$WORK/users_compat"; mkdir "$u"; cp "$HERE/zz-local-no-simdjson.xml" "$u/"
if run x86_64 "$WORK/cpu_pve_v3" "$d" "$u" && grep -q 'WARNING' "$WORK/out"; then
    pass "allow_simdjson=0 drop-in passes with a warning"
else
    fail "allow_simdjson=0 drop-in passes with a warning"; cat "$WORK/out"
fi

# 11. The drop-in covers every profile query_limits.xml defines.
QL="$HERE/../users.d/query_limits.xml"
missing_profiles=""
[ "$(awk '/<profiles>/,/<\/profiles>/' "$QL" | grep -c '^        <[a-z_]*>$')" -ge 9 ] || missing_profiles=" (profile list not found)"
for p in $(awk '/<profiles>/,/<\/profiles>/' "$QL" | sed -n 's/^        <\([a-z_]*\)>$/\1/p'); do
    grep -q "<$p><allow_simdjson>0</allow_simdjson></$p>" "$HERE/zz-local-no-simdjson.xml" || missing_profiles="$missing_profiles $p"
done
if [ -z "$missing_profiles" ]; then
    pass "drop-in covers every ClickHouse profile"
else
    fail "drop-in misses profiles:$missing_profiles"
fi

[ "$FAILS" -eq 0 ] || { echo "$FAILS test(s) failed"; exit 1; }
echo "all clickhouse-preflight tests passed"
