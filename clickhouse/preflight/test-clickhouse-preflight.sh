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

printf 'flags\t\t: fpu sse4_2 avx avx2 bmi2\n' > "$WORK/cpu_avx2"
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

run() { # run <arch> <cpuinfo> <dir>
    PREFLIGHT_ARCH="$1" PREFLIGHT_CPUINFO="$2" sh "$SCRIPT" "$3" >"$WORK/out" 2>&1
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

[ "$FAILS" -eq 0 ] || { echo "$FAILS test(s) failed"; exit 1; }
echo "all clickhouse-preflight tests passed"
