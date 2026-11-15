#!/usr/bin/env bash
# NAN-5449: how many days of events a ClickHouse data disk holds.
#
#   retention-sizing.sh --gb-per-day N --retention-days R --disk-bytes B \
#       [--overhead-bytes O]
#
# Prints KEY=VALUE lines:
#   NANO_RETENTION_SUPPORTED_DAYS  days of events the disk holds before the
#                                  disk-pressure cleanup starts dropping the
#                                  oldest days
#   NANO_RETENTION_NEEDED_BYTES    disk the target retention needs
#   NANO_RETENTION_VERDICT         ok | warn (supported < target) |
#                                  refuse (supported < the 7-day minimum)
#
# The model is the nano-deploy skill's (skills/nano-deploy/scripts/plan.py,
# `clickhouse_shape`): stored bytes = GB/day x days / COMPRESSION x
# MV_OVERHEAD, and the disk is planned to be at most DISK_FILL full. The
# constants below must equal plan.py's COMPRESSION, CH_MV_OVERHEAD and
# CH_DISK_FILL and the Helm chart's (templates/_helpers.tpl,
# "nano.retentionSizing"); deploy/helm/nano/scripts/test_retention_sizing.py
# checks all three. plan.py adds a fixed 100 GiB for a dedicated ClickHouse
# node; a caller passes its own overhead instead (install.sh: Docker, Vector
# buffers and PostgreSQL on the shared disk; Helm: none, the PVC is
# ClickHouse's alone).
#
# Bash 3 compatible, integer arithmetic only (bytes fit in 64 bits).
set -euo pipefail

RETENTION_COMPRESSION_TENTHS=50   # plan.py COMPRESSION = 5.0 (measured 11.7-12x; planned 5:1)
RETENTION_MV_OVERHEAD_PCT=115     # plan.py CH_MV_OVERHEAD = 1.15
RETENTION_DISK_FILL_PCT=70        # plan.py CH_DISK_FILL = 0.70
RETENTION_MIN_DAYS=7              # below this the installer refuses unless forced

gb_per_day="" retention_days="" disk_bytes="" overhead_bytes=0

fail() {
    printf 'retention-sizing: %s\n' "$*" >&2
    exit 2
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --gb-per-day) gb_per_day="${2:-}"; shift 2 ;;
        --retention-days) retention_days="${2:-}"; shift 2 ;;
        --disk-bytes) disk_bytes="${2:-}"; shift 2 ;;
        --overhead-bytes) overhead_bytes="${2:-}"; shift 2 ;;
        --print-constants)
            printf 'RETENTION_COMPRESSION_TENTHS=%s\n' "$RETENTION_COMPRESSION_TENTHS"
            printf 'RETENTION_MV_OVERHEAD_PCT=%s\n' "$RETENTION_MV_OVERHEAD_PCT"
            printf 'RETENTION_DISK_FILL_PCT=%s\n' "$RETENTION_DISK_FILL_PCT"
            printf 'RETENTION_MIN_DAYS=%s\n' "$RETENTION_MIN_DAYS"
            exit 0
            ;;
        *) fail "unknown argument: $1" ;;
    esac
done

[[ "$gb_per_day" =~ ^[1-9][0-9]{0,6}$ ]] || fail "--gb-per-day must be a whole number >= 1"
[[ "$retention_days" =~ ^[1-9][0-9]{0,3}$ ]] || fail "--retention-days must be a whole number of days >= 1"
[[ "$disk_bytes" =~ ^[1-9][0-9]*$ ]] || fail "--disk-bytes must be a positive byte count"
[[ "$overhead_bytes" =~ ^[0-9]+$ ]] || fail "--overhead-bytes must be a byte count"

# Bytes one day takes on disk at the planned fill:
#   GB/day x 1e9 / COMPRESSION x MV_OVERHEAD / DISK_FILL
# = GB/day x 1e9 x (10 x MV_PCT) / (COMP_TENTHS x FILL_PCT)
# The ratio is reduced by its gcd and the inputs are capped so every product
# stays inside 64 bits (1 PB/day x 3650 days x the factor < 2^63).
(( gb_per_day <= 1000000 )) || fail "--gb-per-day above 1,000,000 (1 PB/day) is out of range"
(( retention_days <= 3650 )) || fail "--retention-days above 3650 is out of range"
factor_num=$(( 10 * RETENTION_MV_OVERHEAD_PCT ))
factor_den=$(( RETENTION_COMPRESSION_TENTHS * RETENTION_DISK_FILL_PCT ))
a=$factor_num b=$factor_den
while (( b > 0 )); do t=$(( a % b )); a=$b; b=$t; done
factor_num=$(( factor_num / a )) factor_den=$(( factor_den / a ))

usable=$(( disk_bytes - overhead_bytes ))
(( usable > 0 )) || usable=0
# supported = usable / (GB/day x 1e9 x factor), in whole days.
supported=$(( (usable * factor_den) / (gb_per_day * 1000000000 * factor_num) ))
# needed = days x GB/day x factor x 1e9, rounded up, plus the overhead.
# Whole quotient first, then the remainder, so q x 1e9 never overflows.
q=$(( retention_days * gb_per_day * factor_num ))
# shellcheck disable=SC2017
needed=$(( q / factor_den * 1000000000 + ((q % factor_den) * 1000000000 + factor_den - 1) / factor_den + overhead_bytes ))

if (( supported < RETENTION_MIN_DAYS )); then
    verdict=refuse
elif (( supported < retention_days )); then
    verdict=warn
else
    verdict=ok
fi

printf 'NANO_RETENTION_SUPPORTED_DAYS=%s\n' "$supported"
printf 'NANO_RETENTION_NEEDED_BYTES=%s\n' "$needed"
printf 'NANO_RETENTION_MIN_DAYS=%s\n' "$RETENTION_MIN_DAYS"
printf 'NANO_RETENTION_VERDICT=%s\n' "$verdict"
