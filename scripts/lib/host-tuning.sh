# shellcheck shell=bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Host settings check for ClickHouse (NAN-5910). Warn-only: install.sh sources
# this file and runs nano_host_tuning_check after the host size gate. It never
# refuses an install and never changes the host. Each warning says what is
# wrong, why it matters, and how to fix it, and points to
# docs/getting-started/prepare-the-host.md.
#
# Checked on a Linux host that runs ClickHouse (the single node, or a
# role-split host with the clickhouse role), following ClickHouse's
# "Usage recommendations" page:
#   * transparent huge pages set to `always`
#     (/sys/kernel/mm/transparent_hugepage/enabled shows [always]);
#   * memory overcommit turned off (/proc/sys/vm/overcommit_memory is 2);
#   * a CPU frequency governor other than `performance`
#     (/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; most cloud VMs
#     have no cpufreq at all, and then there is nothing to check);
#   * ClickHouse's data (<Docker's data directory>/volumes, which may be its
#     own mount) on a filesystem other than ext4 or XFS (read from
#     /proc/mounts: the longest mount point that holds the path), with a
#     stronger note for network filesystems. When the data directory is not
#     known, the summary says the filesystem was not checked.
#
# Test seam (only with NANO_INSTALLER_TEST_MODE=1): NANO_HOST_PROC_DIR and
# NANO_HOST_SYS_DIR replace /proc and /sys; with NANO_HOST_PROC_DIR set the
# Linux-only gate is skipped.
# NANO_SKIP_HOST_TUNING_CHECK=1 turns the whole check off.
#
# No awk interval expressions or gawk-only functions (Debian 12 mawk).
# The caller provides ok/warn (install.sh's).

NANO_HOST_TUNING_DOC="docs/getting-started/prepare-the-host.md"
# Marker line nano_host_tuning_findings prints when it could check the data
# filesystem (not a warning; nano_host_tuning_check consumes it).
NANO_HOST_TUNING_FS_CHECKED="#nano-host-tuning:filesystem-checked"

# Non-empty when a test replaced /proc (the Linux-only gate is then skipped).
nano_host_tuning_test_root() {
    [[ "${NANO_INSTALLER_TEST_MODE:-0}" == "1" && -n "${NANO_HOST_PROC_DIR:-}" ]] && printf '%s\n' "$NANO_HOST_PROC_DIR"
    return 0
}

nano_host_tuning_proc() {
    if [[ "${NANO_INSTALLER_TEST_MODE:-0}" == "1" && -n "${NANO_HOST_PROC_DIR:-}" ]]; then
        printf '%s\n' "$NANO_HOST_PROC_DIR"
    else
        printf '/proc\n'
    fi
}

nano_host_tuning_sys() {
    if [[ "${NANO_INSTALLER_TEST_MODE:-0}" == "1" && -n "${NANO_HOST_SYS_DIR:-}" ]]; then
        printf '%s\n' "$NANO_HOST_SYS_DIR"
    else
        printf '/sys\n'
    fi
}

# The filesystem type and mount point ("<type> <mountpoint>") of the longest
# mount in MOUNTS ($2, /proc/mounts format) that holds PATH ($1), or nothing.
# A later line for the same mount point wins (it is the one mounted on top).
# /proc/mounts writes a space in a mount point as \040; a path with one is
# compared in that form.
nano_host_tuning_fs_of() {
    local path=$1 mounts=$2
    [[ -r "$mounts" ]] || return 0
    path=${path// /\\040}
    # ENVIRON, not -v: awk would turn the \040 back into a space.
    NANO_HT_PATH="$path" awk '
        BEGIN { p = ENVIRON["NANO_HT_PATH"] }
        NF >= 3 {
            m = $2
            if (m != "/") sub(/\/+$/, "", m)
            if (p == m || m == "/" || index(p, m "/") == 1) {
                if (length(m) >= best_len) { best_len = length(m); best = $3 " " m }
            }
        }
        END { if (best != "") printf "%s\n", best }
    ' "$mounts"
}

# One plain warning per problem on stdout (nothing when the host is fine).
# $1 = the directory that holds ClickHouse's data (Docker's data root), or "".
nano_host_tuning_findings() {
    local data_dir="${1:-}" proc sys value governors="" gov file found fs type mount real
    proc=$(nano_host_tuning_proc)
    sys=$(nano_host_tuning_sys)

    file="$sys/kernel/mm/transparent_hugepage/enabled"
    if [[ -r "$file" ]]; then
        value=$(cat "$file" 2>/dev/null || true)
        if [[ "$value" == *"[always]"* ]]; then
            printf '%s\n' "Transparent huge pages are set to \"always\". ClickHouse can use much more memory and slow down this way. Set them to \"madvise\": echo madvise | sudo tee $file, and keep it after a reboot with transparent_hugepage=madvise on the kernel command line. See $NANO_HOST_TUNING_DOC."
        fi
    fi

    file="$proc/sys/vm/overcommit_memory"
    if [[ -r "$file" ]]; then
        value=$(tr -d '[:space:]' <"$file" 2>/dev/null || true)
        if [[ "$value" == 2 ]]; then
            printf '%s\n' "Memory overcommit is turned off (vm.overcommit_memory = 2). ClickHouse can then fail to start queries even when memory is free. Set it to 0 (the Linux default): sudo sysctl -w vm.overcommit_memory=0, and add vm.overcommit_memory = 0 to a file in /etc/sysctl.d/ to keep it. See $NANO_HOST_TUNING_DOC."
        fi
    fi

    found=0
    for file in "$sys"/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_governor; do
        [[ -r "$file" ]] || continue
        found=1
        gov=$(tr -d '[:space:]' <"$file" 2>/dev/null || true)
        [[ -n "$gov" && "$gov" != performance && " $governors " != *" $gov "* ]] && governors="${governors:+$governors }$gov"
    done
    if (( found )) && [[ -n "$governors" ]]; then
        printf '%s\n' "The CPU frequency governor is \"${governors// /\", \"}\", not \"performance\". The CPU then slows down between bursts, which makes searches and detections slower. Set it to performance (for example: sudo cpupower frequency-set -g performance) and keep it after a reboot. See $NANO_HOST_TUNING_DOC."
    fi

    # ClickHouse's named volume lives under <DockerRootDir>/volumes, which may
    # be its own mount; the longest-mount match falls back to the data root
    # (or /) when it is not.
    if [[ -n "$data_dir" ]]; then
        # Resolve <root>/volumes itself first, so a symlink at either level
        # (the root, or volumes -> /mnt/data/docker-volumes) is followed; fall
        # back to resolving the root when this user cannot traverse it.
        real=$(readlink -f "${data_dir%/}/volumes" 2>/dev/null || true)
        if [[ -z "$real" ]]; then
            real=$(readlink -f "$data_dir" 2>/dev/null || true)
            [[ -n "$real" ]] || real=$( (cd "$data_dir" 2>/dev/null && pwd -P) || true)
            [[ -n "$real" ]] || real=$data_dir
            real="${real%/}/volumes"
        fi
        fs=$(nano_host_tuning_fs_of "$real" "$proc/mounts")
        if [[ -n "$fs" ]]; then
            printf '%s\n' "$NANO_HOST_TUNING_FS_CHECKED"
            read -r type mount <<<"$fs"
            mount=${mount//\\040/ }
            case "$type" in
                ext4|xfs) ;;
                nfs|nfs4|cifs|smb3|smbfs|ceph|glusterfs|9p|virtiofs|fuse|fuse.*)
                    printf '%s\n' "ClickHouse data ($real) is on a network or shared filesystem ($type, mounted at $mount). ClickHouse needs a local disk: on network storage it is slow and can lose or damage data. Move Docker's data directory to a local ext4 or XFS disk. See $NANO_HOST_TUNING_DOC." ;;
                *)
                    printf '%s\n' "ClickHouse data ($real) is on a $type filesystem (mounted at $mount). ClickHouse is tested on ext4 and XFS; other filesystems can be slower or behave differently under load. Use a local ext4 or XFS disk if you can. See $NANO_HOST_TUNING_DOC." ;;
            esac
        fi
    fi
}

# install.sh entry point. $1 = this host's roles ("" = the single node, which
# runs ClickHouse); $2 = Docker's data directory ("" = not known).
nano_host_tuning_check() {
    local roles="${1:-}" data_dir="${2:-}" finding count=0 fs_checked=0
    case "$(printf '%s' "${NANO_SKIP_HOST_TUNING_CHECK:-0}" | tr '[:upper:]' '[:lower:]')" in
        1|true|yes|on) return 0 ;;
    esac
    if [[ -n "$roles" && ",$roles," != *",clickhouse,"* ]]; then
        return 0
    fi
    if [[ -z "$(nano_host_tuning_test_root)" && "$(uname -s 2>/dev/null)" != Linux ]]; then
        return 0
    fi
    while IFS= read -r finding; do
        [[ -n "$finding" ]] || continue
        if [[ "$finding" == "$NANO_HOST_TUNING_FS_CHECKED" ]]; then
            fs_checked=1
            continue
        fi
        warn "$finding"
        count=$((count + 1))
    done < <(nano_host_tuning_findings "$data_dir")
    if (( count == 0 && fs_checked )); then
        ok "Host settings for ClickHouse look right (huge pages, overcommit, CPU governor, data filesystem)"
    elif (( count == 0 )); then
        ok "Host settings for ClickHouse look right (huge pages, overcommit, CPU governor). The data filesystem was not checked (Docker's data directory, or its mount, was not found). See $NANO_HOST_TUNING_DOC."
    else
        warn "The installer continues. The host settings above are not required, but ClickHouse runs better with them fixed."
    fi
}
