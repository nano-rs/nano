# shellcheck shell=bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Data-disk guard (NAN-5251). A host whose Docker data lives on a separate disk
# (an /etc/fstab entry at or above DockerRootDir, usually /var/lib/docker) must
# never run nano while that disk is unmounted: Docker then starts on an empty
# directory of the root disk, reports "active", and every container, volume and
# replica on the host is silently gone. A `nofail` mount whose fsck or device
# wait fails leaves exactly that state after a reboot.
#
# The installer refuses to continue while the disk is unmounted and warns when
# docker.service does not depend on the mount (RequiresMountsFor=), which is
# what stops Docker from starting without it at boot.
#
# Overrides: NANO_DATA_MOUNT names the mount explicitly (when fstab does not, for
# example a systemd .mount unit), and NANO_DATA_MOUNT=none turns the guard off
# (storage the host manages some other way); NANO_FSTAB_PATH is for tests only.
#
# Only a mount that the boot can skip (`nofail` or `noauto`) needs the
# docker.service dependency: any other fstab mount (a plain /var partition, say)
# is required by local-fs.target, and the boot stops rather than starting Docker
# without it.

# Print the fstab mountpoint that holds PATH (the longest one, never "/").
nano_data_mount_for() {
    nano_data_mount_entry "$1" "$2" | awk '{ print $1 }'
}

# Print "<mountpoint> <options>" for the fstab entry that holds PATH.
nano_data_mount_entry() {
    local path=${1%/} fstab=$2
    [[ -r "$fstab" ]] || return 0
    awk -v p="$path" '
        $1 !~ /^#/ && NF >= 3 && $2 ~ /^\// && $2 != "/" && $3 != "swap" {
            m = $2
            sub(/\/+$/, "", m)
            if ((p == m || index(p, m "/") == 1) && length(m) > length(best)) {
                best = m
                options = (NF >= 4 ? $4 : "defaults")
            }
        }
        END { if (best != "") print best, options }' "$fstab"
}

# 0 when PATH is a mounted filesystem's root. Tests replace this function.
nano_is_mountpoint() {
    if command -v mountpoint >/dev/null 2>&1; then
        mountpoint -q "$1"
    elif command -v findmnt >/dev/null 2>&1; then
        findmnt --mountpoint "$1" >/dev/null 2>&1
    else
        # Unknown: never block an install on a missing util-linux tool.
        return 0
    fi
}

# The mount docker.service must wait for. Tests replace this function.
nano_docker_unit_mounts() {
    command -v systemctl >/dev/null 2>&1 || return 1
    systemctl show docker.service -p RequiresMountsFor --value 2>/dev/null
}

# nano_check_data_mount DOCKER_ROOT_DIR
#   prints "none", "mounted <mount> <dependency: yes|no|unknown>" or
#   "unmounted <mount>"; returns 1 only for "unmounted".
nano_check_data_mount() {
    local root=$1 mount entry options="nofail" dependency=unknown units unit
    if [[ "${NANO_DATA_MOUNT:-}" == none ]]; then
        printf 'none\n'
        return 0
    fi
    mount=${NANO_DATA_MOUNT:-}
    mount=${mount%/}
    if [[ -z "$mount" ]]; then
        entry=$(nano_data_mount_entry "$root" "${NANO_FSTAB_PATH:-/etc/fstab}")
        mount=${entry%% *}
        options=${entry#* }
    fi
    if [[ -z "$mount" ]]; then
        printf 'none\n'
        return 0
    fi
    if ! nano_is_mountpoint "$mount"; then
        printf 'unmounted %s\n' "$mount"
        return 1
    fi
    if [[ ",$options," != *,nofail,* && ",$options," != *,noauto,* ]]; then
        # Required by local-fs.target: Docker never starts without it.
        printf 'mounted %s yes\n' "$mount"
        return 0
    fi
    if units=$(nano_docker_unit_mounts); then
        dependency=no
        for unit in $units; do
            unit=${unit%/}
            # RequiresMountsFor=P pulls in every mount P needs: the data
            # mount itself or any path below it.
            [[ "$unit" == "$mount" || "$unit" == "$mount"/* ]] && dependency=yes
        done
    fi
    printf 'mounted %s %s\n' "$mount" "$dependency"
}

# The systemd drop-in that makes Docker wait for (and refuse to start without)
# the data disk. RequiresMountsFor= implies Requires= and After= on the mount
# unit, so systemd mounts the disk first even when fstab says `nofail`.
nano_docker_mount_dropin() {
    printf '[Unit]\nRequiresMountsFor=%s\n' "$1"
}

# NAN-5269: the data-disk self-heal timer (scripts/lib/data-disk-heal.sh, the
# same file the nano-deploy skill ships). Only a `nofail`/`noauto` fstab mount
# can be skipped at boot, so only such a disk needs the timer.
#   nano_data_mount_skippable MOUNT  -> 0 when fstab marks MOUNT nofail/noauto
nano_data_mount_skippable() {
    local mount=${1%/}
    awk -v m="$mount" '
        $1 !~ /^#/ && NF >= 4 {
            p = $2
            sub(/\/+$/, "", p)
            if (p == m && ("," $4 ",") ~ /,(nofail|noauto),/) found = 1
        }
        END { exit !found }' "${NANO_FSTAB_PATH:-/etc/fstab}" 2>/dev/null
}

# 0 when the timer is enabled and the installed copy is this release's script.
# Tests replace this function.
nano_data_disk_heal_current() {
    local script=$1 installed=${NANO_HEAL_BIN:-/usr/local/sbin/nano-data-disk-heal}
    command -v systemctl >/dev/null 2>&1 || return 1
    [[ -f "$installed" ]] && cmp -s "$script" "$installed" \
        && systemctl is-enabled --quiet nano-data-disk-heal.timer 2>/dev/null
}

# 0 when sudo works without a password prompt. Tests replace this function.
nano_can_sudo() {
    command -v sudo >/dev/null 2>&1 && sudo -n true </dev/null >/dev/null 2>&1
}

# nano_ensure_data_disk_heal MOUNT SCRIPT
#   prints one of: skipped <why> | current | installed | manual <command>
#   Idempotent: an up-to-date, enabled timer is left alone. Installing needs
#   root; install.sh itself runs without sudo, so this uses `sudo -n` only
#   where that never prompts, and otherwise prints the one command to run.
#   NANO_DATA_DISK_HEAL=off skips it. Remove it with
#   `sudo sh SCRIPT uninstall`.
nano_ensure_data_disk_heal() {
    local mount=${1%/} script=$2
    case "${NANO_DATA_DISK_HEAL:-auto}" in
        off|false|0|no) printf 'skipped NANO_DATA_DISK_HEAL=%s\n' "$NANO_DATA_DISK_HEAL"; return 0 ;;
    esac
    if ! command -v systemctl >/dev/null 2>&1; then
        printf 'skipped no systemd\n'; return 0
    fi
    if ! nano_data_mount_skippable "$mount"; then
        printf 'skipped %s is not a nofail fstab mount\n' "$mount"; return 0
    fi
    if nano_data_disk_heal_current "$script"; then
        printf 'current\n'; return 0
    fi
    if nano_can_sudo && sudo -n sh "$script" install "$mount" </dev/null >/dev/null 2>&1 \
        && nano_data_disk_heal_current "$script"; then
        printf 'installed\n'; return 0
    fi
    printf 'manual sudo sh %s install %s\n' "$script" "$mount"
}
