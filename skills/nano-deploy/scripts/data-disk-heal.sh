#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# nano data-disk self-heal.
#
# After a hard reset, udev can miss the data disk's /dev/disk/by-uuid link. The
# fstab mount then times out, docker.service (RequiresMountsFor=/var/lib/docker)
# correctly stays stopped, and the host stays down until someone re-runs udev,
# mounts the disk and starts Docker by hand. This timer does that, only while
# the disk is unmounted, during the first 30 minutes after boot.
#
#   scp data-disk-heal.sh HOST:/tmp/ && ssh HOST 'sudo sh /tmp/data-disk-heal.sh install'   # once per host
#   sudo sh data-disk-heal.sh heal      [/var/lib/docker]   # what the timer runs
#   sudo sh data-disk-heal.sh uninstall                     # remove the timer
#   sh data-disk-heal.sh units          [/var/lib/docker]   # print the units only
#
# `heal` never formats anything and never mounts a disk fstab does not name. It
# mounts through the systemd mount unit (so systemd-fsck and the unit ordering
# still apply, never mount(8) directly), does nothing while the disk's
# systemd-fsck@ unit has failed (the filesystem needs a manual check), and
# starts Docker only after the mount unit is active.
#
# Doing disk maintenance within 30 minutes of boot (unmounting the disk on
# purpose)? Stop the timer first: sudo systemctl stop nano-data-disk-heal.timer
# (it starts again at the next boot).
set -u

ACTION=${1:-}
MOUNT=${2:-/var/lib/docker}
BIN=/usr/local/sbin/nano-data-disk-heal
UNIT_DIR=${NANO_HEAL_UNIT_DIR:-/etc/systemd/system}
HEAL_WINDOW_SECONDS=${NANO_HEAL_WINDOW_SECONDS:-1800}

case "$MOUNT" in
    /*) ;;
    *) echo "nano-data-disk-heal: mount point must be absolute: $MOUNT" >&2; exit 2 ;;
esac
case "$MOUNT" in
    *[!A-Za-z0-9/_.-]*) echo "nano-data-disk-heal: unsupported characters in $MOUNT" >&2; exit 2 ;;
esac

units() {
    # OnBootSec (120 s) is above the fstab x-systemd.device-timeout (90 s): the
    # first attempt runs after boot's own mount job has given up.
    cat <<EOF
# --- $UNIT_DIR/nano-data-disk-heal.service
[Unit]
Description=nano: mount the data disk $MOUNT and start Docker if boot missed it
After=local-fs.target
ConditionPathExists=$BIN

[Service]
Type=oneshot
ExecStart=$BIN heal $MOUNT

# --- $UNIT_DIR/nano-data-disk-heal.timer
[Unit]
Description=nano: retry the data disk mount after boot

[Timer]
OnBootSec=120s
OnUnitInactiveSec=30s
AccuracySec=5s

[Install]
WantedBy=timers.target
EOF
}

in_fstab() {
    awk -v m="$MOUNT" '$1 !~ /^#/ && $2 == m { found = 1 } END { exit !found }' /etc/fstab
}

heal() {
    if mountpoint -q "$MOUNT"; then
        exit 0
    fi
    if ! in_fstab; then
        echo "nano-data-disk-heal: $MOUNT is not in /etc/fstab; nothing to do"
        exit 0
    fi
    uptime_s=$(cut -d. -f1 /proc/uptime)
    if [ "$uptime_s" -gt "$HEAL_WINDOW_SECONDS" ]; then
        # Long after boot an unmounted disk is an operator decision or a
        # failed disk, not a boot race: report it, change nothing.
        echo "nano-data-disk-heal: $MOUNT is not mounted ${uptime_s}s after boot; not retrying (outside the boot window)"
        exit 0
    fi
    unit=$(systemd-escape -p --suffix=mount "$MOUNT")
    # A failed filesystem check is not a boot race: leave it to the operator.
    for dep in $(systemctl show -p Requires -p After --value "$unit" 2>/dev/null); do
        case "$dep" in
            systemd-fsck@*.service)
                if [ "$(systemctl show -p ActiveState --value "$dep" 2>/dev/null)" = failed ]; then
                    echo "nano-data-disk-heal: $dep failed: the filesystem needs a manual check (journalctl -u '$dep'); not mounting $MOUNT"
                    exit 0
                fi ;;
        esac
    done
    echo "nano-data-disk-heal: $MOUNT is not mounted; asking udev to re-scan block devices"
    udevadm trigger --subsystem-match=block --action=change || true
    udevadm settle --timeout=60 || true
    systemctl reset-failed "$unit" 2>/dev/null || true
    if ! systemctl start "$unit" || ! mountpoint -q "$MOUNT"; then
        # exit 0: the timer re-runs on OnUnitInactiveSec either way, and a
        # failed oneshot would only add noise to systemctl --failed.
        echo "nano-data-disk-heal: $unit did not mount $MOUNT; retrying in 30 s (journalctl -u '$unit')" >&2
        exit 0
    fi
    echo "nano-data-disk-heal: mounted $MOUNT ($unit); starting Docker"
    systemctl reset-failed containerd.service docker.socket docker.service 2>/dev/null || true
    systemctl start containerd.service docker.socket docker.service
}

install_units() {
    [ "$(id -u)" = 0 ] || { echo "nano-data-disk-heal: install needs root (sudo)" >&2; exit 2; }
    in_fstab || { echo "nano-data-disk-heal: $MOUNT has no /etc/fstab entry; add the data disk first" >&2; exit 2; }
    # Installs a copy of THIS file: run it from a file (scp it over first),
    # not from stdin (`sh -s`), where $0 is the shell.
    if [ ! -f "$0" ] || ! grep -q 'nano-data-disk-heal' "$0"; then
        echo "nano-data-disk-heal: run install from a copy of this file, e.g. scp data-disk-heal.sh HOST:/tmp/ && ssh HOST 'sudo sh /tmp/data-disk-heal.sh install'" >&2
        exit 2
    fi
    install -m 0755 "$0" "$BIN"
    units | awk -v dir="$UNIT_DIR" '
        /^# --- / { file = $3; next }
        file { print > file }'
    systemctl daemon-reload
    systemctl enable --now nano-data-disk-heal.timer
    echo "nano-data-disk-heal: installed; check with: systemctl list-timers nano-data-disk-heal.timer"
}

uninstall_units() {
    [ "$(id -u)" = 0 ] || { echo "nano-data-disk-heal: uninstall needs root (sudo)" >&2; exit 2; }
    systemctl disable --now nano-data-disk-heal.timer 2>/dev/null || true
    rm -f "$UNIT_DIR/nano-data-disk-heal.timer" "$UNIT_DIR/nano-data-disk-heal.service" "$BIN"
    systemctl daemon-reload
    echo "nano-data-disk-heal: removed (the fstab entry and the docker/containerd drop-ins are unchanged)"
}

case "$ACTION" in
    heal) heal ;;
    install) install_units ;;
    uninstall) uninstall_units ;;
    units) units ;;
    *) echo "usage: $0 install|uninstall|heal|units [MOUNT_POINT]" >&2; exit 2 ;;
esac
