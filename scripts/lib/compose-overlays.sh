# shellcheck shell=bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# NAN-5968: the one reader of NANO_COMPOSE_OVERLAYS, the extra Compose files a
# single-host install runs on top of docker-compose.opensource.yml (TLS, the
# Agent Lane gate, metrics). Sourced by scripts/nano (init_context, and with it
# restart, backup and restore; the restore paths) and by
# scripts/lib/vector-native-pki.sh (`scripts/nano vector-client-cert`, which
# runs before scripts/nano's init_context exists). It needs only bash and awk,
# and defines functions only.
#
#   nano_overlay_value ENV_FILE
#       The NANO_COMPOSE_OVERLAYS value, read like Compose's --env-file and
#       install.sh: the LAST line wins, a trailing CR is dropped, and one
#       matching pair of outer quotes is removed. Prints nothing when the key
#       (or the file) is absent; fails (non-zero) when the file exists but
#       cannot be read, or awk cannot run.
#   nano_overlay_name_ok NAME
#       A plain compose file name: [A-Za-z0-9][A-Za-z0-9._-]*.yml or .yaml.
#   nano_overlay_args INSTALL_DIR [defer-missing]
#       Checks every listed overlay in order, each one first for its name, then
#       for a regular file in INSTALL_DIR that is not a symbolic link, and on
#       success sets NANO_OVERLAY_NAMES (every listed name), NANO_OVERLAY_ARGS
#       (-f INSTALL_DIR/NAME for each file present) and NANO_OVERLAY_DEFERRED.
#       With defer-missing (restore only), a name that does not exist at all is
#       put in NANO_OVERLAY_DEFERRED instead of refused; a link never is.
#       On the first bad overlay it sets NANO_OVERLAY_ERROR to the refusal
#       (the text scripts/nano has always printed) and returns 1.

# shellcheck disable=SC2034  # read by the scripts that source this file
NANO_OVERLAY_NAMES=()
NANO_OVERLAY_ARGS=()
NANO_OVERLAY_DEFERRED=()
NANO_OVERLAY_ERROR=""

nano_overlay_value() {
    [[ -e "$1" || -L "$1" ]] || return 0
    [[ -f "$1" && -r "$1" ]] || return 1
    awk -v k=NANO_COMPOSE_OVERLAYS '
        index($0, k "=") == 1 { v = substr($0, length(k) + 2); seen = 1 }
        END {
            if (!seen) exit
            sub(/\r+$/, "", v)
            q = substr(v, 1, 1)
            if (length(v) >= 2 && (q == "\"" || q == "\047") && substr(v, length(v), 1) == q)
                v = substr(v, 2, length(v) - 2)
            print v
        }' "$1"
}

nano_overlay_name_ok() {
    [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*\.ya?ml$ ]]
}

nano_overlay_args() {
    local dir="$1" mode="${2:-}" overlay value
    NANO_OVERLAY_NAMES=() NANO_OVERLAY_ARGS=() NANO_OVERLAY_DEFERRED=() NANO_OVERLAY_ERROR=""
    # Fail closed: a .env that cannot be read (or no awk) never means "no overlays".
    if ! value="$(nano_overlay_value "$dir/.env")"; then
        NANO_OVERLAY_ERROR="cannot read NANO_COMPOSE_OVERLAYS from $dir/.env"
        return 1
    fi
    IFS=$' \t\n' read -r -a NANO_OVERLAY_NAMES <<< "$value"
    for overlay in ${NANO_OVERLAY_NAMES[@]+"${NANO_OVERLAY_NAMES[@]}"}; do
        if ! nano_overlay_name_ok "$overlay"; then
            NANO_OVERLAY_ERROR="NANO_COMPOSE_OVERLAYS contains an invalid file name"
            return 1
        fi
        if [[ "$mode" == defer-missing && ! -e "$dir/$overlay" && ! -L "$dir/$overlay" ]]; then
            NANO_OVERLAY_DEFERRED+=("$overlay")
            continue
        fi
        if [[ ! -f "$dir/$overlay" || -L "$dir/$overlay" ]]; then
            # shellcheck disable=SC2034  # read by the scripts that source this file
            NANO_OVERLAY_ERROR="NANO_COMPOSE_OVERLAYS file is missing or symbolic: $overlay"
            return 1
        fi
        NANO_OVERLAY_ARGS+=(-f "$dir/$overlay")
    done
}
