#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Merge the app.nano.rs enrollment values into a prepared nano .env ON THE HOST,
# without printing them.
#
#   scp -p enrollment.env USER@HOST:.nano-enrollment.env        # operator's 0600 file
#   ssh USER@HOST 'bash -s -- --env "$HOME/nano/.env" --from "$HOME/.nano-enrollment.env"' < apply-enrollment.sh
#
# Keep the arguments INSIDE the single quotes: an unquoted ~ or $HOME expands
# on the workstation, not on the host. Without --env/--from the defaults are
# $HOME/nano/.env and $HOME/.nano-enrollment.env on the host, and a literal
# leading "~/" is expanded on the host.
#
# Accepts only LICENSE_URL, LICENSE_TOKEN and NANO_DEPLOYMENT_ID. Replaces
# existing values for those keys, keeps every other line, keeps the .env owner
# and mode 0600, then deletes the uploaded copy (use --keep-source to keep it).
# The uploaded copy is deleted on failure too, so a license token never stays
# behind on the host; upload it again after fixing the cause.
# Idempotent. Prints key names and a status, never values.
set -euo pipefail
umask 077
default_src="$HOME/.nano-enrollment.env"
env_file="$HOME/nano/.env" src="$default_src" keep=0 tmp=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --env) env_file="$2"; shift 2 ;;
        --from) src="$2"; shift 2 ;;
        --keep-source) keep=1; shift ;;
        --) shift ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done
# A literal "~/" (quoted on the workstation) means this host's home.
[[ "$env_file" == "~/"* ]] && env_file="$HOME/${env_file#\~/}"
[[ "$src" == "~/"* ]] && src="$HOME/${src#\~/}"

# On any failure, remove the uploaded token file (and a half-written .env).
cleanup() {
    local rc=$?
    [[ -n "$tmp" ]] && rm -f -- "$tmp"
    if (( rc != 0 && ! keep )); then
        for f in "$src" "$default_src"; do
            if [[ -f "$f" && ! -L "$f" ]]; then
                rm -f -- "$f" && echo "removed the uploaded enrollment file $f; upload it again after fixing the error" >&2
            fi
        done
    fi
}
trap cleanup EXIT

if [[ ! -f "$src" ]]; then
    case "$src" in
        /Users/*|/home/*|/root/*) [[ "$src" == "$HOME"/* ]] || hint=" (that path looks like another machine's home: keep --from inside the ssh command's single quotes so it expands on this host)" ;;
    esac
    echo "enrollment file not found: ${src}${hint:-}" >&2
    exit 2
fi
[[ -f "$env_file" && ! -L "$env_file" ]] || { echo "$env_file is missing or a symlink: run the prepare step first" >&2; exit 2; }
[[ "$(stat -c '%u' "$env_file")" == "$(id -u)" ]] || { echo "$env_file is not owned by $(id -un)" >&2; exit 2; }

declare -A want=()
while IFS= read -r line || [[ -n "$line" ]]; do
    line=${line%$'\r'}
    [[ -z "$line" || "$line" == \#* ]] && continue
    key=${line%%=*}; val=${line#*=}
    case "$key" in
        LICENSE_URL|LICENSE_TOKEN|NANO_DEPLOYMENT_ID) ;;
        *) echo "refusing unexpected key in enrollment file: $key" >&2; exit 2 ;;
    esac
    val=${val#\"}; val=${val%\"}; val=${val#\'}; val=${val%\'}
    [[ -n "$val" && "$val" != *[[:space:]]* ]] || { echo "empty or whitespace value for $key" >&2; exit 2; }
    # Compose interpolates $ in .env values; refuse anything outside a URL/token-safe set.
    [[ "$val" =~ ^[A-Za-z0-9._~:/?\&=+%@-]+$ ]] || { echo "unexpected characters in $key (value not shown)" >&2; exit 2; }
    want[$key]=$val
done < "$src"
for k in LICENSE_URL LICENSE_TOKEN NANO_DEPLOYMENT_ID; do
    [[ -n "${want[$k]:-}" ]] || { echo "enrollment file lacks $k" >&2; exit 2; }
done
[[ "${want[LICENSE_URL]}" == https://* ]] || { echo "LICENSE_URL must be https://" >&2; exit 2; }

tmp=$(mktemp "$(dirname "$env_file")/.env.enroll.XXXXXX")
grep -vE '^(LICENSE_URL|LICENSE_TOKEN|NANO_DEPLOYMENT_ID)=' "$env_file" > "$tmp" || true
for k in LICENSE_URL LICENSE_TOKEN NANO_DEPLOYMENT_ID; do printf '%s=%s\n' "$k" "${want[$k]}" >> "$tmp"; done
chmod 600 "$tmp"
mv "$tmp" "$env_file"
(( keep )) || rm -f -- "$src"
printf 'applied LICENSE_URL, LICENSE_TOKEN, NANO_DEPLOYMENT_ID to %s (mode %s)%s\n' \
    "$env_file" "$(stat -c '%a' "$env_file")" "$( (( keep )) && echo '' || echo '; removed the uploaded copy')"
