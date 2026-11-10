#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Create the first-admin credential file ON THE APP HOST without the password
# ever leaving the host or appearing on a command line.
#
#   ssh USER@APP_HOST "bash -s -- --email admin@example.com --name 'Site Admin'" < admin-credentials.sh
#   (ssh joins its arguments into one remote command line, so quote a name that
#   contains spaces INSIDE the double-quoted remote command, as shown.)
#
# Writes ~/.nano-admin-credentials (mode 0600) with NANO_ADMIN_EMAIL,
# NANO_ADMIN_NAME and a generated NANO_ADMIN_PASSWORD that meets the installer
# policy (12+ chars, upper, lower, digit, special). If the file exists it is
# kept unchanged (idempotent). Prints only the path and the email.
set -euo pipefail
umask 077
email="" name="Admin" file="$HOME/.nano-admin-credentials"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --email) email="$2"; shift 2 ;;
        --name) name="$2"; shift 2 ;;
        --file) file="$2"; shift 2 ;;
        --) shift ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done
if [[ -f "$file" ]]; then
    chmod 600 "$file"
    printf 'kept existing %s (email=%s)\n' "$file" "$(awk -F= '$1=="NANO_ADMIN_EMAIL"{print $2}' "$file")"
    exit 0
fi
[[ -n "$email" ]] || { echo "--email is required" >&2; exit 2; }
[[ "$email" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$ ]] || { echo "invalid email" >&2; exit 2; }
[[ "$name" =~ ^[A-Za-z0-9\ ._-]{1,64}$ ]] || { echo "name: letters, digits, spaces, dot, underscore, hyphen only" >&2; exit 2; }
pw="Nn1!$(openssl rand -base64 33 | tr -dc 'A-Za-z0-9' | cut -c1-24)"
tmp=$(mktemp "$file.XXXXXX")
printf "NANO_ADMIN_EMAIL=%s\nNANO_ADMIN_NAME='%s'\nNANO_ADMIN_PASSWORD=%s\n" "$email" "$name" "$pw" > "$tmp"
chmod 600 "$tmp"
mv "$tmp" "$file"
unset pw
printf 'wrote %s (mode 0600, email=%s); the password stays on this host\n' "$file" "$email"
