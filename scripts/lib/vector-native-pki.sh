#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# nano Vector-native (:6000) mutual-TLS PKI (NAN-5515).
#
# The Vector-native listener has no token auth, so it is always TLS with a
# REQUIRED client certificate: Vector's `vector` source with tls.enabled and
# tls.verify_certificate = true refuses every connection whose client
# certificate does not chain to a certificate in tls.ca_file. There is no
# plaintext mode.
#
# Trust model (two separate trust paths, so neither side can act as the other):
#   * LISTENER CA: signs the listener (server) certificate. Senders verify nano
#     with it (their ca.crt). It is never rotated by a revocation. Single host:
#     server-ca.key/.crt here. Role split: the cluster's private TLS CA (the
#     ingest hosts' listener certificate is the staged cluster certificate, so
#     no CA key ever reaches an ingest host). Helm: the chart's listener CA.
#   * CLIENT ANCHORS: one small CA per sender (CA:TRUE, pathlen 0, EKU
#     clientAuth), which signs only that sender's certificate. The listener's
#     tls.ca_file is the bundle of every active sender's anchor (plus a locked
#     anchor whose key never existed on disk, so the bundle is never empty).
#     Vector loads every certificate of a multi-certificate ca_file. The
#     listener CA is never in that bundle, so a listener certificate can never
#     be used as a sender, and an anchor is never in a sender's ca.crt, so a
#     sender anchor can never act as a listener.
#
# Revocation: Vector 0.61 has no CRL/OCSP option on its sources
# (`tls.crl_file` is refused), so a sender is revoked by removing its anchor
# from the bundle (and deleting the anchor key) and restarting Vector. Every
# other sender keeps working with the files it already has: zero blast radius.
#
# Files:
#   PKI dir (single host / role-split app host: <install>/.nano-pki/vector-native,
#   mode 0700; never mounted into a container, never in .env):
#     server-ca.key / server-ca.crt   listener CA (single host); role split and
#                                     Helm: server-ca.crt only (a copy)
#     locked-anchor.crt               bundle placeholder (its key was discarded)
#     client-ca.crt                   the anchor bundle (derived)
#     clients.tsv                     name, serial, notAfter, status, out dir, days
#     clients/NAME/anchor.key/.crt    the sender's anchor (key 0600)
#     clients/NAME/client.csr/.crt    the sender's request (public) and certificate
#   TLS dir (<install>/config/vector-native, mounted read-only at
#   /etc/nano/vector-native): server.crt, server.key (0600), client-ca.crt,
#   .sans. A role-split ingest host keeps only client-ca.crt here (its
#   listener certificate is the cluster's), built from the shared .env key
#   NANO_VECTOR_NATIVE_CLIENT_ANCHORS (public certificates, never keys).
#
# Commands (scripts/nano vector-client-cert is the operator-facing wrapper):
#   ensure --pki-dir P --tls-dir T [--base-url URL] [--san NAME|IP]... [--new-ca]
#       Single host: the listener CA (created once), the listener certificate
#       (re-issued when its SANs, the CA or its validity change) and the anchor
#       bundle. Refuses to mint a new CA where certificates were already issued
#       (restore the PKI from a backup, or pass --new-ca deliberately).
#       Prints `ca=<created|present> server=<issued|unchanged> anchors=<changed|unchanged>`.
#   ensure-ingest --tls-dir T --env-file F
#       Role-split ingest host: client-ca.crt from the shared .env.
#       Prints `anchors=<count> changed=<0|1>`.
#   issue NAME --pki-dir P [--out DIR] [--days N] [--csr FILE] [--address H[:P]]
#       [--server-ca FILE] [--server-name NAME] [--tls-dir T]
#   renew NAME --pki-dir P [--days N] [--csr FILE] [--out DIR]
#   revoke NAME --pki-dir P
#   list --pki-dir P
#   expiring --pki-dir P [--tls-dir T]      warnings for the next 30 days
#   anchors --pki-dir P                     the bundle's active anchors, base64
#   sans [--base-url URL] [--san NAME|IP]...
#   events-query --profile P   SQL: events taken on :6000 in the last 24 h
#   bundle NAME... --install-dir DIR [--address H[:P]] [--ensure]
#       One bundle per sender in DIR/vector-client-bundles/NAME (0600 files,
#       with vector-sink.toml). --ensure first creates the listener CA and
#       certificate, so it also runs on a 0.1.x checkout before the upgrade.
#
# Private keys are written with umask 077 and chmod 0600, only ever by openssl
# to a file path; no key material is printed or passed in argv.
set -euo pipefail
umask 077

PROG="vector-native-pki"
LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
CA_DAYS=3650
SERVER_DAYS=825
CLIENT_DAYS_DEFAULT=825
CLIENT_DAYS_MAX=3650
# Re-issue the listener certificate, and warn about a sender's, this close to expiry.
RENEW_SECONDS=$((30 * 24 * 3600))
NATIVE_PORT=6000
ANCHORS_KEY=NANO_VECTOR_NATIVE_CLIENT_ANCHORS

# Temporary directories (some hold private keys) are removed on every exit.
CLEANUP=()
cleanup_tmp() { ((${#CLEANUP[@]} == 0)) || rm -rf "${CLEANUP[@]}"; }
trap cleanup_tmp EXIT
tmpdir() { # tmpdir <template>: a new directory, registered for cleanup.
    local dir
    dir=$(mktemp -d "$1") || { printf '%s: could not create a temporary directory (%s)\n' "$PROG" "$1" >&2; exit 1; }
    CLEANUP+=("$dir")
    printf '%s\n' "$dir"
}

die() { printf '%s: %s\n' "$PROG" "$*" >&2; exit 1; }
usage_die() { printf '%s: %s\n' "$PROG" "$*" >&2; exit 2; }
note() { printf '%s\n' "$*" >&2; }

command -v openssl >/dev/null 2>&1 || die "openssl is required"

# One writer at a time per PKI directory.
lock_pki() { # lock_pki <pki_dir>
    command -v flock >/dev/null 2>&1 || return 0
    mkdir -p "$1"
    exec 8>>"$1/.lock"
    # BusyBox flock has no -w: wait without a bound there.
    flock -w 120 8 2>/dev/null || flock 8 || die "another vector-native PKI command is running on $1"
}

valid_name() { [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$ ]]; }

is_ipv4() {
    local IFS=. octet
    [[ "$1" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
    for octet in $1; do ((10#$octet <= 255)) || return 1; done
}
is_ipv6() {
    [[ "$1" == *:* && "$1" =~ ^[0-9A-Fa-f:.]+$ ]] || return 1
    if command -v python3 >/dev/null 2>&1; then
        python3 -I -c 'import ipaddress, sys; ipaddress.IPv6Address(sys.argv[1])' "$1" >/dev/null 2>&1
    else
        [[ "$1" =~ ^([0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}$ && "$1" != *:::* ]]
    fi
}
is_dns() { [[ "${#1}" -le 253 && "$1" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$ ]]; }

# san_entry <host or address>: prints DNS:x / IP:x; warns about anything else.
san_entry() {
    local value="${1#[}"
    value="${value%]}"
    [[ -n "$value" ]] || return 0
    case "$value" in 0.0.0.0 | :: | "*") return 0 ;; esac
    if is_ipv4 "$value" || is_ipv6 "$value"; then
        printf 'IP:%s\n' "$value"
    elif [[ "$value" != *:* ]] && is_dns "$value"; then
        printf 'DNS:%s\n' "$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')"
    else
        note "warning: ignoring '$value' for the Vector-native listener certificate (not a host name or IP address)"
    fi
}

# host_of_url <url or host[:port]>: the bare host.
host_of_url() {
    local host="$1"
    host="${host#*://}"
    host="${host%%/*}"
    host="${host##*@}"
    if [[ "$host" == \[* ]]; then
        host="${host%%]*}"
        host="${host#[}"
    elif [[ "$host" != *:*:* ]]; then
        host="${host%%:*}"
    fi
    printf '%s\n' "$host"
}

# The host's own addresses. NANO_VECTOR_NATIVE_HOST_ADDRESSES (comma or space
# separated) replaces detection. Container and bridge interfaces and temporary
# IPv6 privacy addresses are skipped, so the list is stable across reboots.
host_addresses() {
    if [[ -n "${NANO_VECTOR_NATIVE_HOST_ADDRESSES+set}" ]]; then
        local -a listed=()
        read -r -a listed <<< "${NANO_VECTOR_NATIVE_HOST_ADDRESSES//,/ }"
        ((${#listed[@]} == 0)) || printf '%s\n' "${listed[@]}"
        return 0
    fi
    if command -v ip >/dev/null 2>&1; then
        ip -o addr show scope global 2>/dev/null </dev/null | awk '
            $2 ~ /^(docker|br-|veth|cni|flannel|virbr|cali|vxlan|tun|kube|lxc|weave|cilium)/ { next }
            / temporary / || / deprecated / { next }
            { split($4, a, "/"); print a[1] }'
    elif command -v hostname >/dev/null 2>&1; then
        hostname -I 2>/dev/null </dev/null | tr ' ' '\n' || true
    fi
}

# compute_sans <base_url> <extra...>: the listener SANs, sorted and unique.
compute_sans() {
    local base_url="$1" value
    local -a configured=()
    local sans_env="${NANO_VECTOR_NATIVE_SANS:-}"
    shift
    read -r -a configured <<< "${sans_env//,/ }"
    {
        printf 'DNS:localhost\nIP:127.0.0.1\nIP:::1\n'
        if command -v hostname >/dev/null 2>&1; then
            san_entry "$(hostname 2>/dev/null </dev/null || true)"
        fi
        while read -r value; do san_entry "$value"; done < <(host_addresses)
        [[ -z "$base_url" ]] || san_entry "$(host_of_url "$base_url")"
        for value in "${configured[@]}"; do san_entry "$value"; done
        for value in "$@"; do san_entry "$value"; done
    } | LC_ALL=C sort -u
}

new_key() { # new_key <path>: an EC P-256 private key, mode 0600.
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" </dev/null >/dev/null 2>&1 \
        || die "openssl could not generate a key"
    chmod 600 "$1"
}

new_serial() { printf '0x%s' "$(openssl rand -hex 16 </dev/null)"; }

# make_ca <key> <crt> <common name> <server|anchor>: a self-signed CA.
# An anchor carries EKU clientAuth, so OpenSSL refuses anything it signs for a
# server role.
make_ca() {
    local key="$1" crt="$2" cn="$3" kind="$4" cfg
    cfg=$(mktemp "${crt}.cnf.XXXXXX") || die "could not create a temporary file next to $crt"
    {
        printf '[req]\ndistinguished_name = dn\n[dn]\n[v3_ca]\n'
        printf 'basicConstraints = critical,CA:TRUE,pathlen:0\n'
        printf 'keyUsage = critical,keyCertSign,cRLSign\n'
        printf 'subjectKeyIdentifier = hash\n'
        [[ "$kind" != anchor ]] || printf 'extendedKeyUsage = clientAuth\n'
    } > "$cfg"
    new_key "$key"
    if ! openssl req -x509 -new -config "$cfg" -extensions v3_ca -key "$key" \
        -subj "/O=nano/CN=$cn" -days "$CA_DAYS" -sha256 -set_serial "$(new_serial)" \
        -out "$crt" </dev/null >/dev/null 2>&1; then
        rm -f "$cfg"
        die "openssl could not create the CA certificate $crt"
    fi
    rm -f "$cfg"
    chmod 644 "$crt"
}

# sign <csr> <ca_crt> <ca_key> <out_crt> <days> <server|client> [san_csv]
sign() {
    local csr="$1" ca_crt="$2" ca_key="$3" out="$4" days="$5" kind="$6" sans="${7:-}" ext
    ext=$(mktemp "${out}.ext.XXXXXX") || die "could not create a temporary file next to $out"
    {
        printf 'basicConstraints = critical,CA:FALSE\n'
        printf 'keyUsage = critical,digitalSignature\n'
        if [[ "$kind" == server ]]; then
            printf 'extendedKeyUsage = serverAuth\nsubjectAltName = %s\n' "$sans"
        else
            printf 'extendedKeyUsage = clientAuth\n'
        fi
        printf 'subjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid,issuer\n'
    } > "$ext"
    if ! openssl x509 -req -in "$csr" -CA "$ca_crt" -CAkey "$ca_key" \
        -set_serial "$(new_serial)" -days "$days" -sha256 -extfile "$ext" \
        -out "$out" </dev/null >/dev/null 2>&1; then
        rm -f "$ext"
        die "openssl could not sign $(basename "$out")"
    fi
    rm -f "$ext"
    chmod 644 "$out"
}

# make_locked_anchor <crt>: a CA certificate whose key is deleted at once.
make_locked_anchor() {
    local dir
    dir=$(tmpdir "$(dirname "$1")/.locked.XXXXXX")
    make_ca "$dir/key" "$dir/crt" "nano vector-native locked anchor (no key exists)" anchor
    mv -f "$dir/crt" "$1"
    rm -rf "$dir"
}

cert_serial() { openssl x509 -noout -serial -in "$1" </dev/null | sed 's/^serial=//'; }
cert_not_after() { openssl x509 -noout -enddate -in "$1" </dev/null | sed 's/^notAfter=//'; }
valid_for() { openssl x509 -checkend "$2" -noout -in "$1" </dev/null >/dev/null 2>&1; } # valid_for <crt> <seconds>

prepare_pki_dir() {
    local dir="$1"
    mkdir -p "$dir"
    chmod 700 "$dir"
    mkdir -p "$dir/clients"
    chmod 700 "$dir/clients"
    [[ -e "$dir/clients.tsv" ]] || : > "$dir/clients.tsv"
    chmod 600 "$dir/clients.tsv"
    [[ -s "$dir/locked-anchor.crt" ]] || make_locked_anchor "$dir/locked-anchor.crt"
}

prepare_tls_dir() {
    mkdir -p "$1"
    # Bind-mounted read-only into Vector (root there); the key itself is 0600.
    chmod 755 "$1"
    rm -rf "$1"/.issue.* "$1"/.locked.*   # left by an interrupted run
}

index_field() { # index_field <pki> <name> <field number>
    awk -F '\t' -v n="$2" -v f="$3" '$1 == n { v = $f } END { if (v != "") print v }' "$1/clients.tsv"
}

index_put() { # index_put <pki> <name> <serial> <not_after> <status> <out_dir> <days>
    local pki="$1" tmp
    tmp=$(mktemp "$pki/.clients.XXXXXX") || die "could not update $pki/clients.tsv"
    awk -F '\t' -v n="$2" '$1 != n' "$pki/clients.tsv" > "$tmp"
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$2" "$3" "$4" "$5" "$6" "$7" >> "$tmp"
    chmod 600 "$tmp"
    mv -f "$tmp" "$pki/clients.tsv"
}

active_names() { awk -F '\t' '$4 == "active" { print $1 }' "$1/clients.tsv" | LC_ALL=C sort; }

# build_bundle <pki>: client-ca.crt = locked anchor + every active anchor.
# Returns 0 when the bundle changed.
build_bundle() {
    local pki="$1" tmp name
    tmp=$(mktemp "$pki/.bundle.XXXXXX") || die "could not write the anchor bundle"
    cat "$pki/locked-anchor.crt" > "$tmp"
    while read -r name; do
        [[ -z "$name" ]] || cat "$pki/clients/$name/anchor.crt" >> "$tmp"
    done < <(active_names "$pki")
    chmod 644 "$tmp"
    if [[ -f "$pki/client-ca.crt" ]] && cmp -s "$tmp" "$pki/client-ca.crt"; then
        rm -f "$tmp"
        return 1
    fi
    mv -f "$tmp" "$pki/client-ca.crt"
}

# install_bundle <bundle> <tls_dir>: copy into the listener dir; 0 when changed.
install_bundle() {
    local tmp
    if [[ -f "$2/client-ca.crt" ]] && cmp -s "$1" "$2/client-ca.crt"; then return 1; fi
    tmp=$(mktemp "$2/.client-ca.XXXXXX") || die "could not write $2/client-ca.crt"
    cat "$1" > "$tmp"
    chmod 644 "$tmp"
    mv -f "$tmp" "$2/client-ca.crt"
}

# --------------------------------------------------------- listener (single host)
server_ca_present() { [[ -s "$1/server-ca.key" && -s "$1/server-ca.crt" ]]; }

key_matches() { # key_matches <crt> <key>
    local cert_pub key_pub
    cert_pub=$(openssl x509 -noout -pubkey -in "$1" </dev/null 2>/dev/null) || return 1
    key_pub=$(openssl pkey -pubout -in "$2" </dev/null 2>/dev/null) || return 1
    [[ -n "$cert_pub" && "$cert_pub" == "$key_pub" ]]
}

server_current() { # server_current <pki> <tls> <sans>
    local pki="$1" tls="$2" sans="$3"
    [[ -s "$tls/server.crt" && -s "$tls/server.key" && -f "$tls/.sans" ]] || return 1
    [[ "$(cat "$tls/.sans")" == "$sans" ]] || return 1
    openssl verify -CAfile "$pki/server-ca.crt" "$tls/server.crt" </dev/null >/dev/null 2>&1 || return 1
    valid_for "$tls/server.crt" "$RENEW_SECONDS" || return 1
    key_matches "$tls/server.crt" "$tls/server.key"
}

issue_server() { # issue_server <pki> <tls> <sans>
    local pki="$1" tls="$2" sans="$3" tmp san_csv
    tmp=$(tmpdir "$tls/.issue.XXXXXX")
    san_csv=$(printf '%s\n' "$sans" | paste -sd, -)
    new_key "$tmp/server.key"
    openssl req -new -key "$tmp/server.key" -subj "/O=nano/CN=nano vector-native listener" \
        -out "$tmp/server.csr" </dev/null >/dev/null 2>&1 || die "openssl could not create the listener request"
    sign "$tmp/server.csr" "$pki/server-ca.crt" "$pki/server-ca.key" "$tmp/server.crt" "$SERVER_DAYS" server "$san_csv"
    printf '%s\n' "$sans" > "$tmp/.sans"
    chmod 644 "$tmp/.sans"
    # A crash between these moves leaves a mismatched pair, which
    # server_current detects (key_matches) and the next run re-issues.
    mv -f "$tmp/server.key" "$tls/server.key"
    mv -f "$tmp/server.crt" "$tls/server.crt"
    mv -f "$tmp/.sans" "$tls/.sans"
    rm -rf "$tmp"
}

cmd_sans() {
    local base_url="" extra=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --base-url) [[ $# -ge 2 ]] || usage_die "--base-url needs a value"; base_url="$2"; shift 2 ;;
            --san) [[ $# -ge 2 ]] || usage_die "--san needs a value"; extra+=("$2"); shift 2 ;;
            *) usage_die "sans: unknown argument: $1" ;;
        esac
    done
    compute_sans "$base_url" "${extra[@]}"
}

cmd_ensure() {
    local pki="" tls="" base_url="" new_ca=0 extra=() sans ca_state server_state anchors=unchanged
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --pki-dir) [[ $# -ge 2 ]] || usage_die "--pki-dir needs a value"; pki="$2"; shift 2 ;;
            --tls-dir) [[ $# -ge 2 ]] || usage_die "--tls-dir needs a value"; tls="$2"; shift 2 ;;
            --base-url) [[ $# -ge 2 ]] || usage_die "--base-url needs a value"; base_url="$2"; shift 2 ;;
            --san) [[ $# -ge 2 ]] || usage_die "--san needs a value"; extra+=("$2"); shift 2 ;;
            --new-ca) new_ca=1; shift ;;
            *) usage_die "ensure: unknown argument: $1" ;;
        esac
    done
    [[ -n "$pki" && -n "$tls" ]] || usage_die "ensure needs --pki-dir and --tls-dir"
    lock_pki "$pki"
    prepare_tls_dir "$tls"
    if server_ca_present "$pki"; then
        ca_state=present
    else
        # Never silently replace a CA that issued certificates (a restore that
        # missed .nano-pki, a deleted directory): every sender would be refused.
        if [[ "$new_ca" != 1 ]] && { [[ -s "$pki/clients.tsv" ]] || [[ -s "$tls/server.crt" ]]; }; then
            note "$PROG: the Vector-native listener CA is missing from $pki, but this install already issued"
            note "  certificates ($( [[ -s "$pki/clients.tsv" ]] && printf '%s' "$pki/clients.tsv" || printf '%s' "$tls/server.crt")). A new CA would refuse every existing sender."
            note "  Restore .nano-pki/vector-native from a backup (scripts/nano restore brings it back), or start"
            note "  over deliberately with NANO_VECTOR_NATIVE_NEW_CA=1 (re-issue every sender's certificate)."
            exit 3
        fi
        [[ "$new_ca" != 1 || ! -s "$pki/clients.tsv" ]] || mv -f "$pki/clients.tsv" "$pki/clients.tsv.before-new-ca"
        prepare_pki_dir "$pki"
        [[ ! -e "$pki/server-ca.key" && ! -e "$pki/server-ca.crt" ]] || rm -f "$pki/server-ca.key" "$pki/server-ca.crt"
        make_ca "$pki/server-ca.key" "$pki/server-ca.crt" "nano vector-native listener CA ($(date -u +%Y%m%d%H%M%S))" server
        ca_state=created
    fi
    prepare_pki_dir "$pki"
    sans=$(compute_sans "$base_url" "${extra[@]}")
    if server_current "$pki" "$tls" "$sans"; then
        server_state=unchanged
    else
        issue_server "$pki" "$tls" "$sans"
        server_state=issued
    fi
    build_bundle "$pki" || true
    install_bundle "$pki/client-ca.crt" "$tls" && anchors=changed
    printf 'ca=%s server=%s anchors=%s\n' "$ca_state" "$server_state" "$anchors"
}

# --------------------------------------------------- role-split ingest listener
env_file_value() { # env_file_value <file> <key>: last assignment, quotes stripped.
    [[ -f "$1" ]] || return 0
    awk -v k="$2" 'index($0, k "=") == 1 { v = substr($0, length(k) + 2) } END { print v }' "$1" \
        | sed "s/^[\"']//; s/[\"']\$//"
}

cmd_ensure_ingest() {
    local tls="" env_file="" value tmp count=0 changed=0 part
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --tls-dir) [[ $# -ge 2 ]] || usage_die "--tls-dir needs a value"; tls="$2"; shift 2 ;;
            --env-file) [[ $# -ge 2 ]] || usage_die "--env-file needs a value"; env_file="$2"; shift 2 ;;
            *) usage_die "ensure-ingest: unknown argument: $1" ;;
        esac
    done
    [[ -n "$tls" && -n "$env_file" ]] || usage_die "ensure-ingest needs --tls-dir and --env-file"
    prepare_tls_dir "$tls"
    [[ -s "$tls/.locked-anchor.crt" ]] || make_locked_anchor "$tls/.locked-anchor.crt"
    tmp=$(tmpdir "$tls/.issue.XXXXXX")
    cat "$tls/.locked-anchor.crt" > "$tmp/bundle"
    value=$(env_file_value "$env_file" "$ANCHORS_KEY")
    if [[ -n "$value" ]]; then
        [[ "$value" =~ ^[A-Za-z0-9+/=]+$ ]] || die "$ANCHORS_KEY in $env_file is not base64; copy .env again from the first app host"
        printf '%s' "$value" | openssl base64 -d -A > "$tmp/anchors" 2>/dev/null \
            || die "$ANCHORS_KEY in $env_file does not decode; copy .env again from the first app host"
        # Each block must be a certificate (public data only).
        awk -v dir="$tmp" '/-----BEGIN CERTIFICATE-----/ { n++; f = dir "/a" n ".pem" } f { print > f } /-----END CERTIFICATE-----/ { close(f); f = "" }' "$tmp/anchors"
        grep -q 'PRIVATE KEY' "$tmp/anchors" && die "$ANCHORS_KEY must hold certificates only"
        for part in "$tmp"/a*.pem; do
            [[ -e "$part" ]] || continue
            openssl x509 -noout -in "$part" </dev/null >/dev/null 2>&1 || die "$ANCHORS_KEY holds an invalid certificate"
            cat "$part" >> "$tmp/bundle"
            count=$((count + 1))
        done
    fi
    install_bundle "$tmp/bundle" "$tls" && changed=1
    rm -rf "$tmp"
    printf 'anchors=%s changed=%s\n' "$count" "$changed"
}

# ------------------------------------------------------------ sender certificates
require_pki() {
    [[ -d "$1" && -s "$1/locked-anchor.crt" ]] || prepare_pki_dir "$1"
}

server_ca_for() { # server_ca_for <pki> <explicit or empty>: the sender's ca.crt source
    if [[ -n "$2" ]]; then
        [[ -s "$2" ]] && openssl x509 -noout -in "$2" </dev/null >/dev/null 2>&1 \
            || die "--server-ca $2 is not a certificate"
        if ! cmp -s "$2" "$1/server-ca.crt" 2>/dev/null; then
            [[ ! -s "$1/server-ca.key" ]] || die "$1 has its own listener CA; --server-ca does not apply here"
            cp "$2" "$1/server-ca.crt"
            chmod 644 "$1/server-ca.crt"
        fi
    fi
    [[ -s "$1/server-ca.crt" ]] \
        || die "no listener CA certificate in $1 (single host: run install.sh; role split: run this on the first app host; Helm: pass --server-ca, see the Kubernetes install guide)"
    printf '%s\n' "$1/server-ca.crt"
}

# with_port <host[:port]>: adds :6000 when no port is given (IPv6 in brackets).
with_port() {
    local value="$1"
    if [[ -z "$value" ]]; then
        printf '<nano host>:%s\n' "$NATIVE_PORT"
    elif [[ "$value" =~ ^\[.*\]:[0-9]+$ || "$value" =~ ^[^:]+:[0-9]+$ ]]; then
        printf '%s\n' "$value"
    elif [[ "$value" == \[*\] ]]; then
        printf '%s:%s\n' "$value" "$NATIVE_PORT"
    elif [[ "$value" == *:* ]]; then
        printf '[%s]:%s\n' "$value" "$NATIVE_PORT"
    else
        printf '%s:%s\n' "$value" "$NATIVE_PORT"
    fi
}

print_sink_config() { # print_sink_config <address> <server name> <crt> <key> <ca>
    printf '[sinks.nano]\ntype = "vector"\ninputs = ["<your source or transform>"]\n'
    printf 'address = "%s"\nversion = "2"\ntls.enabled = true\n' "$1"
    [[ -z "$2" ]] || printf 'tls.server_name = "%s"\n' "$2"
    printf 'tls.crt_file = "%s"\ntls.key_file = "%s"\ntls.ca_file = "%s"\n' "$3" "$4" "$5"
}

# safe_out <dir>: create (0700) or accept an existing real directory; prints its path.
safe_out() {
    if [[ ! -e "$1" ]]; then
        mkdir -p "$1"
        chmod 700 "$1"
    fi
    [[ -d "$1" && ! -L "$1" ]] || die "--out $1 is not a directory"
    (cd "$1" && pwd -P)
}

check_csr() { # check_csr <file>: a valid, self-signed request
    [[ -f "$1" ]] || die "--csr $1 does not exist"
    openssl req -verify -noout -in "$1" </dev/null >/dev/null 2>&1 || die "--csr $1 is not a valid certificate request"
    grep -q 'PRIVATE KEY' "$1" && die "--csr $1 contains a private key; pass only the request"
    return 0
}

write_out() { # write_out <src> <dst>: copy a public file, never through a symlink.
    [[ ! -L "$2" ]] || die "$2 is a symlink; refusing to write through it"
    cp "$1" "$2.tmp.$$"
    chmod 644 "$2.tmp.$$"
    mv -f "$2.tmp.$$" "$2"
}

cmd_issue() {
    local name="" pki="" out="" days="$CLIENT_DAYS_DEFAULT" address="" tls="" csr="" server_ca="" server_name=""
    local status serial key crt ca host dir ca_src key_label
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --pki-dir) [[ $# -ge 2 ]] || usage_die "--pki-dir needs a value"; pki="$2"; shift 2 ;;
            --out) [[ $# -ge 2 ]] || usage_die "--out needs a directory"; out="$2"; shift 2 ;;
            --days) [[ $# -ge 2 ]] || usage_die "--days needs a number"; days="$2"; shift 2 ;;
            --address) [[ $# -ge 2 ]] || usage_die "--address needs HOST[:PORT]"; address="$2"; shift 2 ;;
            --tls-dir) [[ $# -ge 2 ]] || usage_die "--tls-dir needs a value"; tls="$2"; shift 2 ;;
            --csr) [[ $# -ge 2 ]] || usage_die "--csr needs a file"; csr="$2"; shift 2 ;;
            --server-ca) [[ $# -ge 2 ]] || usage_die "--server-ca needs a file"; server_ca="$2"; shift 2 ;;
            --server-name) [[ $# -ge 2 ]] || usage_die "--server-name needs a name"; server_name="$2"; shift 2 ;;
            -*) usage_die "issue: unknown option: $1" ;;
            *) [[ -z "$name" ]] || usage_die "issue takes one sender name"; name="$1"; shift ;;
        esac
    done
    [[ -n "$pki" ]] || usage_die "issue needs --pki-dir"
    valid_name "$name" || usage_die "sender name must be 1-63 characters: letters, digits, dot, underscore or hyphen (got '${name}')"
    [[ "$days" =~ ^[0-9]+$ ]] && ((days >= 1 && days <= CLIENT_DAYS_MAX)) \
        || usage_die "--days must be a whole number from 1 to $CLIENT_DAYS_MAX"
    [[ -z "$server_name" ]] || is_dns "$server_name" || usage_die "--server-name must be a DNS name"
    [[ -z "$csr" ]] || check_csr "$csr"
    lock_pki "$pki"
    require_pki "$pki"
    ca_src=$(server_ca_for "$pki" "$server_ca")
    status=$(index_field "$pki" "$name" 4)
    if [[ "$status" == active ]]; then
        die "'$name' already has an active certificate. Renew it with --renew $name (same anchor, no restart), or --revoke $name first to replace it"
    fi
    [[ -n "$out" ]] || out="./nano-vector-$name"
    [[ "$out" != *$'\n'* && "$out" != *$'\t'* ]] || usage_die "--out must not contain tabs or newlines"
    out=$(safe_out "$out")
    key="$out/$name.key" crt="$out/$name.crt" ca="$out/ca.crt"
    [[ -n "$csr" || ( ! -e "$key" && ! -L "$key" ) ]] \
        || die "$key already exists; refusing to overwrite a private key (use another --out directory)"
    dir="$pki/clients/$name"
    rm -rf "$dir"
    mkdir -m 700 "$dir"
    make_ca "$dir/anchor.key" "$dir/anchor.crt" "nano vector-native anchor: $name" anchor
    if [[ -n "$csr" ]]; then
        cp "$csr" "$dir/client.csr"
    else
        new_key "$key"
        openssl req -new -key "$key" -subj "/O=nano vector-native sender/CN=$name" \
            -out "$dir/client.csr" </dev/null >/dev/null 2>&1 || die "openssl could not create the request"
    fi
    chmod 644 "$dir/client.csr"
    sign "$dir/client.csr" "$dir/anchor.crt" "$dir/anchor.key" "$dir/client.crt" "$days" client
    write_out "$dir/client.crt" "$crt"
    write_out "$ca_src" "$ca"
    serial=$(cert_serial "$crt")
    index_put "$pki" "$name" "$serial" "$(cert_not_after "$crt")" active "$out" "$days"
    build_bundle "$pki" || true
    [[ -z "$tls" ]] || install_bundle "$pki/client-ca.crt" "$tls" || true
    address=$(with_port "$address")
    host=$(host_of_url "$address")
    if [[ -n "$tls" && -f "$tls/.sans" && -z "$server_name" && "$host" != "<nano host>" ]] \
        && ! grep -qxF -e "DNS:$(printf '%s' "$host" | tr '[:upper:]' '[:lower:]')" -e "IP:$host" "$tls/.sans"; then
        note "warning: '$host' is not in the listener certificate (see $tls/.sans), so this sender's TLS check will fail."
        note "         Use one of those names or addresses, or add '$host' to NANO_VECTOR_NATIVE_SANS in .env and re-run install.sh."
    fi
    key_label="$key"
    [[ -z "$csr" ]] || key_label="<the private key behind $csr, on the sender>"
    note "Issued a Vector-native client certificate for '$name' (serial $serial, expires $(cert_not_after "$crt"))."
    if [[ -n "$csr" ]]; then
        note "Files: $crt and $ca (the private key never left the sender)."
    else
        note "Files (copy all three to the sender; keep $name.key private, mode 0600):"
        note "  $crt"
        note "  $key"
        note "  $ca"
    fi
    note ""
    note "Vector sink config for the sender (adjust the paths to where you copy the files):"
    print_sink_config "$address" "$server_name" "$crt" "$key_label" "$ca"
}

cmd_renew() {
    local name="" pki="" days="" csr="" out="" dir status crt
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --pki-dir) [[ $# -ge 2 ]] || usage_die "--pki-dir needs a value"; pki="$2"; shift 2 ;;
            --days) [[ $# -ge 2 ]] || usage_die "--days needs a number"; days="$2"; shift 2 ;;
            --csr) [[ $# -ge 2 ]] || usage_die "--csr needs a file"; csr="$2"; shift 2 ;;
            --out) [[ $# -ge 2 ]] || usage_die "--out needs a directory"; out="$2"; shift 2 ;;
            -*) usage_die "renew: unknown option: $1" ;;
            *) [[ -z "$name" ]] || usage_die "renew takes one sender name"; name="$1"; shift ;;
        esac
    done
    [[ -n "$pki" ]] || usage_die "renew needs --pki-dir"
    valid_name "$name" || usage_die "invalid sender name '$name'"
    [[ -z "$csr" ]] || check_csr "$csr"
    lock_pki "$pki"
    status=$(index_field "$pki" "$name" 4)
    [[ "$status" == active ]] || die "'$name' has no active certificate to renew (see --list); issue a new one"
    dir="$pki/clients/$name"
    [[ -s "$dir/anchor.key" ]] || die "the anchor key for '$name' is missing; --revoke $name and issue it again"
    [[ -n "$days" ]] || days=$(index_field "$pki" "$name" 6)
    [[ "$days" =~ ^[0-9]+$ ]] && ((days >= 1 && days <= CLIENT_DAYS_MAX)) || days=$CLIENT_DAYS_DEFAULT
    if [[ -n "$csr" ]]; then
        cp "$csr" "$dir/client.csr"
        chmod 644 "$dir/client.csr"
    fi
    [[ -s "$dir/client.csr" ]] || die "no request on record for '$name'; pass --csr FILE"
    sign "$dir/client.csr" "$dir/anchor.crt" "$dir/anchor.key" "$dir/client.crt.new" "$days" client
    mv -f "$dir/client.crt.new" "$dir/client.crt"
    [[ -n "$out" ]] || out=$(index_field "$pki" "$name" 5)
    crt="$dir/client.crt"
    if [[ -n "$out" ]] && out=$(safe_out "$out" 2>/dev/null); then
        write_out "$dir/client.crt" "$out/$name.crt"
        crt="$out/$name.crt"
    fi
    index_put "$pki" "$name" "$(cert_serial "$dir/client.crt")" "$(cert_not_after "$dir/client.crt")" active "$out" "$days"
    note "Renewed '$name' (same anchor and key; no listener change or restart): $crt, expires $(cert_not_after "$dir/client.crt")."
    note "Copy it to the sender and restart the sender's Vector."
}

cmd_list() {
    local pki="" name serial not_after status out days state
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --pki-dir) [[ $# -ge 2 ]] || usage_die "--pki-dir needs a value"; pki="$2"; shift 2 ;;
            *) usage_die "list: unknown argument: $1" ;;
        esac
    done
    [[ -n "$pki" ]] || usage_die "list needs --pki-dir"
    if [[ ! -s "$pki/clients.tsv" ]]; then
        printf 'No Vector-native client certificates issued (%s).\n' "$pki"
        return 0
    fi
    printf '%-24s %-9s %-26s %s\n' NAME STATUS EXPIRES SERIAL
    while IFS=$'\t' read -r name serial not_after status out days; do
        [[ -n "$name" ]] || continue
        state="$status"
        if [[ "$status" == active ]]; then
            if ! valid_for "$pki/clients/$name/client.crt" 0; then state=expired
            elif ! valid_for "$pki/clients/$name/client.crt" "$RENEW_SECONDS"; then state=expiring
            fi
        fi
        printf '%-24s %-9s %-26s %s\n' "$name" "$state" "$not_after" "$serial"
    done < "$pki/clients.tsv"
    : "${out:-}" "${days:-}"
}

cmd_expiring() {
    local pki="" tls="" name
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --pki-dir) [[ $# -ge 2 ]] || usage_die "--pki-dir needs a value"; pki="$2"; shift 2 ;;
            --tls-dir) [[ $# -ge 2 ]] || usage_die "--tls-dir needs a value"; tls="$2"; shift 2 ;;
            *) usage_die "expiring: unknown argument: $1" ;;
        esac
    done
    if [[ -n "$pki" && -s "$pki/clients.tsv" ]]; then
        while read -r name; do
            [[ -n "$name" ]] || continue
            valid_for "$pki/clients/$name/client.crt" "$RENEW_SECONDS" && continue
            printf "Vector-native client certificate '%s' expires %s: scripts/nano vector-client-cert --renew %s\n" \
                "$name" "$(cert_not_after "$pki/clients/$name/client.crt")" "$name"
        done < <(active_names "$pki")
    fi
    if [[ -n "$pki" && -s "$pki/server-ca.crt" ]] && ! valid_for "$pki/server-ca.crt" $((365 * 24 * 3600)); then
        printf 'Vector-native listener CA %s expires %s: plan a new CA (every sender needs a new ca.crt).\n' \
            "$pki/server-ca.crt" "$(cert_not_after "$pki/server-ca.crt")"
    fi
    if [[ -n "$tls" && -s "$tls/server.crt" ]] && ! valid_for "$tls/server.crt" "$RENEW_SECONDS"; then
        printf 'Vector-native listener certificate expires %s: re-run install.sh to renew it.\n' "$(cert_not_after "$tls/server.crt")"
    fi
    return 0
}

cmd_anchors() { # the active anchors (not the locked one), base64 on one line
    local pki="" name
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --pki-dir) [[ $# -ge 2 ]] || usage_die "--pki-dir needs a value"; pki="$2"; shift 2 ;;
            *) usage_die "anchors: unknown argument: $1" ;;
        esac
    done
    [[ -n "$pki" ]] || usage_die "anchors needs --pki-dir"
    [[ -s "$pki/clients.tsv" ]] || { printf '\n'; return 0; }
    while read -r name; do
        [[ -z "$name" ]] || cat "$pki/clients/$name/anchor.crt"
    done < <(active_names "$pki") | openssl base64 -A
    printf '\n'
}

cmd_revoke() {
    local name="" pki="" status dir
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --pki-dir) [[ $# -ge 2 ]] || usage_die "--pki-dir needs a value"; pki="$2"; shift 2 ;;
            --yes) shift ;;   # accepted for compatibility; revocation no longer affects other senders
            -*) usage_die "revoke: unknown option: $1" ;;
            *) [[ -z "$name" ]] || usage_die "revoke takes one sender name"; name="$1"; shift ;;
        esac
    done
    [[ -n "$pki" ]] || usage_die "revoke needs --pki-dir"
    valid_name "$name" || usage_die "invalid sender name '$name'"
    lock_pki "$pki"
    require_pki "$pki"
    status=$(index_field "$pki" "$name" 4)
    [[ -n "$status" ]] || die "no client certificate named '$name' (see --list)"
    dir="$pki/clients/$name"
    # Bundle first (the anchor leaves the trust list), then the record.
    index_put "$pki" "$name" "$(index_field "$pki" "$name" 2)" "$(index_field "$pki" "$name" 3)" revoked \
        "$(index_field "$pki" "$name" 5)" "$(index_field "$pki" "$name" 6)"
    build_bundle "$pki" || true
    rm -f "$dir/anchor.key"
    [[ ! -f "$dir/anchor.crt" ]] || mv -f "$dir/anchor.crt" "$dir/revoked-anchor.crt"
    note "Revoked '$name': its anchor is removed from $pki/client-ca.crt and its anchor key deleted."
    note "Other senders are not affected and need no new files."
}

# ---------------------------------------------------------------- operator CLI
client_cert_usage() {
    cat >&2 <<'USAGE'
usage: scripts/nano vector-client-cert <name> [--out DIR] [--days N] [--csr FILE] [--address HOST[:PORT]]
       scripts/nano vector-client-cert --renew <name> [--days N] [--csr FILE] [--out DIR]
       scripts/nano vector-client-cert --revoke <name>
       scripts/nano vector-client-cert --list
Common: [--pki-dir DIR --server-ca FILE [--server-name NAME]] issues from a PKI
directory outside this install (Helm: see the Kubernetes install guide).

Issues a client certificate for a sender to nano's Vector-native listener
(port 6000, mutual TLS only) and prints the Vector sink config. Without --csr
the private key is written to DIR (default ./nano-vector-<name>) with mode 0600
and never printed; with --csr FILE the key stays on the sender. Each sender has
its own trust anchor, so --revoke cuts off that sender only (Vector restarts
to apply it); --renew re-signs a sender with no listener change.
USAGE
}

# compose_restart_vector <install>: restart a running Vector to load the bundle.
#
# NAN-5566: on a single host never a plain restart under live ingest. Close
# ingest (Vector's published ports by its ingest gate, nginx's routes),
# drain, restart with more time than Vector's 60 s graceful limit, reopen; the
# EXIT trap reopens on any exit in between (scripts/lib/vector-quiesce.sh).
# Role split: the ingest host's edge is closed by its install/upgrade flow, so
# the restart stays as it was.
compose_restart_vector() {
    local install="$1" args=() rc=0
    if [[ -f "$install/.nano-role.env" ]]; then
        args=(--project-directory "$install/deploy/compose" --env-file "$install/.env"
            --env-file "$install/.nano-role.env" -f "$install/deploy/compose/docker-compose.enterprise.yml")
        docker compose "${args[@]}" restart vector </dev/null >/dev/null 2>&1
        return
    fi
    args=(--project-directory "$install" --env-file "$install/.env" -f "$install/docker-compose.opensource.yml")
    if [[ ! -r "$LIB_DIR/vector-quiesce.sh" ]]; then
        note "!! scripts/lib/vector-quiesce.sh is missing: restarting Vector without closing ingest first"
        docker compose "${args[@]}" restart vector </dev/null >/dev/null 2>&1
        return
    fi
    # shellcheck source=scripts/lib/vector-quiesce.sh
    . "$LIB_DIR/vector-quiesce.sh"
    NANO_VQ_PKI_COMPOSE_ARGS=("${args[@]}")
    nano_vq_compose() { docker compose "${NANO_VQ_PKI_COMPOSE_ARGS[@]}" "$@"; }
    declare -F log >/dev/null || log() { note "$*"; }
    declare -F warn >/dev/null || warn() { note "warning: $*"; }
    trap 'cleanup_tmp; nano_vq_reopen 30 || true' EXIT
    nano_vq_close
    nano_vq_drain "${NANO_VECTOR_DRAIN_SECS:-120}"
    nano_vq_compose restart --timeout "$NANO_VQ_STOP_TIMEOUT" vector </dev/null >/dev/null 2>&1 || rc=$?
    nano_vq_reopen || true
    trap cleanup_tmp EXIT
    return "$rc"
}

# role_split_publish <install> <pki> <what>: the shared .env carries the anchors.
role_split_publish() {
    local install="$1" pki="$2" what="$3" anchors
    anchors=$(cmd_anchors --pki-dir "$pki")
    # shellcheck source=scripts/lib/generated-secrets.sh
    . "$LIB_DIR/generated-secrets.sh"
    nano_env_set_keys "$install/.env" "$ANCHORS_KEY=$anchors" || die "could not record $ANCHORS_KEY in $install/.env"
    note ""
    note "!! Role split: $what is NOT yet effective on the ingest hosts. The sender anchors travel in the"
    note "!! shared .env ($ANCHORS_KEY, public certificates only). To apply it:"
    note "!!   1. stream this host's .env to every other host (multi-node guide, Step 5: distribute .env);"
    note "!!   2. re-run each ingest host's install command (it rebuilds client-ca.crt and restarts Vector)."
}

# apply_local_ingest <install>: this app host is also an ingest host.
apply_local_ingest() {
    cmd_ensure_ingest --tls-dir "$1/config/vector-native" --env-file "$1/.env" >/dev/null
    if compose_restart_vector "$1"; then
        note "Applied on this host's own listener (Vector restarted)."
    else
        note "!! Could not restart Vector on this host; re-run its install command."
        exit 1
    fi
}

cmd_client_cert() {
    local install="" pki="" tls="" mode=issue name="" address="" base_url host server_ca="" server_name=""
    local role_split=0 role_env="" this_ingest=0 external=0
    local -a rest=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --install-dir) [[ $# -ge 2 ]] || usage_die "--install-dir needs a value"; install="$2"; shift 2 ;;
            --pki-dir) [[ $# -ge 2 ]] || usage_die "--pki-dir needs a value"; pki="$2"; shift 2 ;;
            --server-ca) [[ $# -ge 2 ]] || usage_die "--server-ca needs a file"; server_ca="$2"; shift 2 ;;
            --server-name) [[ $# -ge 2 ]] || usage_die "--server-name needs a name"; server_name="$2"; shift 2 ;;
            --list) mode=list; shift ;;
            --renew) [[ $# -ge 2 ]] || usage_die "--renew needs a sender name"; mode=renew; name="$2"; shift 2 ;;
            --revoke) [[ $# -ge 2 ]] || usage_die "--revoke needs a sender name"; mode=revoke; name="$2"; shift 2 ;;
            --yes) shift ;;
            --address) [[ $# -ge 2 ]] || usage_die "--address needs HOST[:PORT]"; address="$2"; shift 2 ;;
            --out | --days | --csr) [[ $# -ge 2 ]] || usage_die "$1 needs a value"; rest+=("$1" "$2"); shift 2 ;;
            -h | --help) client_cert_usage; exit 0 ;;
            -*) client_cert_usage; usage_die "unknown option: $1" ;;
            *) [[ -z "$name" ]] || { client_cert_usage; usage_die "one sender name only"; }; name="$1"; shift ;;
        esac
    done
    if [[ -n "$pki" ]]; then
        external=1
    else
        [[ -n "$install" ]] || usage_die "--install-dir or --pki-dir is required"
        pki="$install/.nano-pki/vector-native"
        if [[ -f "$install/.nano-role.env" ]]; then
            role_split=1
            role_env="$install/.nano-role.env"
            [[ ",$(env_file_value "$role_env" NANO_ROLE_PROFILES)," == *,ingest,* ]] && this_ingest=1
            # The cluster's private TLS CA verifies every ingest host's listener.
            [[ -n "$server_ca" ]] || server_ca=$(env_file_value "$role_env" NANO_TLS_CA)
            [[ -n "$server_name" ]] || server_name=$(env_file_value "$role_env" NANO_TLS_SERVER_NAME)
            if [[ "$mode" == issue && ( -z "$server_ca" || "$server_ca" == /dev/null ) ]]; then
                die "this role-split cluster has no private TLS CA (plaintext lab mode), so it has no Vector-native listener"
            fi
        else
            tls="$install/config/vector-native"
        fi
    fi
    case "$mode" in
        list) cmd_list --pki-dir "$pki" ;;
        renew) cmd_renew "$name" --pki-dir "$pki" "${rest[@]}" ;;
        revoke)
            cmd_revoke "$name" --pki-dir "$pki"
            if ((external)); then
                note ""
                note "!! Not applied to a listener yet: publish $pki/client-ca.crt as the listener's client CA"
                note "!! (Helm: the <release>-nano-vector-native-clients Secret, key ca.crt) and restart Vector."
            elif ((role_split)); then
                role_split_publish "$install" "$pki" "the revocation of '$name'"
                note "!! Until then the ingest hosts still accept '$name'."
                ((this_ingest == 0)) || apply_local_ingest "$install"
            elif [[ -n "$tls" && -d "$tls" ]]; then
                install_bundle "$pki/client-ca.crt" "$tls" || true
                if compose_restart_vector "$install"; then
                    note "Restarted Vector: '$name' is refused from now on."
                else
                    note "!! The revocation is NOT effective yet: Vector could not be restarted here. Run:"
                    note "!!   docker compose -f $install/docker-compose.opensource.yml restart vector"
                    exit 1
                fi
            fi
            ;;
        issue)
            [[ -n "$name" ]] || { client_cert_usage; exit 2; }
            if [[ -z "$address" && -n "$install" ]]; then
                host="${NANO_VECTOR_NATIVE_PUBLIC_HOST:-$(env_file_value "$install/.env" NANO_VECTOR_NATIVE_PUBLIC_HOST)}"
                if [[ -z "$host" && "$role_split" == 1 ]]; then
                    host=$(env_file_value "$role_env" NANO_INGEST_HOSTNAME)
                fi
                if [[ -z "$host" ]]; then
                    base_url=$(env_file_value "$install/.env" BASE_URL)
                    [[ -z "$base_url" ]] || host=$(host_of_url "$base_url")
                fi
                case "$host" in
                    "" | localhost | 127.* | ::1)
                        note "warning: no address senders can reach is known (BASE_URL host '${host:-unset}'). Pass --address HOST, or"
                        note "         set NANO_VECTOR_NATIVE_PUBLIC_HOST=<name or IP senders use> in .env."
                        ;;
                esac
                address="$host"
            fi
            [[ -z "$address" ]] || rest+=(--address "$address")
            [[ -z "$tls" ]] || rest+=(--tls-dir "$tls")
            [[ -z "$server_ca" ]] || rest+=(--server-ca "$server_ca")
            [[ -z "$server_name" ]] || rest+=(--server-name "$server_name")
            cmd_issue "$name" --pki-dir "$pki" "${rest[@]}"
            if ((external)); then
                note ""
                note "Publish $pki/client-ca.crt as the listener's client CA (Helm: the <release>-nano-vector-native-clients"
                note "Secret, key ca.crt) and restart Vector; see the Kubernetes install guide."
            elif ((role_split)); then
                role_split_publish "$install" "$pki" "the new sender '$name'"
                ((this_ingest == 0)) || apply_local_ingest "$install"
            elif [[ -n "$tls" && -d "$tls" ]]; then
                if compose_restart_vector "$install"; then
                    note "Restarted Vector: the listener now accepts '$name'."
                else
                    note "!! Restart Vector so the listener accepts '$name':"
                    note "!!   docker compose -f $install/docker-compose.opensource.yml restart vector"
                fi
            fi
            ;;
    esac
}

# ------------------------------------------- per-sender bundles (NAN-5559)
# A 0.1.x install's :6000 listener was plaintext; after the upgrade it is
# mutual TLS only. `bundle` issues one client certificate bundle per sender
# into <install>/vector-client-bundles/<name>/ (directory 0700, every file
# 0600): <name>.crt, <name>.key, ca.crt and vector-sink.toml, the sender's
# sink config with a disk buffer. install.sh runs it at the legacy cutover;
# an operator can run it BEFORE the window on the 0.1.x host (--ensure also
# creates the listener CA and certificate there). Nothing in 0.1.x reads
# .nano-pki/ or config/vector-native/, and the upgrade's checkout reset keeps
# both (untracked, at paths 2.x does not ship), so 2.x finds the CA in place
# and every staged bundle stays valid.
#
# Prints one line per bundle on stdout: `bundle <name> <dir>`.
SENDER_BUFFER_BYTES=268435488   # Vector's minimum disk buffer
SENDER_FILES_DIR=/etc/vector/nano

# print_bundle_sink_config <address> <name> <dir on the sender>
print_bundle_sink_config() {
    printf '# nano Vector-native sink for sender "%s". Copy %s.crt, %s.key and ca.crt\n' "$2" "$2" "$2"
    printf '# to %s on the sender (the key mode 0600), then merge this into its config.\n' "$3"
    printf '[sinks.nano]\ntype = "vector"\ninputs = ["<your source or transform>"]\n'
    printf 'address = "%s"\nversion = "2"\n' "$1"
    printf 'tls.enabled = true\n'
    printf 'tls.crt_file = "%s/%s.crt"\ntls.key_file = "%s/%s.key"\ntls.ca_file = "%s/ca.crt"\n' "$3" "$2" "$3" "$2" "$3"
    printf '# Holds events on disk while nano is unreachable (an upgrade, a restart).\n'
    printf 'acknowledgements.enabled = true\nbuffer.type = "disk"\nbuffer.max_size = %s\nbuffer.when_full = "block"\n' \
        "$SENDER_BUFFER_BYTES"
}

cmd_bundle() {
    local install="" address="" ensure=0 name env pki tls bundles out host base_url bind sans_env result err status file
    local -a names=() failed=() ensure_args=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --install-dir) [[ $# -ge 2 ]] || usage_die "--install-dir needs a value"; install="$2"; shift 2 ;;
            --address) [[ $# -ge 2 ]] || usage_die "--address needs HOST[:PORT]"; address="$2"; shift 2 ;;
            --ensure) ensure=1; shift ;;
            -*) usage_die "bundle: unknown option: $1" ;;
            *) names+=("$1"); shift ;;
        esac
    done
    [[ -n "$install" && -d "$install" ]] || usage_die "bundle needs --install-dir DIR (the nano install directory)"
    ((${#names[@]} > 0)) || usage_die "bundle needs at least one sender name"
    for name in "${names[@]}"; do
        valid_name "$name" || usage_die "sender name must be 1-63 characters: letters, digits, dot, underscore or hyphen (got '${name}')"
    done
    install=$(cd "$install" && pwd -P)
    env="$install/.env" pki="$install/.nano-pki/vector-native" tls="$install/config/vector-native"
    bundles="$install/vector-client-bundles"
    if ((ensure)); then
        # The same inputs install.sh's ensure uses (BASE_URL, the bind address,
        # NANO_VECTOR_NATIVE_SANS from .env), so the upgrade finds the listener
        # certificate current instead of re-issuing it with other names.
        base_url=$(env_file_value "$env" BASE_URL)
        bind=$(env_file_value "$env" NANO_VECTOR_NATIVE_BIND_ADDRESS)
        sans_env=${NANO_VECTOR_NATIVE_SANS:-$(env_file_value "$env" NANO_VECTOR_NATIVE_SANS)}
        ensure_args=(--pki-dir "$pki" --tls-dir "$tls" --base-url "$base_url")
        [[ -z "$bind" ]] || ensure_args+=(--san "$bind")
        result=$(NANO_VECTOR_NATIVE_SANS="$sans_env" bash "${BASH_SOURCE[0]}" ensure "${ensure_args[@]}" </dev/null) \
            || die "could not prepare the Vector-native listener in $tls (above)"
        note "Vector-native listener: $result (its names and addresses: $tls/.sans)"
    fi
    [[ -s "$pki/server-ca.crt" && -s "$tls/server.crt" ]] \
        || die "no Vector-native listener CA in $pki yet: run install.sh, or pass --ensure"
    if [[ -z "$address" ]]; then
        host="${NANO_VECTOR_NATIVE_PUBLIC_HOST:-$(env_file_value "$env" NANO_VECTOR_NATIVE_PUBLIC_HOST)}"
        if [[ -z "$host" ]]; then
            base_url=$(env_file_value "$env" BASE_URL)
            [[ -z "$base_url" ]] || host=$(host_of_url "$base_url")
        fi
        case "$host" in
            "" | localhost | 127.* | ::1)
                note "warning: no address senders can reach is known (BASE_URL host '${host:-unset}'). Each sink config"
                note "         says <nano host>: replace it, or set NANO_VECTOR_NATIVE_PUBLIC_HOST in .env and run this again."
                host=""
                ;;
        esac
        address="$host"
    fi
    address=$(with_port "$address")
    mkdir -p "$bundles"
    chmod 700 "$bundles"
    for name in "${names[@]}"; do
        out="$bundles/$name"
        if [[ "$(index_field "$pki" "$name" 4)" == active ]]; then
            if [[ ! -s "$out/$name.crt" ]]; then
                note "'$name' already has an active certificate, but not in $out; skipped. If its files are lost:"
                note "  scripts/nano vector-client-cert --revoke $name, then issue it again."
                failed+=("$name")
                continue
            fi
            note "'$name': bundle issued earlier, kept ($out)."
            # Files may have been moved to the sender since: put back the public ca.crt.
            [[ -s "$out/ca.crt" ]] || write_out "$pki/server-ca.crt" "$out/ca.crt"
        else
            status=0
            err=$(bash "${BASH_SOURCE[0]}" issue "$name" --pki-dir "$pki" --tls-dir "$tls" --out "$out" \
                --address "$address" 2>&1 >/dev/null </dev/null) || status=$?
            if [[ "$status" != 0 ]]; then
                printf '%s\n' "$err" >&2
                failed+=("$name")
                continue
            fi
            # issue's own sink config is replaced by vector-sink.toml; keep its warnings.
            printf '%s\n' "$err" | grep -E '^ *(warning|Use one)' >&2 || true
        fi
        print_bundle_sink_config "$address" "$name" "$SENDER_FILES_DIR" > "$out/vector-sink.toml.tmp.$$"
        mv -f "$out/vector-sink.toml.tmp.$$" "$out/vector-sink.toml"
        chmod 700 "$out"
        for file in "$out/$name.crt" "$out/$name.key" "$out/ca.crt" "$out/vector-sink.toml"; do
            [[ ! -f "$file" ]] || chmod 600 "$file"
        done
        printf 'bundle %s %s\n' "$name" "$out"
    done
    ((${#failed[@]} == 0)) || die "no bundle for: ${failed[*]}"
}

# NAN-5523: the ClickHouse query counting events the stack took on :6000 in
# the last 24 hours (source_type 'vector_native', set by the vector_auth
# transform). An OCSF profile (ocsf, ocsf+tenzir) stores events in
# nanosiem.ocsf_logs, whose source_type column carries the same routing value;
# udm (and a .env without a profile, which install.sh pins to udm) in
# nanosiem.logs. install.sh and nano upgrade both use this query.
cmd_events_query() {
    local profile="" table
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --profile) [[ $# -ge 2 ]] || usage_die "--profile needs a value"; profile="$2"; shift 2 ;;
            *) usage_die "unknown argument: $1" ;;
        esac
    done
    case "$profile" in
        ocsf | ocsf+tenzir) table=nanosiem.ocsf_logs ;;
        udm | "") table=nanosiem.logs ;;
        *) usage_die "unknown schema profile: $profile" ;;
    esac
    printf "SELECT count() FROM %s WHERE timestamp >= now() - INTERVAL 1 DAY AND source_type = 'vector_native' FORMAT TSV\n" "$table"
}

main() {
    local command="${1:-}"
    [[ $# -gt 0 ]] && shift
    case "$command" in
        ensure) cmd_ensure "$@" ;;
        ensure-ingest) cmd_ensure_ingest "$@" ;;
        sans) cmd_sans "$@" ;;
        issue) cmd_issue "$@" ;;
        renew) cmd_renew "$@" ;;
        list) cmd_list "$@" ;;
        expiring) cmd_expiring "$@" ;;
        anchors) cmd_anchors "$@" ;;
        revoke) cmd_revoke "$@" ;;
        client-cert) cmd_client_cert "$@" ;;
        bundle) cmd_bundle "$@" ;;
        events-query) cmd_events_query "$@" ;;
        *) sed -n '2,72p' "${BASH_SOURCE[0]}" >&2; exit 2 ;;
    esac
}

main "$@"
