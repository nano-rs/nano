#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Create a private CA and ONE server certificate for nano role-split private
# transport (ClickHouse, Keeper, app-internal). Use only when the operator has
# no PKI of their own. Run it on the operator's workstation.
#
#   make-private-ca.sh --out ./nano-pki --server-name nano-private.example.com \
#       --ip 10.20.0.11 --ip 10.20.0.12 --ip 10.20.0.13 [--dns extra.name] [--days 825]
#
# The certificate is used as both server and client certificate (Keeper requires
# a private-CA client certificate), so it carries serverAuth + clientAuth and a
# SAN for the server name and every inventory address.
#
# Output (directory mode 0700): ca.key (0600, keep OFFLINE, never copy to hosts),
# ca.crt, server.key (0600), server.crt. Copy only ca.crt, server.crt and
# server.key to each host (see references/multi-node-ha.md). Prints no key material.
set -euo pipefail
umask 077
out="" name="" days=825 sans=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --out) out="$2"; shift 2 ;;
        --server-name) name="$2"; shift 2 ;;
        --ip) sans+=("IP:$2"); shift 2 ;;
        --dns) sans+=("DNS:$2"); shift 2 ;;
        --days) days="$2"; shift 2 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done
[[ -n "$out" && -n "$name" && ${#sans[@]} -gt 0 ]] || { sed -n '2,18p' "$0"; exit 2; }
if [[ -e "$out/server.key" || -e "$out/ca.key" ]]; then
    echo "$out already holds keys; refusing to overwrite (move it aside deliberately to re-issue)" >&2
    exit 3
fi
mkdir -p "$out"; chmod 700 "$out"
san="DNS:$name"; for s in "${sans[@]}"; do san+=",$s"; done
openssl req -x509 -newkey rsa:3072 -nodes -days "$((days + 365))" -sha256 \
    -subj "/CN=nano private CA ($name)" \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -addext 'subjectKeyIdentifier=hash' \
    -keyout "$out/ca.key" -out "$out/ca.crt" >/dev/null 2>&1
cat > "$out/server.ext" <<EOF
subjectAltName=$san
extendedKeyUsage=serverAuth,clientAuth
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
openssl req -newkey rsa:3072 -nodes -subj "/CN=$name" \
    -keyout "$out/server.key" -out "$out/server.csr" >/dev/null 2>&1
openssl x509 -req -days "$days" -sha256 -in "$out/server.csr" \
    -CA "$out/ca.crt" -CAkey "$out/ca.key" -CAcreateserial \
    -extfile "$out/server.ext" -out "$out/server.crt" >/dev/null 2>&1
rm -f "$out/server.csr" "$out/server.ext"
chmod 600 "$out/ca.key" "$out/server.key"; chmod 644 "$out/ca.crt" "$out/server.crt"
openssl verify -CAfile "$out/ca.crt" "$out/server.crt" >/dev/null
printf 'created %s: ca.crt, server.crt (SAN %s), server.key, ca.key (keep ca.key offline)\n' "$out" "$san"
openssl x509 -in "$out/server.crt" -noout -enddate
