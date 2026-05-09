#!/bin/bash
# Generate self-signed SSL certificates for development
# For production, use Let's Encrypt or your own CA-signed certs

SSL_DIR="$(dirname "$0")/ssl"
mkdir -p "$SSL_DIR"

# Generate private key and self-signed certificate
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "$SSL_DIR/privkey.pem" \
    -out "$SSL_DIR/fullchain.pem" \
    -subj "/C=US/ST=State/L=City/O=Nano/OU=Security/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,DNS:*.localhost,IP:127.0.0.1"

echo "SSL certificates generated in $SSL_DIR"
echo "  - privkey.pem (private key)"
echo "  - fullchain.pem (certificate)"
echo ""
echo "For production, replace these with Let's Encrypt or CA-signed certificates."
