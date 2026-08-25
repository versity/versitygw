#!/usr/bin/env bash
#
# Generate the mTLS material the S3 gateway needs to talk to a standalone IAM
# service's private endpoints over TCP:
#
#   <dir>/ca.pem          CA certificate, trusted by both sides
#   <dir>/iam-server.pem  IAM private-listener server certificate
#   <dir>/iam-server.key
#   <dir>/gw-client.pem   S3 gateway client certificate
#   <dir>/gw-client.key
#
# Usage: genmtlscerts.sh <output-dir> [server-ip]
#
# The server certificate carries an IP SAN for server-ip (default 127.0.0.1)
# because the gateway dials the private endpoint as "https://<host>:<port>"
# with standard Go certificate verification and no hostname override — an IP
# endpoint therefore needs an IP SAN, not a CN or a DNS SAN, or the handshake
# fails with a name-mismatch error.

set -Eeuo pipefail

if [[ $# -lt 1 ]]; then
	echo "usage: $0 <output-dir> [server-ip]" >&2
	exit 1
fi

CERT_DIR="$1"
SERVER_IP="${2:-127.0.0.1}"

mkdir -p "$CERT_DIR"

EXT_FILE="$CERT_DIR/openssl-ext.cnf"
# Written as a file rather than passed via -addext so this works on both
# OpenSSL and the LibreSSL
cat >"$EXT_FILE" <<EOF
[server]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = IP:$SERVER_IP

[client]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF

# CA
openssl genpkey -algorithm RSA -out "$CERT_DIR/ca.key" -pkeyopt rsa_keygen_bits:2048 2>/dev/null
openssl req -new -x509 -key "$CERT_DIR/ca.key" -out "$CERT_DIR/ca.pem" -days 1 \
	-subj "/C=US/ST=California/L=San Francisco/O=Versity/OU=Software/CN=versitygw-test-ca"

# IAM private-listener server certificate
openssl genpkey -algorithm RSA -out "$CERT_DIR/iam-server.key" -pkeyopt rsa_keygen_bits:2048 2>/dev/null
openssl req -new -key "$CERT_DIR/iam-server.key" -out "$CERT_DIR/iam-server.csr" \
	-subj "/C=US/ST=California/L=San Francisco/O=Versity/OU=Software/CN=versitygw-iam-private"
openssl x509 -req -in "$CERT_DIR/iam-server.csr" -CA "$CERT_DIR/ca.pem" -CAkey "$CERT_DIR/ca.key" \
	-CAcreateserial -out "$CERT_DIR/iam-server.pem" -days 1 \
	-extfile "$EXT_FILE" -extensions server 2>/dev/null

# S3 gateway client certificate. The IAM service verifies it against the CA
# but does not authorize on its identity — authorization is the root SigV4
# credential the gateway signs each private request with.
openssl genpkey -algorithm RSA -out "$CERT_DIR/gw-client.key" -pkeyopt rsa_keygen_bits:2048 2>/dev/null
openssl req -new -key "$CERT_DIR/gw-client.key" -out "$CERT_DIR/gw-client.csr" \
	-subj "/C=US/ST=California/L=San Francisco/O=Versity/OU=Software/CN=versitygw-s3-gateway"
openssl x509 -req -in "$CERT_DIR/gw-client.csr" -CA "$CERT_DIR/ca.pem" -CAkey "$CERT_DIR/ca.key" \
	-CAcreateserial -out "$CERT_DIR/gw-client.pem" -days 1 \
	-extfile "$EXT_FILE" -extensions client 2>/dev/null

rm -f "$CERT_DIR"/*.csr "$EXT_FILE"
