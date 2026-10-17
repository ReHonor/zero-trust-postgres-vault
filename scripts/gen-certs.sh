#!/usr/bin/env bash
# Generates a private CA and a TLS server certificate for the PostgreSQL container.
# Output goes to ./certs (git-ignored). Safe to re-run: old files are replaced.
set -euo pipefail

CERT_DIR="${1:-certs}"
DAYS=365

mkdir -p "$CERT_DIR"
cd "$CERT_DIR"
rm -f ca.key ca.crt ca.srl ca.cnf server.key server.csr server.crt server.ext

echo "[1/4] Creating the CA key and self-signed CA certificate"
printf '%s\n' \
  "[req]" \
  "distinguished_name = dn" \
  "prompt = no" \
  "x509_extensions = v3_ca" \
  "[dn]" \
  "CN = ZeroTrust-Lab-CA" \
  "[v3_ca]" \
  "basicConstraints = critical, CA:TRUE" \
  "keyUsage = critical, keyCertSign, cRLSign" \
  "subjectKeyIdentifier = hash" \
  "authorityKeyIdentifier = keyid:always" > ca.cnf
openssl genrsa -out ca.key 4096
openssl req -x509 -new -key ca.key -sha256 -days "$DAYS" -config ca.cnf -out ca.crt

echo "[2/4] Creating the server key and certificate signing request (CSR)"
openssl genrsa -out server.key 2048
openssl req -new -key server.key -subj "/CN=postgres" -out server.csr

echo "[3/4] Writing the extensions file (SAN = valid hostnames)"
printf '%s\n' \
  "subjectAltName = DNS:postgres, DNS:localhost, IP:127.0.0.1" \
  "basicConstraints = CA:FALSE" \
  "keyUsage = digitalSignature, keyEncipherment" \
  "extendedKeyUsage = serverAuth" \
  "subjectKeyIdentifier = hash" \
  "authorityKeyIdentifier = keyid,issuer" > server.ext

echo "[4/4] Signing the server certificate with the CA"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -sha256 -days "$DAYS" -extfile server.ext -out server.crt

chmod 600 ca.key server.key
chmod 644 ca.crt server.crt
echo "Done. Files in $(pwd):"
ls -l
