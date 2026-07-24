#!/usr/bin/env bash
# ==============================================================================
# Project Parewa — Self-Signed SSL Certificate Generator
# Generates TLS certificates for IP: 192.168.178.200
# Output: ./certs/parewa.crt  and  ./certs/parewa.key
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="${SCRIPT_DIR}/certs"
CERT_FILE="${CERT_DIR}/parewa.crt"
KEY_FILE="${CERT_DIR}/parewa.key"
SERVER_IP="192.168.178.200"
VALIDITY_DAYS=365

echo "============================================"
echo "  Project Parewa — Certificate Generator"
echo "============================================"
echo ""

# Create certs directory if it doesn't exist
mkdir -p "${CERT_DIR}"

# Check if certificates already exist
if [[ -f "${CERT_FILE}" && -f "${KEY_FILE}" ]]; then
    echo "[!] Certificates already exist:"
    echo "    ${CERT_FILE}"
    echo "    ${KEY_FILE}"
    echo ""
    read -rp "Overwrite existing certificates? [y/N]: " confirm
    if [[ "${confirm}" != "y" && "${confirm}" != "Y" ]]; then
        echo "[*] Aborted. Existing certificates retained."
        exit 0
    fi
    echo ""
fi

echo "[*] Generating self-signed certificate for IP: ${SERVER_IP}"
echo "[*] Validity: ${VALIDITY_DAYS} days"
echo ""

# Generate self-signed certificate with Subject Alternative Name (SAN) for IP
openssl req -x509 -nodes -newkey rsa:4096 \
    -days "${VALIDITY_DAYS}" \
    -keyout "${KEY_FILE}" \
    -out "${CERT_FILE}" \
    -subj "/C=NP/ST=Bagmati/L=Kathmandu/O=Project Parewa/OU=Infrastructure/CN=${SERVER_IP}" \
    -addext "subjectAltName=IP:${SERVER_IP}" \
    -addext "keyUsage=digitalSignature,keyEncipherment" \
    -addext "extendedKeyUsage=serverAuth"

echo ""
echo "[✓] Certificates generated successfully!"
echo "    Certificate : ${CERT_FILE}"
echo "    Private Key : ${KEY_FILE}"
echo ""
echo "[*] Certificate details:"
openssl x509 -in "${CERT_FILE}" -noout -subject -dates -fingerprint -sha256
echo ""
echo "[*] Next steps:"
echo "    1. Start the Docker stack:  docker compose up -d"
echo "    2. Pin the certificate SHA-256 fingerprint in the Android client (Task 3)"
echo "============================================"
