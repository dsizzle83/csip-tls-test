#!/bin/bash
# Generates (or regenerates) the production server cert, signed by the
# existing CA in certs/vault/.  The SAN includes configurable demo-network
# IP addresses so Pi devices on a LAN switch can reach the server.
#
# Usage:
#   bash scripts/gen-server-cert.sh [IP...]
#
# Examples:
#   bash scripts/gen-server-cert.sh                          # localhost + 127.0.0.1 only
#   bash scripts/gen-server-cert.sh 192.168.10.1             # add one LAN IP
#   bash scripts/gen-server-cert.sh 192.168.10.1 10.0.0.5   # add multiple IPs
#
# Output: certs/server-cert.pem (tracked), certs/vault/server-key.pem (gitignored)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CERTS="$REPO_ROOT/certs"
VAULT="$CERTS/vault"

if [[ ! -f "$VAULT/ca-key.pem" ]]; then
  echo "error: $VAULT/ca-key.pem not found." >&2
  echo "Run the full cert setup first to create the production CA." >&2
  exit 1
fi

WORK=$(mktemp -d)
trap "rm -rf $WORK" EXIT

# === Server private key (in vault — gitignored) ==============================
openssl ecparam -name prime256v1 -genkey -noout \
  -out "$VAULT/server-key.pem"
chmod 600 "$VAULT/server-key.pem"

# === Build SAN extension config ==============================================
cat > "$WORK/server-ext.cnf" <<'EXTEOF'
basicConstraints = critical,CA:FALSE
keyUsage         = critical,digitalSignature,keyAgreement
extendedKeyUsage = serverAuth
subjectAltName   = @san
[san]
DNS.1 = localhost
IP.1  = 127.0.0.1
EXTEOF

# Append any extra IPs passed as arguments
IP_IDX=2
for ip in "$@"; do
  echo "IP.$IP_IDX  = $ip" >> "$WORK/server-ext.cnf"
  IP_IDX=$((IP_IDX + 1))
done

echo "=== SAN config ==="
grep -A 20 '\[san\]' "$WORK/server-ext.cnf"

# === CSR =====================================================================
openssl req -new \
  -key "$VAULT/server-key.pem" \
  -out "$WORK/server.csr" \
  -subj "/CN=csip-hub-server"

# === Sign with production CA =================================================
openssl x509 -req \
  -in "$WORK/server.csr" \
  -CA "$CERTS/ca-cert.pem" \
  -CAkey "$VAULT/ca-key.pem" \
  -CAcreateserial \
  -out "$CERTS/server-cert.pem" \
  -days 365 \
  -extfile "$WORK/server-ext.cnf" \
  -sha256

rm -f "$CERTS/ca-cert.srl"

echo
echo "=== Verify cert chain ==="
openssl verify -CAfile "$CERTS/ca-cert.pem" "$CERTS/server-cert.pem"
openssl x509 -noout -subject -dates -ext subjectAltName -in "$CERTS/server-cert.pem"

echo
echo "Output:"
echo "  cert: $CERTS/server-cert.pem  (commit this)"
echo "  key:  $VAULT/server-key.pem   (gitignored — stays in vault)"
echo
echo "Next: restart the hub to pick up the new cert."
