#!/bin/bash
# Generates the OCPP CSMS TLS cert (Security Profile 2), signed by the
# existing CA in certs/vault/. This is a plain crypto/tls WebSocket cert for
# the EV charger link — NOT the CSIP mTLS server cert (see gen-server-cert.sh).
#
# Usage:
#   bash scripts/gen-ev-cert.sh [IP-or-DNS...]
#
# Examples:
#   bash scripts/gen-ev-cert.sh                  # localhost + 127.0.0.1 only
#   bash scripts/gen-ev-cert.sh 69.0.0.1         # add the hub's LAN IP
#
# Output: certs/ev-server-cert.pem (tracked), certs/vault/ev-server-key.pem (gitignored)
#
# Deploy: copy both files to the hub, then in lexa-hub's ocpp.json set
#   "cert_path": "/etc/lexa/ev-server-cert.pem",
#   "key_path":  "/etc/lexa/ev-server-key.pem",
#   "basic_auth_user": "...", "basic_auth_pass": "..."
# and point evsim at it:
#   evsim -csms wss://69.0.0.1:8887/ocpp -tls-ca certs/ca-cert.pem \
#         -auth-user ... -auth-pass ...
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
  -out "$VAULT/ev-server-key.pem"
chmod 600 "$VAULT/ev-server-key.pem"

# === Build SAN extension config ==============================================
cat > "$WORK/ev-ext.cnf" <<'EXTEOF'
basicConstraints = critical,CA:FALSE
keyUsage         = critical,digitalSignature,keyAgreement
extendedKeyUsage = serverAuth
subjectAltName   = @san
[san]
DNS.1 = localhost
IP.1  = 127.0.0.1
EXTEOF

# Append extra IPs/hostnames passed as arguments
IP_IDX=2
DNS_IDX=2
for name in "$@"; do
  if [[ "$name" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "IP.$IP_IDX  = $name" >> "$WORK/ev-ext.cnf"
    IP_IDX=$((IP_IDX + 1))
  else
    echo "DNS.$DNS_IDX = $name" >> "$WORK/ev-ext.cnf"
    DNS_IDX=$((DNS_IDX + 1))
  fi
done

echo "=== SAN config ==="
grep -A 20 '\[san\]' "$WORK/ev-ext.cnf"

# === CSR =====================================================================
openssl req -new \
  -key "$VAULT/ev-server-key.pem" \
  -out "$WORK/ev.csr" \
  -subj "/CN=csip-ev-csms"

# === Sign with production CA =================================================
openssl x509 -req \
  -in "$WORK/ev.csr" \
  -CA "$CERTS/ca-cert.pem" \
  -CAkey "$VAULT/ca-key.pem" \
  -CAcreateserial \
  -out "$CERTS/ev-server-cert.pem" \
  -days 365 \
  -extfile "$WORK/ev-ext.cnf" \
  -sha256

rm -f "$CERTS/ca-cert.srl"

echo
echo "=== Verify cert chain ==="
openssl verify -CAfile "$CERTS/ca-cert.pem" "$CERTS/ev-server-cert.pem"
openssl x509 -noout -subject -dates -ext subjectAltName -in "$CERTS/ev-server-cert.pem"

echo
echo "Output:"
echo "  cert: $CERTS/ev-server-cert.pem      (commit this)"
echo "  key:  $VAULT/ev-server-key.pem       (gitignored — stays in vault)"
echo
echo "Next: deploy to the hub and enable cert_path/key_path + basic auth in ocpp.json."
