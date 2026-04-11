#!/bin/bash
# Generates a client cert for a DER device, signed by the existing
# production CA in certs/vault/. Run from the repo root.
#
# Usage:
#   bash scripts/gen-client-cert.sh [CN]
#
#   CN defaults to "csip-test-der-001". Override for each device:
#     bash scripts/gen-client-cert.sh csip-pi-001
#
# Output: certs/client-staging/{ca-cert,client-cert,client-key}.pem
# After SCP'ing client-staging/ to the device, delete it from WSL:
#   rm -rf certs/client-staging
#
# The CA and server certs are NOT touched — only new client material
# is generated. To issue a second device cert, run this script again
# with a different CN.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CERTS="$REPO_ROOT/certs"
VAULT="$CERTS/vault"
STAGING="$CERTS/client-staging"
CN="${1:-csip-test-der-001}"

if [[ ! -f "$VAULT/ca-key.pem" ]]; then
  echo "error: $VAULT/ca-key.pem not found." >&2
  echo "The production CA does not exist yet. Run the full cert setup first." >&2
  exit 1
fi

rm -rf "$STAGING"
mkdir -p "$STAGING"

# === Client private key ================================================
openssl ecparam -name prime256v1 -genkey -noout \
  -out "$STAGING/client-key.pem"
chmod 600 "$STAGING/client-key.pem"

# === CSR (intermediate, deleted below) =================================
openssl req -new \
  -key "$STAGING/client-key.pem" \
  -out "$VAULT/client.csr" \
  -subj "/CN=$CN"

# === Sign with existing production CA ==================================
openssl x509 -req \
  -in "$VAULT/client.csr" \
  -CA "$CERTS/ca-cert.pem" \
  -CAkey "$VAULT/ca-key.pem" \
  -CAcreateserial \
  -out "$STAGING/client-cert.pem" \
  -days 365 \
  -extfile "$VAULT/client-ext.cnf" \
  -sha256

# Clean up CSR and serial — not needed after signing
rm -f "$VAULT/client.csr" "$CERTS/ca-cert.srl"

# Client also needs the CA cert to verify the server
cp "$CERTS/ca-cert.pem" "$STAGING/ca-cert.pem"

# The public cert goes directly into certs/ so it can be committed and
# cloned to devices without a separate SCP. Only the key stays in staging.
cp "$STAGING/client-cert.pem" "$CERTS/client-cert.pem"

echo
echo "=== Verify cert chain ==="
openssl verify -CAfile "$CERTS/ca-cert.pem" "$STAGING/client-cert.pem"
openssl x509 -noout -subject -issuer -dates -in "$STAGING/client-cert.pem"

echo
echo "=== Client staging (SCP to the Pi, then DELETE from WSL) ==="
ls -l "$STAGING/"
echo
echo "Next steps:"
echo "  1. Commit certs/client-cert.pem (public — safe to track):"
echo "     git add $CERTS/client-cert.pem && git commit -m 'add client cert'"
echo "  2. SCP only the private key to the Pi:"
echo "     scp $STAGING/client-key.pem dmitri@192.168.0.81:~/csip-tls-test/certs/"
echo "  3. Delete staging from WSL:"
echo "     rm -rf $STAGING"
