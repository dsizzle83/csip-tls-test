#!/bin/bash
# Generates the test certificate fixtures used by integration tests in
# the tlsserver and tlsclient packages. Both packages use the same
# certs, so we generate them once and copy into each package's
# testdata directory.
#
# Run: bash scripts/gen-test-certs.sh   (or `make gen-test-certs`)
set -euo pipefail

# Find the repo root regardless of where this script is invoked from.
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SERVER_CERTS="$REPO_ROOT/internal/tlsserver/testdata/certs"
CLIENT_CERTS="$REPO_ROOT/internal/tlsclient/testdata/certs"

WORK=$(mktemp -d)
trap "rm -rf $WORK" EXIT

mkdir -p "$WORK/certs"
CERTS="$WORK/certs"

# === Primary test CA ========================================================
openssl ecparam -name prime256v1 -genkey -noout -out $CERTS/ca-key.pem
openssl req -x509 -new -key $CERTS/ca-key.pem -days 3650 \
    -out $CERTS/ca-cert.pem \
    -subj "/CN=csip-tls-test Test CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -sha256

# === Server cert ============================================================
openssl ecparam -name prime256v1 -genkey -noout -out $CERTS/server-key.pem
openssl req -new -key $CERTS/server-key.pem -out $WORK/server.csr \
    -subj "/CN=csip-tls-test-server"

cat > $WORK/server-ext.cnf <<'EOF'
basicConstraints = critical,CA:FALSE
keyUsage         = critical,digitalSignature,keyAgreement
extendedKeyUsage = serverAuth
subjectAltName   = @san
[san]
DNS.1 = localhost
IP.1  = 127.0.0.1
EOF

openssl x509 -req -in $WORK/server.csr \
    -CA $CERTS/ca-cert.pem -CAkey $CERTS/ca-key.pem -CAcreateserial \
    -out $CERTS/server-cert.pem -days 365 \
    -extfile $WORK/server-ext.cnf -sha256

# === Good client cert =======================================================
openssl ecparam -name prime256v1 -genkey -noout -out $CERTS/client-key.pem
openssl req -new -key $CERTS/client-key.pem -out $WORK/client.csr \
    -subj "/CN=csip-tls-test-client"

cat > $WORK/client-ext.cnf <<'EOF'
basicConstraints = critical,CA:FALSE
keyUsage         = critical,digitalSignature
extendedKeyUsage = clientAuth
EOF

openssl x509 -req -in $WORK/client.csr \
    -CA $CERTS/ca-cert.pem -CAkey $CERTS/ca-key.pem -CAcreateserial \
    -out $CERTS/client-cert.pem -days 365 \
    -extfile $WORK/client-ext.cnf -sha256

# === Wrong CA + client signed by it (negative test fixture) ================
openssl ecparam -name prime256v1 -genkey -noout -out $CERTS/wrong-ca-key.pem
openssl req -x509 -new -key $CERTS/wrong-ca-key.pem -days 3650 \
    -out $CERTS/wrong-ca-cert.pem \
    -subj "/CN=Wrong Test CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -sha256

openssl ecparam -name prime256v1 -genkey -noout -out $CERTS/wrong-ca-client-key.pem
openssl req -new -key $CERTS/wrong-ca-client-key.pem -out $WORK/wrong.csr \
    -subj "/CN=rogue-client"

openssl x509 -req -in $WORK/wrong.csr \
    -CA $CERTS/wrong-ca-cert.pem -CAkey $CERTS/wrong-ca-key.pem -CAcreateserial \
    -out $CERTS/wrong-ca-client-cert.pem -days 365 \
    -extfile $WORK/client-ext.cnf -sha256

chmod 600 $CERTS/*-key.pem
rm -f $CERTS/ca-cert.srl $CERTS/wrong-ca-cert.srl

# Distribute to both package testdata dirs
mkdir -p "$SERVER_CERTS" "$CLIENT_CERTS"
cp $CERTS/*.pem "$SERVER_CERTS/"
cp $CERTS/*.pem "$CLIENT_CERTS/"

echo "✓ Test certs generated"
echo "  → $SERVER_CERTS"
echo "  → $CLIENT_CERTS"
ls -l "$SERVER_CERTS"
