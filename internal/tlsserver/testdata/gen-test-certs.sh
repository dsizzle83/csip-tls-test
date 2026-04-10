#!/bin/bash
# Generates the test certificate fixtures used by integration tests in
# the tlsserver package. These are deliberately isolated from the
# production cert vault at ~/csip-tls-test/certs/ — different CA,
# different filenames, different scope.
#
# Run this once after cloning, or whenever you want to refresh the
# fixtures. The Makefile target `make gen-test-certs` does the same thing.
set -euo pipefail

cd "$(dirname "$0")"
CERTS=./certs
WORK=$(mktemp -d)
trap "rm -rf $WORK" EXIT

mkdir -p $CERTS

# === Primary test CA ========================================================
openssl ecparam -name prime256v1 -genkey -noout -out $CERTS/ca-key.pem
openssl req -x509 -new -key $CERTS/ca-key.pem -days 3650 \
    -out $CERTS/ca-cert.pem \
    -subj "/CN=tlsserver Test CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -sha256

# === Server cert ============================================================
openssl ecparam -name prime256v1 -genkey -noout -out $CERTS/server-key.pem
openssl req -new -key $CERTS/server-key.pem -out $WORK/server.csr \
    -subj "/CN=tlsserver-test"

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

# === Good client cert (signed by primary CA) ===============================
openssl ecparam -name prime256v1 -genkey -noout -out $CERTS/client-key.pem
openssl req -new -key $CERTS/client-key.pem -out $WORK/client.csr \
    -subj "/CN=tlsserver-test-client"

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
# This is a completely separate CA used to test that the server rejects
# client certs not signed by the trusted CA.
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

echo "✓ Test certs generated in $CERTS/"
ls -l $CERTS/
