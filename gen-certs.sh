#!/bin/bash
set -euo pipefail

# Run from ~/csip-tls-test
CERTS=./certs
VAULT=$CERTS/vault
CLIENT_OUT=$CERTS/client-staging

# Wipe and recreate
rm -rf $CERTS
mkdir -p $CERTS $VAULT $CLIENT_OUT

# === Root CA ===========================================================
# CA private key — lives in vault forever, never deployed to any machine
openssl ecparam -name prime256v1 -genkey -noout -out $VAULT/ca-key.pem
chmod 600 $VAULT/ca-key.pem

# CA self-signed cert — needed by both server and client at runtime
openssl req -x509 -new -key $VAULT/ca-key.pem -days 3650 \
  -out $CERTS/ca-cert.pem \
  -subj "/CN=CSIP Test Root CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash"

# === Server cert =======================================================
openssl ecparam -name prime256v1 -genkey -noout -out $CERTS/server-key.pem
chmod 600 $CERTS/server-key.pem

openssl req -new -key $CERTS/server-key.pem \
  -out $VAULT/server.csr \
  -subj "/CN=csip-test-server"

# Server SAN must include every name/IP a client might connect to.
# Add more entries here if you want to test from other machines.
cat > $VAULT/server-ext.cnf <<'EOF'
basicConstraints       = critical,CA:FALSE
keyUsage               = critical,digitalSignature,keyAgreement
extendedKeyUsage       = serverAuth
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
subjectAltName         = @san

[san]
DNS.1 = csip-test-server
DNS.2 = localhost
IP.1  = 192.168.0.188
IP.2  = 127.0.0.1
EOF

openssl x509 -req -in $VAULT/server.csr \
  -CA $CERTS/ca-cert.pem -CAkey $VAULT/ca-key.pem -CAcreateserial \
  -out $CERTS/server-cert.pem -days 365 \
  -extfile $VAULT/server-ext.cnf \
  -sha256

# === Client cert (DER device) ==========================================
openssl ecparam -name prime256v1 -genkey -noout -out $CLIENT_OUT/client-key.pem
chmod 600 $CLIENT_OUT/client-key.pem

openssl req -new -key $CLIENT_OUT/client-key.pem \
  -out $VAULT/client.csr \
  -subj "/CN=csip-test-der-001"

cat > $VAULT/client-ext.cnf <<'EOF'
basicConstraints       = critical,CA:FALSE
keyUsage               = critical,digitalSignature
extendedKeyUsage       = clientAuth
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
EOF

openssl x509 -req -in $VAULT/client.csr \
  -CA $CERTS/ca-cert.pem -CAkey $VAULT/ca-key.pem -CAcreateserial \
  -out $CLIENT_OUT/client-cert.pem -days 365 \
  -extfile $VAULT/client-ext.cnf \
  -sha256

# Client also needs the CA cert to verify the server
cp $CERTS/ca-cert.pem $CLIENT_OUT/ca-cert.pem

# Cleanup intermediate CSRs and serial
rm -f $VAULT/server.csr $VAULT/client.csr $CERTS/ca-cert.srl

echo
echo "=========================================================="
echo "Runtime files for the SERVER (loaded by your Go server):"
ls -l $CERTS/*.pem
echo
echo "Vault (offline only, never deploy, used to issue more certs later):"
ls -l $VAULT/
echo
echo "Client staging (SCP to the Pi, then DELETE from WSL):"
ls -l $CLIENT_OUT/
echo "=========================================================="