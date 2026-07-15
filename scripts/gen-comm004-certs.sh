#!/bin/bash
# Generates the COMM-004 certificate-chain fixtures for the wolfSSL server-chain
# verification dry-run (VERIFICATION_SWEEP "COMM-004 D–G reject-path pcap
# procedure"). All material is air-gapped openssl, idempotent (re-run
# overwrites), and lands under certs/comm004/.
#
# The 7 COMM-004 scenarios put gridsim (the CSIP server) behind a series of
# certificate chains while the DUT (lexa-northbound, the CSIP client) verifies
# them against the SERCA root:
#
#   Accept (handshake completes, GET DeviceCapability → 200):
#     004A  depth 2  SERCA → server                (single leaf, serve with -cert)
#     004B  depth 3  SERCA → MICA → server         (serve with -cert-chain)
#     004C  depth 4  SERCA → MCA → MICA → server    (serve with -cert-chain)
#   Reject (client refuses the handshake — no HTTP bytes past the TLS Alert):
#     004D  MICA with Extended-Key-Usage marked CRITICAL on a CA cert
#     004E  MICA with Name-Constraints marked NON-critical (RFC 5280 wants critical)
#     004F  MICA with Policy-Mappings marked NON-critical (RFC 5280 wants critical)
#     004G  self-signed server leaf (no SERCA involvement)
#
# The exact X.509 malformations for 004D/E/F are the illustrative shapes from
# the VERIFICATION_SWEEP; reconcile against SunSpec's Test PKI hierarchy doc
# before treating them as authoritative for a lab campaign.
#
# Run: bash scripts/gen-comm004-certs.sh   (or `make gen-comm004-certs`)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CERTS="$REPO_ROOT/certs/comm004"
mkdir -p "$CERTS"

WORK=$(mktemp -d)
trap "rm -rf $WORK" EXIT
SERIAL="$WORK/serial.srl"

# Optional extra SAN IP (e.g. the bench desktop) — append with IPS="69.0.0.20".
EXTRA_IPS="${IPS:-69.0.0.20}"

# ── leaf extension config (shared by every server leaf) ─────────────────────
san_block() {
	local n=2
	echo "basicConstraints = critical,CA:FALSE"
	echo "keyUsage         = critical,digitalSignature,keyAgreement"
	echo "extendedKeyUsage = serverAuth"
	echo "subjectAltName   = @san"
	echo "[san]"
	echo "DNS.1 = localhost"
	echo "IP.1  = 127.0.0.1"
	for ip in $EXTRA_IPS; do
		echo "IP.$n = $ip"
		n=$((n + 1))
	done
}
san_block > "$WORK/leaf-ext.cnf"

# gen_leaf CN CA_CERT CA_KEY OUT_CERT OUT_KEY  — issue a TLS server leaf.
gen_leaf() {
	local cn="$1" ca="$2" cak="$3" out="$4" key="$5"
	openssl ecparam -name prime256v1 -genkey -noout -out "$key"
	openssl req -new -key "$key" -out "$WORK/leaf.csr" -subj "/CN=$cn"
	openssl x509 -req -in "$WORK/leaf.csr" -CA "$ca" -CAkey "$cak" \
		-CAserial "$SERIAL" -CAcreateserial -days 365 -sha256 \
		-out "$out" -extfile "$WORK/leaf-ext.cnf"
}

# gen_intermediate CN CA_CERT CA_KEY OUT_CERT OUT_KEY PATHLEN [EXTRA_EXT...]
#   Issue an intermediate CA cert. EXTRA_EXT lines are appended verbatim to the
#   extension file (used for the 004D/E/F malformations).
gen_intermediate() {
	local cn="$1" ca="$2" cak="$3" out="$4" key="$5" pathlen="$6"
	shift 6
	{
		echo "basicConstraints = critical,CA:TRUE,pathlen:$pathlen"
		echo "keyUsage         = critical,keyCertSign,cRLSign"
		local line
		for line in "$@"; do echo "$line"; done
	} > "$WORK/int-ext.cnf"
	openssl ecparam -name prime256v1 -genkey -noout -out "$key"
	openssl req -new -key "$key" -out "$WORK/int.csr" -subj "/CN=$cn"
	openssl x509 -req -in "$WORK/int.csr" -CA "$ca" -CAkey "$cak" \
		-CAserial "$SERIAL" -CAcreateserial -days 1825 -sha256 \
		-out "$out" -extfile "$WORK/int-ext.cnf"
}

# === SERCA root (pathlen 2 → allows SERCA → MCA → MICA → server, depth 4) ====
openssl ecparam -name prime256v1 -genkey -noout -out "$CERTS/serca-key.pem"
openssl req -x509 -new -key "$CERTS/serca-key.pem" -days 3650 -sha256 \
	-out "$CERTS/serca-cert.pem" \
	-subj "/CN=COMM-004 Test SERCA" \
	-addext "basicConstraints=critical,CA:TRUE,pathlen:2" \
	-addext "keyUsage=critical,keyCertSign,cRLSign"

# === 004A — depth 2: SERCA signs the server leaf directly (single cert) ======
gen_leaf "comm004-server-a" "$CERTS/serca-cert.pem" "$CERTS/serca-key.pem" \
	"$CERTS/004a-server-cert.pem" "$CERTS/004a-server-key.pem"

# === 004B — depth 3: SERCA → MICA → server (chain bundle) ====================
gen_intermediate "COMM-004 Test MICA" "$CERTS/serca-cert.pem" "$CERTS/serca-key.pem" \
	"$WORK/mica-cert.pem" "$WORK/mica-key.pem" 0
gen_leaf "comm004-server-b" "$WORK/mica-cert.pem" "$WORK/mica-key.pem" \
	"$WORK/004b-leaf.pem" "$CERTS/004b-server-key.pem"
cat "$WORK/004b-leaf.pem" "$WORK/mica-cert.pem" > "$CERTS/004b-server-chain.pem"

# === 004C — depth 4: SERCA → MCA → MICA → server (chain bundle) ==============
gen_intermediate "COMM-004 Test MCA" "$CERTS/serca-cert.pem" "$CERTS/serca-key.pem" \
	"$WORK/mca-cert.pem" "$WORK/mca-key.pem" 1
gen_intermediate "COMM-004 Test MICA (under MCA)" "$WORK/mca-cert.pem" "$WORK/mca-key.pem" \
	"$WORK/mica2-cert.pem" "$WORK/mica2-key.pem" 0
gen_leaf "comm004-server-c" "$WORK/mica2-cert.pem" "$WORK/mica2-key.pem" \
	"$WORK/004c-leaf.pem" "$CERTS/004c-server-key.pem"
cat "$WORK/004c-leaf.pem" "$WORK/mica2-cert.pem" "$WORK/mca-cert.pem" > "$CERTS/004c-server-chain.pem"

# === 004D — MICA with Extended-Key-Usage marked CRITICAL (invalid on a CA) ===
gen_intermediate "COMM-004 Test MICA (EKU-critical)" "$CERTS/serca-cert.pem" "$CERTS/serca-key.pem" \
	"$WORK/micad-cert.pem" "$WORK/micad-key.pem" 0 \
	"extendedKeyUsage = critical,serverAuth"
gen_leaf "comm004-server-d" "$WORK/micad-cert.pem" "$WORK/micad-key.pem" \
	"$WORK/004d-leaf.pem" "$CERTS/004d-server-key.pem"
cat "$WORK/004d-leaf.pem" "$WORK/micad-cert.pem" > "$CERTS/004d-server-chain.pem"

# === 004E — MICA with Name-Constraints marked NON-critical ===================
#   RFC 5280 §4.2.1.10: nameConstraints MUST be critical when present.
gen_intermediate "COMM-004 Test MICA (NC-noncritical)" "$CERTS/serca-cert.pem" "$CERTS/serca-key.pem" \
	"$WORK/micae-cert.pem" "$WORK/micae-key.pem" 0 \
	"nameConstraints = permitted;DNS:.comm004.test"
gen_leaf "comm004-server-e" "$WORK/micae-cert.pem" "$WORK/micae-key.pem" \
	"$WORK/004e-leaf.pem" "$CERTS/004e-server-key.pem"
cat "$WORK/004e-leaf.pem" "$WORK/micae-cert.pem" > "$CERTS/004e-server-chain.pem"

# === 004F — MICA with Policy-Mappings marked NON-critical ====================
#   RFC 5280 §4.2.1.5: policyMappings SHOULD be critical; here left non-critical.
gen_intermediate "COMM-004 Test MICA (PM-noncritical)" "$CERTS/serca-cert.pem" "$CERTS/serca-key.pem" \
	"$WORK/micaf-cert.pem" "$WORK/micaf-key.pem" 0 \
	"certificatePolicies = 1.3.6.1.4.1.99999.1.1" \
	"policyMappings       = 1.3.6.1.4.1.99999.1.1:1.3.6.1.4.1.99999.2.1"
gen_leaf "comm004-server-f" "$WORK/micaf-cert.pem" "$WORK/micaf-key.pem" \
	"$WORK/004f-leaf.pem" "$CERTS/004f-server-key.pem"
cat "$WORK/004f-leaf.pem" "$WORK/micaf-cert.pem" > "$CERTS/004f-server-chain.pem"

# === 004G — self-signed server leaf (no SERCA at all) ========================
# Build the SAN as a single -addext string (matches the SERCA root's -addext
# style; avoids a config-section for one cert).
SAN_ADDEXT="subjectAltName=DNS:localhost,IP:127.0.0.1"
for ip in $EXTRA_IPS; do SAN_ADDEXT="$SAN_ADDEXT,IP:$ip"; done
openssl ecparam -name prime256v1 -genkey -noout -out "$CERTS/004g-server-key.pem"
openssl req -x509 -new -key "$CERTS/004g-server-key.pem" -days 365 -sha256 \
	-out "$CERTS/004g-server-cert.pem" \
	-subj "/CN=comm004-server-g-selfsigned" \
	-addext "basicConstraints=critical,CA:FALSE" \
	-addext "keyUsage=critical,digitalSignature,keyAgreement" \
	-addext "extendedKeyUsage=serverAuth" \
	-addext "$SAN_ADDEXT"

chmod 600 "$CERTS"/*-key.pem
rm -f "$CERTS"/*.srl

echo "✓ COMM-004 fixtures generated under $CERTS"
echo "  root (client-trusted CA): serca-cert.pem"
echo "  accept: 004a-server-cert.pem (-cert) · 004b/004c-server-chain.pem (-cert-chain)"
echo "  reject: 004d/004e/004f-server-chain.pem (-cert-chain) · 004g-server-cert.pem (-cert)"
ls -1 "$CERTS"
