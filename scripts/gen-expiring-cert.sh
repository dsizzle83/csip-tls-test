#!/bin/bash
# gen-expiring-cert.sh — mint a client cert with a controlled validity window
# (or a wrong-CA cert) to exercise lexa-hub's cert-expiry monitor
# (cmd/northbound/certmon.go) and staged cert-rotation (cmd/northbound/rotate.go),
# audit docs/QA_COMPLETENESS_AUDIT.md P2-1. The complement to
# scripts/gen-client-cert.sh (fixed 365-day validity) and scripts/cert-churn-soak.sh.
#
# Usage:
#   bash scripts/gen-expiring-cert.sh [--days N] [--expired] [--bad-ca]
#                                     [--cn CN] [--out NAME] [--dry-run]
#
#   --days N     near-expiry cert valid N days from now (default 20 — below the
#                hub's 30-day cert_expiry_warn_days ⇒ certmon logs WARN and sets
#                lexa_cert_expiring_client=1 immediately). N can be small (1).
#   --expired    already-expired cert (notAfter in 2020) ⇒ certmon logs ERROR and
#                sets the gauge. Uses `openssl ca` with explicit dates because
#                this OpenSSL (3.0) lacks x509 -not_before/-not_after (3.2+) and
#                faketime is not assumed present.
#   --bad-ca     sign with a THROWAWAY self-signed CA, not the bench CA ⇒ the hub
#                cannot handshake with it (wrong issuer) and its LFDI differs, so
#                a rotation onto it FAILS CLOSED (probe/LFDI refusal in rotate.go,
#                lexa_nb_cert_rotation_refusals_total). The safe way to drive the
#                fail-closed rotation path without ever installing a working-but-
#                wrong cert.
#   --cn CN      subject CN (default csip-test-der-001).
#   --out NAME   staging basename (default client-cert-expiring) → certs/client-staging/NAME.pem + NAME-key.pem.
#   --dry-run    print the openssl commands without running them or writing files.
#
# IMPORTANT — LFDI caveat (lexa-hub CLAUDE.md / docs/CERT_ROTATION_RUNBOOK.md):
# this codebase's LFDI hashes the FULL cert DER, so ANY freshly-signed cert — even
# same CN, same key — has a DIFFERENT LFDI than the enrolled device. rotate.go
# therefore REFUSES a fresh cert as re-enrollment (not rotation). That is by
# design and is exactly what the fail-closed rotation scenario asserts. To drive
# a CLEAN rotation you need a byte-identical copy of the LIVE cert (same DER, same
# LFDI) — that is what cert-churn-soak.sh does; it is NOT what this script is for.
# This script mints DISTINCT certs to drive (a) the expiry MONITOR (replace the
# live cert, restart lexa-northbound, watch certmon) and (b) the fail-closed
# rotation REFUSAL. Neither needs a matching LFDI.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CERTS="$REPO_ROOT/certs"
VAULT="$CERTS/vault"
STAGING="$CERTS/client-staging"

DAYS=20
EXPIRED=0
BAD_CA=0
CN="csip-test-der-001"
OUT="client-cert-expiring"
DRYRUN=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --days)    DAYS="$2"; shift 2 ;;
    --expired) EXPIRED=1; shift ;;
    --bad-ca)  BAD_CA=1; shift ;;
    --cn)      CN="$2"; shift 2 ;;
    --out)     OUT="$2"; shift 2 ;;
    --dry-run) DRYRUN=1; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

KEY="$STAGING/${OUT}-key.pem"
CERT="$STAGING/${OUT}.pem"

run() {
  if [[ "$DRYRUN" == "1" ]]; then
    printf '  %q ' "$@"; echo
  else
    "$@"
  fi
}

echo "== gen-expiring-cert: CN=$CN out=$OUT $( ((EXPIRED)) && echo '(expired)' || echo "(valid ${DAYS}d)" ) $( ((BAD_CA)) && echo '[wrong CA]' )"

if [[ "$DRYRUN" != "1" ]]; then
  mkdir -p "$STAGING"
fi

# 1. Key + CSR (always).
run openssl ecparam -name prime256v1 -genkey -noout -out "$KEY"
[[ "$DRYRUN" == "1" ]] || chmod 600 "$KEY"
CSR="$STAGING/${OUT}.csr"
run openssl req -new -key "$KEY" -out "$CSR" -subj "/CN=$CN"

# 2. Choose the signing CA.
if (( BAD_CA )); then
  # Throwaway self-signed CA — wrong issuer on purpose.
  BADCA_KEY="$STAGING/${OUT}-badca-key.pem"
  BADCA_CERT="$STAGING/${OUT}-badca.pem"
  run openssl ecparam -name prime256v1 -genkey -noout -out "$BADCA_KEY"
  run openssl req -new -x509 -key "$BADCA_KEY" -out "$BADCA_CERT" -days 3650 -subj "/CN=lexa-mayhem-wrong-ca"
  SIGN_CA_CERT="$BADCA_CERT"; SIGN_CA_KEY="$BADCA_KEY"
else
  if [[ ! -f "$VAULT/ca-key.pem" ]]; then
    echo "error: $VAULT/ca-key.pem not found — run the full cert setup first (or pass --bad-ca)." >&2
    exit 1
  fi
  SIGN_CA_CERT="$CERTS/ca-cert.pem"; SIGN_CA_KEY="$VAULT/ca-key.pem"
fi

EXT="$VAULT/client-ext.cnf"

# 3. Sign with the requested validity.
if (( EXPIRED )); then
  # openssl ca with explicit dates in the past (2020) → already-expired.
  # Build a throwaway CA db in a temp dir so we do not touch the vault's state.
  TMPCA="$(mktemp -d)"
  trap 'rm -rf "$TMPCA"' EXIT
  : > "$TMPCA/index.txt"
  echo 1000 > "$TMPCA/serial"
  cat > "$TMPCA/ca.cnf" <<CACNF
[ ca ]
default_ca = lexa_ca
[ lexa_ca ]
database = $TMPCA/index.txt
serial = $TMPCA/serial
new_certs_dir = $TMPCA
default_md = sha256
policy = pol_any
copy_extensions = copy
[ pol_any ]
commonName = supplied
CACNF
  run openssl ca -batch -config "$TMPCA/ca.cnf" \
    -cert "$SIGN_CA_CERT" -keyfile "$SIGN_CA_KEY" \
    -extfile "$EXT" \
    -startdate 20200101000000Z -enddate 20200201000000Z \
    -in "$CSR" -out "$CERT"
else
  run openssl x509 -req -in "$CSR" \
    -CA "$SIGN_CA_CERT" -CAkey "$SIGN_CA_KEY" -CAcreateserial \
    -out "$CERT" -days "$DAYS" -extfile "$EXT" -sha256
fi

# 4. Stage the CA the hub should trust alongside (the REAL bench CA — the point
#    of --bad-ca is a client cert the real CA did NOT sign, not a new trust root).
run cp "$CERTS/ca-cert.pem" "$STAGING/${OUT}-ca.pem"

if [[ "$DRYRUN" == "1" ]]; then
  echo "# dry-run — no files written"
  exit 0
fi

rm -f "$CSR" "$CERTS/ca-cert.srl" 2>/dev/null || true
echo
echo "=== Minted ==="
openssl x509 -noout -subject -issuer -dates -in "$CERT"
echo
echo "Staged: $CERT (+ ${OUT}-key.pem, ${OUT}-ca.pem) under $STAGING/"
echo
echo "Drive certmon (expiry): scp the cert/key onto the hub's live paths"
echo "  (/etc/lexa/certs/client.pem + client-key.pem), restart lexa-northbound,"
echo "  then watch /status cert_status + lexa_cert_expiring_client on :9102."
echo "Drive rotate.go (fail-closed): stage under a NEW path on the hub and write"
echo "  the rotation sentinel (see scripts on lexa-hub: rotate-cert.sh) — a"
echo "  different-LFDI/wrong-CA cert is REFUSED, old cert kept (the safe path)."
