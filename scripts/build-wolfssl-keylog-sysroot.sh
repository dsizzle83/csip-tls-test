#!/bin/bash
# build-wolfssl-keylog-sysroot.sh — build the bench's KEYLOG-ENABLED wolfSSL
# sysroot, used only by the conformance-evidence binaries.
#
# WHY A SECOND SYSROOT
#
# The conformance demonstration tool captures packets while it drives the
# gateway, and an encrypted capture only proves handshake-layer facts. To also
# prove application-layer conformance (the Modbus PDUs, the 2030.5 exchanges,
# the register values the DUT actually returned) the capture has to be
# decryptable, which means the bench must export its own TLS session secrets in
# NSS key-log format (internal/wolfssl/keylog.go).
#
# That needs wolfSSL built with --enable-keylog-export (HAVE_SECRET_CALLBACK).
# Rather than turn secret export on in the sysroot every other bench binary
# links, this builds a SEPARATE prefix. The stock sysroot is left exactly as it
# was, so:
#
#   - ordinary builds cannot leak session keys even by accident;
#   - the evidence binaries are visibly, deliberately different (they need both
#     this sysroot AND `-tags keylog`; either alone is a compile error or a
#     loud runtime failure — see internal/wolfssl/keylog_stub.go).
#
# The product's own TLS stack (lexa-platform/mbedtls, on the gateway) is NOT
# given key export. Every session the bench captures has the bench as one of
# its two endpoints, so the bench side's secrets are sufficient — nothing has
# to be extracted from the device under test, and the device that ships is the
# device that was measured.
#
# USAGE
#   scripts/build-wolfssl-keylog-sysroot.sh [prefix]
#     prefix defaults to ~/.local/wolfssl-amd64-keylog
#
# Then build evidence binaries with:
#   CGO_CFLAGS="-I<prefix>/include" \
#   CGO_LDFLAGS="-L<prefix>/lib -lwolfssl -lm" \
#   go build -tags keylog ./...
#
# Needs: curl or wget, tar, a C toolchain, make.
set -euo pipefail

VERSION="5.7.6-stable"
# Pinned to match the stock sysroot's manifest so the two differ ONLY in the
# keylog flag — an evidence run must exercise the same TLS code the rest of the
# bench does, or it is measuring a different implementation.
TARBALL_SHA256="52b1e439e30d1ed8162a16308a8525a862183b67aa30373b11166ecbab000d63"
TARBALL_URL="https://github.com/wolfSSL/wolfssl/archive/refs/tags/v${VERSION}.tar.gz"

PREFIX="${1:-$HOME/.local/wolfssl-amd64-keylog}"
WORK="${WOLFSSL_KEYLOG_WORKDIR:-/tmp/wolfssl-keylog-build}"
SRC="$WORK/wolfssl-$VERSION"

echo "wolfSSL keylog sysroot"
echo "  version: $VERSION"
echo "  prefix:  $PREFIX"
echo "  workdir: $WORK"

mkdir -p "$WORK"
cd "$WORK"

if [[ ! -d "$SRC" ]]; then
  TARBALL="$WORK/wolfssl-$VERSION.tar.gz"
  if [[ ! -f "$TARBALL" ]]; then
    echo "fetching $TARBALL_URL"
    if command -v curl >/dev/null; then curl -fsSL -o "$TARBALL" "$TARBALL_URL"
    else wget -qO "$TARBALL" "$TARBALL_URL"; fi
  fi
  got=$(sha256sum "$TARBALL" | awk '{print $1}')
  if [[ "$got" != "$TARBALL_SHA256" ]]; then
    echo "ERROR: tarball sha256 mismatch" >&2
    echo "  want $TARBALL_SHA256" >&2
    echo "  got  $got" >&2
    exit 1
  fi
  tar -xzf "$TARBALL" -C "$WORK"
fi

BUILD="$WORK/build"
rm -rf "$BUILD"; mkdir -p "$BUILD"; cd "$BUILD"

# --enable-ticket-nonce-malloc is REQUIRED for interop, not a preference. Without
# it wolfSSL caps ticket_nonce at TLS13_TICKET_NONCE_STATIC_SZ = 8 bytes
# (wolfssl/internal.h) and DoTls13NewSessionTicket returns INVALID_PARAMETER ->
# alert 47 illegal_parameter. RFC 8446 4.6.1 allows ticket_nonce<0..255>, and
# mbed TLS sends 32 -- so a stock-built referee ABORTS every session with the
# product the moment the gateway issues a session ticket, which it does by
# default (mbaps.json session_cache: true). That looked like a gateway defect
# for several rounds on 2026-07-27; it is a harness build limitation. The stock
# sysroot needs this flag too.
#
# Flags are the stock sysroot's configure_flags (see
# ~/.local/wolfssl-amd64/wolfssl-sysroot-manifest.txt) PLUS --enable-keylog-export.
# Keep this list in lockstep with the stock builder: a divergence here means the
# evidence runs and the ordinary runs are exercising different TLS builds.
"$SRC/configure" --prefix="$PREFIX" \
  --enable-tls13 \
  --enable-aesccm \
  --enable-tlsx \
  --enable-certgen \
  --enable-opensslall \
  --enable-maxfragment \
  --enable-secure-renegotiation \
  --enable-session-ticket \
  --enable-cryptocb \
  --enable-sessioncerts \
  --enable-keylog-export \
  --enable-ticket-nonce-malloc \
  --enable-static \
  --disable-shared \
  --disable-examples \
  --disable-crypttests \
  --enable-reproducible-build

make -j"$(nproc)"
make install

# Fail loudly if the flag did not take: a sysroot that silently lacks the
# callback produces captures nobody can decrypt, discovered only at analysis
# time when the evidence is already stale.
if ! grep -q "define HAVE_SECRET_CALLBACK" "$PREFIX/include/wolfssl/options.h"; then
  echo "ERROR: HAVE_SECRET_CALLBACK not defined in the installed options.h" >&2
  exit 1
fi
# Same reasoning, different failure mode: without the nonce-malloc macro the
# referee cannot talk to the product at all once a ticket is issued, and the
# symptom (alert 47 mid-session, after a clean handshake) reads as a DUT fault.
if ! grep -q "define WOLFSSL_TICKET_NONCE_MALLOC" "$PREFIX/include/wolfssl/options.h"; then
  echo "ERROR: WOLFSSL_TICKET_NONCE_MALLOC not defined — this sysroot would reject" >&2
  echo "       mbed TLS's 32-byte ticket_nonce with illegal_parameter" >&2
  exit 1
fi

cat > "$PREFIX/wolfssl-sysroot-manifest.txt" <<EOF
wolfssl_version: $VERSION
tarball_sha256: $TARBALL_SHA256
tarball_url: $TARBALL_URL
arch: amd64
variant: keylog (bench evidence only — exports TLS session secrets)
built_by: scripts/build-wolfssl-keylog-sysroot.sh
EOF

echo
echo "OK: $PREFIX"
grep -E "define (HAVE_SECRET_CALLBACK|WOLFSSL_SSLKEYLOGFILE)" \
  "$PREFIX/include/wolfssl/options.h" | sed 's/^/  /'
