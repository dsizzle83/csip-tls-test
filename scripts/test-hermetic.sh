#!/bin/bash
# The hermeticity gate: run the unit suite on a machine that HAS NO BENCH.
#
# Audit IW8-005 (2026-08-05): two suitessm unit tests were green on the desktop
# and red everywhere else, because they inherited certify.DefaultTargets' live
# bench addresses and the runner's preflight dialled 69.0.0.20:11114 before the
# first check ran. Nothing in the suite could tell you that: on the desktop the
# bench answers, so the leak was invisible exactly where it was introduced.
#
# Reading the tests is not a gate. THIS is the gate: an unprivileged network
# namespace with nothing in it but a loopback interface. 69.0.0.x is not
# unreachable-by-firewall here, it is unrouteable — a test that reaches for the
# lab gets ENETUNREACH in its first millisecond, wherever in the tree it lives
# and whatever idiom it used to get there. Loopback stays up, because hermetic
# means "stands up its own fixtures", not "does no I/O": the loopback servers
# every suite in this repo mints for itself must keep working.
#
# Usage:
#   scripts/test-hermetic.sh                  # the default hermetic package set
#   scripts/test-hermetic.sh ./internal/...   # a subset
#
# Requires unprivileged user namespaces (`unshare -rn`). Where they are
# disabled this exits 2 and says so, rather than reporting a pass it did not
# establish — a gate that silently degrades to "ran normally" is the same
# false reassurance it exists to remove.
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE"

if ! command -v unshare >/dev/null 2>&1; then
  echo "test-hermetic: unshare(1) is not installed, so the bench cannot be made" >&2
  echo "  unreachable and this gate cannot be run. Install util-linux, or run the" >&2
  echo "  suite on a host with no route to 69.0.0.0/24." >&2
  exit 2
fi
if ! unshare -rn true 2>/dev/null; then
  echo "test-hermetic: unprivileged user namespaces are disabled on this host" >&2
  echo "  (unshare -rn was refused), so the bench cannot be made unreachable and" >&2
  echo "  this gate cannot be run. Enable them, or run the suite on a host with" >&2
  echo "  no route to 69.0.0.0/24." >&2
  exit 2
fi

PKGS=("$@")
if [[ ${#PKGS[@]} -eq 0 ]]; then
  PKGS=(./...)
fi

# The wolfSSL sysroot, on the same terms as the Makefile — except that -lm has
# to come AFTER -lwolfssl for the static libwolfssl.a's dh.c (pow/log) to
# resolve. The Makefile's own ordering links fine for its targets and fails for
# a bare `go test ./...`, which is the documented gap (HANDOFF_2026-07-28 §2);
# it is written the working way here so this gate covers the WHOLE tree.
WOLFSSL_SYSROOT="${WOLFSSL_SYSROOT:-$HOME/.local/wolfssl-amd64}"
if [[ -d "$WOLFSSL_SYSROOT/include" ]]; then
  export CGO_CFLAGS="${CGO_CFLAGS:-} -I$WOLFSSL_SYSROOT/include"
  export CGO_LDFLAGS="${CGO_LDFLAGS:-} -L$WOLFSSL_SYSROOT/lib -lwolfssl -lm"
fi

# `go test -exec` is the whole trick: the toolchain COMPILES in the ordinary
# environment — module cache, build cache, and (on this desktop) a snap-confined
# go that cannot run inside a user namespace at all — and only the finished test
# BINARY is handed to the wrapper, which is what runs with no route off the box.
# Building inside the namespace would fail as "no network", which is exactly the
# symptom being hunted and therefore the one thing this gate must not be able to
# manufacture itself.
echo "== running the suite with NO ROUTE OFF THIS MACHINE =="
go test -count=1 -exec "$HERE/scripts/netns-exec.sh" "${PKGS[@]}"
rc=$?

if [[ $rc -eq 0 ]]; then
  echo "== HERMETIC: the suite passes with the lab unrouteable =="
else
  echo "== NOT HERMETIC (or a real failure): exit $rc ==" >&2
  echo "   A 'connect: network is unreachable' or a 69.0.0.x address in the output" >&2
  echo "   above is a test reaching for the bench. Give it local targets (see" >&2
  echo "   internal/certify/suitessm/helpers_test.go for the shape) or move it" >&2
  echo "   behind the //go:build integration tag this repo uses for bench work." >&2
fi
exit $rc
