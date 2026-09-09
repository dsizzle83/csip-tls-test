#!/usr/bin/env bash
# check-live-set.sh — WP7-T1 (REV0907-E1/H8/E10), wired into `make live-set-check`
# (and, at the end, into `make test-certify` itself).
#
# The certify live set (Makefile's CERTIFY_LIVE_SET) is a COMMITTED snapshot
# of `go list -deps ./cmd/certify ./cmd/gw-campaign`: every package this
# repo's own conformance tool and continuous-adversary campaign engine can
# actually import at build time. ci.yml's new `referee` job and cgo-fast's
# `make test-certify` + tlsprobe/mbtls step are wired against that snapshot,
# not against a fresh `go list` on every run — a snapshot is reviewable in a
# diff and gives a stable, printable "this is what CI covers" answer, but it
# can silently go stale the moment an import changes. This script is the
# check that catches that: it fails loud, with a diff, the moment the
# committed CERTIFY_LIVE_SET and a fresh `go list -deps` disagree, instead of
# CI quietly under- or over-covering the live set forever after.
#
# GOWORK=off: a developer's untracked local go.work (dev overlay onto a live
# ../lexa-proto checkout — see scripts/gen-mbaps-certs.sh's header) must not
# change which packages the SHIPPED binaries resolve to; hosted CI never has
# one, so this is a no-op there and only matters for a correct desktop run.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE"

ACTUAL="$(GOWORK=off GOFLAGS=-mod=vendor go list -deps ./cmd/certify ./cmd/gw-campaign | grep '^csip-tls-test/' | sort -u)"
# --no-print-directory: under a nested make (test-certify -> live-set-check),
# make prints "make[2]: Entering/Leaving directory" lines to STDOUT even with
# -s unless MAKEFLAGS carries it, and those lines polluted the snapshot in CI
# (first hosted run of this gate, 2026-09-08) while passing locally.
COMMITTED="$(make -s --no-print-directory live-set-committed)"

if [[ "$ACTUAL" != "$COMMITTED" ]]; then
  echo "live-set-check: FAIL — Makefile's CERTIFY_LIVE_SET has drifted from" >&2
  echo "'go list -deps ./cmd/certify ./cmd/gw-campaign'." >&2
  echo >&2
  echo "--- diff (< committed in Makefile, > actual from go list) ---" >&2
  diff <(echo "$COMMITTED") <(echo "$ACTUAL") >&2 || true
  echo >&2
  echo "Regenerate: run 'make live-set-print', paste its output into" >&2
  echo "CERTIFY_LIVE_SET in the Makefile, then re-check whether the" >&2
  echo "added/removed package needs its own wiring in .github/workflows/ci.yml" >&2
  echo "(a package landing in internal/mbtls- or internal/tlsprobe-shape — cgo," >&2
  echo "real wolfSSL — belongs in cgo-fast next to those two, not referee's" >&2
  echo "CGO_ENABLED=0 step; see the CERTIFY_LIVE_SET comment in the Makefile)." >&2
  exit 1
fi

echo "live-set-check: OK — CERTIFY_LIVE_SET matches 'go list -deps ./cmd/certify ./cmd/gw-campaign' ($(echo "$ACTUAL" | wc -l) packages)."
