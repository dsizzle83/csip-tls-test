#!/bin/bash
# Generates the bench's committed Secure SunSpec Modbus (mbaps) PKI tree
# under certs/mbaps/ (T06.1): a two-tier CA (root + intermediate), one
# role-bearing client leaf per mandatory + vendor mbaps role, a device
# server leaf for sim/mbapsdev, and the negative-fixture matrix (no-role,
# two-role, bad-encoding, empty-role, oversize-role, expired, wrong-ca).
#
# The actual minting logic lives in cmd/gen-mbaps-certs (Go, stdlib-only —
# see that package's doc comment for why it is deliberately cgo-free and
# does not import internal/mbtls or any product-side tooling, T06 PN-1 /
# T00 ruling C9). This script is a thin, repo-root-relative wrapper, in the
# same spirit as the other scripts/gen-*.sh generators.
#
# Run: bash scripts/gen-mbaps-certs.sh   (or `make gen-mbaps-certs`)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# GOWORK=off: this repo's go.work (dev overlay onto a live lexa-proto
# checkout) is developer-local and gitignored; the generator must build
# against the pinned vendor/lexa-proto tree like any other bench command
# (CLAUDE.md proto.pin convention).
GOWORK=off go run ./cmd/gen-mbaps-certs -out certs/mbaps "$@"
