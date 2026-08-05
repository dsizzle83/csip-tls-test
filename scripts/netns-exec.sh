#!/bin/bash
# netns-exec.sh — run one command in an unprivileged network namespace that has
# a working loopback and NO ROUTE ANYWHERE ELSE.
#
# It is written to be `go test -exec`'s wrapper (see scripts/test-hermetic.sh):
# go builds the test binary in the ordinary environment and then hands it here
# to be RUN, so the toolchain never has to work inside the namespace — which
# matters on hosts where go is a confined snap and cannot.
#
# Loopback comes UP deliberately. "Hermetic" in this repo means a suite stands
# up its own fixtures, not that it does no I/O: nearly every test here mints a
# PKI and dials its own listener on 127.0.0.1. What must be impossible is
# reaching the LAB.
set -uo pipefail
exec unshare -rn -- /bin/bash -c '
  ip link set lo up || {
    echo "netns-exec: could not raise loopback inside the namespace" >&2
    exit 2
  }
  exec "$@"
' -- "$@"
