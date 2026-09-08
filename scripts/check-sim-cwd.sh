#!/usr/bin/env bash
# check-sim-cwd.sh — REV0907-E5 (WP0-T3) regression guard, wired into
# `make test-fast`.
#
# A wolfSSL sysroot built with --enable-keylog-export ALSO writes its own
# ./sslkeylog.log into the process CWD (WOLFSSL_SSLKEYLOGFILE_OUTPUT is a
# compile-time constant, independent of the -keylog flag / SIMS_KEYLOG that
# internal/wolfssl/keylog.go uses — see .gitignore's note on this). Before
# 2026-09-08 the keylog sims (bin/server-keylog, bin/mbapsdev-keylog) that
# scripts/bench-sims-up.sh and scripts/lab/lab-sims-up.sh start were launched
# with cwd = the repo root, so a live bench run accumulated a multi-MB
# TLS-secret file at csip-tls-test/sslkeylog.log — gitignored, but one
# .gitignore edit from a leak.
#
# The fix: every launcher that can start a *-keylog sim binary runs that sim
# from a scratch directory OUTSIDE the repo, cd'ing into it only around the
# exec — see start() in either script above for the pattern:
#
#   rundir="$SIM_RUNDIR/..."
#   mkdir -p "$rundir" && chmod 0700 "$rundir"
#   ( cd "$rundir" && exec "$@" ) >"$LOG/$name.log" 2>&1 &
#
# This is a STATIC guard, not a runtime one — it does not build or start any
# sim (that needs a wolfSSL keylog sysroot this environment may not have). It
# finds every shell script under scripts/ that references a *-keylog sim
# BINARY (bin/<name>-keylog — the actual compiled artifact, not just the
# word "keylog" in prose: scripts/build-wolfssl-keylog-sysroot.sh mentions
# "keylog" throughout but never launches a sim, so it must not be flagged)
# and fails if that same file does not also contain the cwd-redirect guard
# immediately around a sim launch.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE"

# The launcher signal: a reference to the compiled *-keylog sim binary
# itself, under bin/ (as a default var assignment, an -x test, or a literal
# invocation) — not merely the word "keylog" appearing in a comment.
LAUNCHER_PATTERN='bin/[A-Za-z0-9_-]+-keylog'
# The guard signal: a subshell that cd's into a NON-REPO-ROOT variable
# directory and execs the sim there. The variable name is deliberately
# unconstrained ($rundir today) so a rename does not silently defeat this
# check, but the shape — cd into a var, "&&", exec — is exact.
GUARD_PATTERN='\(\s*cd\s+"\$[A-Za-z_][A-Za-z0-9_]*"\s*&&\s*exec\b'

# Exclude this checker's own file: its comments and pattern strings above
# necessarily spell out both LAUNCHER_PATTERN and GUARD_PATTERN literally, so
# it would otherwise "pass" itself by self-reference rather than by having an
# actual sim launch.
mapfile -t LAUNCHERS < <(grep -rlE "$LAUNCHER_PATTERN" --include='*.sh' scripts/ 2>/dev/null | grep -v '/check-sim-cwd\.sh$' || true)

if [ "${#LAUNCHERS[@]}" -eq 0 ]; then
  echo "check-sim-cwd: no scripts under scripts/ reference a bin/*-keylog sim binary — nothing to check."
  exit 0
fi

FAIL=0
for f in "${LAUNCHERS[@]}"; do
  if grep -qE "$GUARD_PATTERN" "$f"; then
    echo "  ok   $f"
  else
    echo "  FAIL $f — references a bin/*-keylog sim binary but has no"
    echo "       '( cd \"\$<rundir-var>\" && exec ... )' cwd guard around its sim launch."
    echo "       A keylog sim run with cwd=repo-root writes a live TLS-secret file"
    echo "       (sslkeylog.log) into the repo — REV0907-E5."
    FAIL=1
  fi
done

if [ "$FAIL" != 0 ]; then
  echo "check-sim-cwd: FAIL"
  exit 1
fi
echo "check-sim-cwd: OK (${#LAUNCHERS[@]} launcher(s) checked)"
