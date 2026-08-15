#!/bin/bash
# TASK-024: CI shared-module version-pinning gate (AD-003(c)).
#
# NOTE 2026-08-03: lexa-hub is ABANDONED (product decision: single-product
# focus on lexa-gw; checkout archived off-disk, see ~/projects/archives/).
# Everything below through roughly line 60 documents the original two-
# consumer (csip-tls-test/lexa-hub) design and its CI wiring as history — it
# is left as written, not rewritten, so the design record stays intact. What
# actually changed: the peer set is now csip-tls-test + lexa-gw, the
# --product default below points at ../lexa-gw, and a missing --product peer
# is now an informational skip rather than a hard failure (a machine that
# only has this one checkout is a legitimate configuration, same reasoning
# lexa-gw's own scripts/check-proto-pin.sh already applies to its --peer
# array).
#
# Replaces TASK-004's raw-diff lockstep gate (scripts/ci/lockstep-check.sh,
# now deleted): that script byte-diffed internal/southbound/sunspec and
# internal/ocppserver between this repo and lexa-hub while both trees still
# existed in-repo. TASK-020-023 extracted every shared package into the
# `lexa-proto` module (sunspec, derbase, modbus, ocppserver, csipmodel) —
# there is nothing left for a tree-diff to compare, so a report of "0
# divergences" would be green by vacuity, not by lockstep. The real question
# now is: do the two consumer repos (csip-tls-test, lexa-hub) require the
# SAME lexa-proto commit?
#
# Pinning mechanism (AD-003(c)): `lexa-proto` is not hosted yet (no GitHub
# repo under dsizzle83/lexa-proto, no fetch credential in any CI runner —
# same class of gap as AD-012's branch-protection blocker). The go.mod
# pseudo-version mechanism (`require lexa-proto vX.Y.Z-<ts>-<sha>` compared
# between the two consumers' go.mod files) is the intended long-run
# replacement for this script but CANNOT work until lexa-proto is fetchable.
# Until then, each consumer repo commits a `proto.pin` file at its root
# holding the required lexa-proto commit SHA (one line). This script:
#
#   (a) Compares the two consumer repos' `proto.pin` files. Mismatch fails —
#       this is the check that actually runs in hosted CI, on every PR, in
#       both repos (csip-tls-test AND lexa-hub — TASK-004 only gated the
#       csip-tls-test side, which is exactly the "asymmetric bump" failure
#       mode TASK-024 closes).
#   (b) IF a local `lexa-proto` checkout is available (developer machines,
#       and any CI runner that has been given one — no hosted runner has
#       this today, see below) — verifies that checkout resolves the pinned
#       SHA to a real commit, and that its checked-out HEAD matches it.
#       Gracefully degrades (warns, does not fail) when no local checkout
#       exists, which is hosted CI's normal case today.
#   (c) With --verify-vendor (opt-in, local/desktop only: needs a `go`
#       toolchain AND a local lexa-proto checkout) — regenerates
#       vendor/lexa-proto/* from the pinned SHA in a scratch copy and diffs
#       it against the committed vendor/ tree (AD-003(e) interim vendoring:
#       both consumers commit `require lexa-proto v0.0.0` + `replace
#       lexa-proto => ../lexa-proto` + a committed vendor/lexa-proto/ tree,
#       so hosted CI can build without ever fetching lexa-proto). This
#       catches "pin bumped but vendor/ wasn't regenerated" and "vendor/
#       hand-edited" — neither (a) nor (b) can see either of those.
#
# Cross-repo visibility (same shape as TASK-004's lockstep job): both repos
# are private under one owner, so the default GITHUB_TOKEN can't read the
# peer repo. csip-tls-test's CI job checks out lexa-hub via the existing
# `LEXA_HUB_RO_TOKEN` secret (fine-grained PAT, read-only contents,
# lexa-hub-only — TASK-004). lexa-hub's CI job checks out csip-tls-test via
# a NEW secret, `CSIP_TLS_TEST_RO_TOKEN` (same shape, csip-tls-test-only) —
# this is a new human-dependency item, not yet created, same class of gap as
# LEXA_HUB_RO_TOKEN and AD-012 branch protection. Until it exists, lexa-hub's
# proto-pin job fails at the checkout step, not on an actual pin mismatch —
# check the failure message before assuming drift (identical caveat to
# TASK-004's lockstep job).
#
# This script is the single implementation (lives only in csip-tls-test);
# lexa-hub's CI job checks out csip-tls-test (the token above) and invokes
# THIS copy of the script from that checkout, passing --self/--product so it
# knows which side is which regardless of which repo it's physically running
# in.
#
# Usage:
#   scripts/check-proto-pin.sh [--self <path>] [--product <path>]
#                               [--proto <path-to-lexa-proto>]
#                               [--no-proto-check] [--verify-vendor]
#
#   --self <path>      Path to "this side" of the pin comparison. Default:
#                       this script's own repo root (works out of the box
#                       when run in csip-tls-test).
#   --product <path>   Path to the peer consumer repo. Default: `../lexa-gw`
#                       if --self's basename isn't "lexa-gw", else
#                       `../csip-tls-test` — i.e. "the other one" under the
#                       normal sibling-checkout layout (lexa-hub, the
#                       original other peer, was abandoned 2026-08-03 — see
#                       the note atop this file). CI always passes this
#                       explicitly (the checked-out subdirectory). A missing
#                       peer is an informational skip, not a failure.
#   --proto <path>     Path to a local lexa-proto checkout, for the (b)/(c)
#                       checks. Default: ../lexa-proto relative to --self.
#   --no-proto-check   Skip (b)/(c) entirely even if --proto exists (fast
#                       path: pin-vs-pin only).
#   --verify-vendor     Run the (c) deep vendor-regeneration diff. Requires a
#                       `go` toolchain and a real --proto checkout. Slow;
#                       intended for desktop/local runs, not every CI job.
#
# Exit codes: 0 = pins match, or no peer was found to compare against (an
# informational skip, 2026-08-03 -- see the note atop this file), and, unless
# skipped/unavailable, (b) and any requested (c) check pass too. 1 = pin
# mismatch, malformed proto.pin (self or a found peer), (b) mismatch, or (c)
# diff found. 2 = usage error.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_SELF="$(cd "$SCRIPT_DIR/.." && pwd)"

SELF="$DEFAULT_SELF"
PRODUCT=""
PROTO=""
NO_PROTO_CHECK=0
VERIFY_VENDOR=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --self)
      [[ $# -ge 2 ]] || { echo "check-proto-pin: --self needs a path argument" >&2; exit 2; }
      SELF="$2"; shift 2 ;;
    --product)
      [[ $# -ge 2 ]] || { echo "check-proto-pin: --product needs a path argument" >&2; exit 2; }
      PRODUCT="$2"; shift 2 ;;
    --proto)
      [[ $# -ge 2 ]] || { echo "check-proto-pin: --proto needs a path argument" >&2; exit 2; }
      PROTO="$2"; shift 2 ;;
    --no-proto-check)
      NO_PROTO_CHECK=1; shift ;;
    --verify-vendor)
      VERIFY_VENDOR=1; shift ;;
    -h|--help)
      sed -n '2,75p' "${BASH_SOURCE[0]}"
      exit 0 ;;
    *)
      echo "check-proto-pin: unknown argument: $1" >&2
      exit 2 ;;
  esac
done

[[ -d "$SELF" ]] || { echo "check-proto-pin: --self path not found: $SELF" >&2; exit 2; }
SELF="$(cd "$SELF" && pwd)"

if [[ -z "$PRODUCT" ]]; then
  if [[ "$(basename "$SELF")" == "lexa-gw" ]]; then
    PRODUCT="$SELF/../csip-tls-test"
  else
    PRODUCT="$SELF/../lexa-gw"
  fi
fi

# A missing peer is an INFORMATIONAL skip, not a failure (2026-08-03): with
# lexa-hub abandoned and archived off-disk, a checkout that only has this one
# repo is a normal, legitimate configuration -- not evidence of drift. Same
# reasoning lexa-gw's own scripts/check-proto-pin.sh already applies to an
# empty --peer set. SELF's own proto.pin is still read and validated below
# either way.
PRODUCT_FOUND=1
if [[ ! -d "$PRODUCT" ]]; then
  PRODUCT_FOUND=0
else
  PRODUCT="$(cd "$PRODUCT" && pwd)"
fi

if [[ -z "$PROTO" ]]; then
  PROTO="$SELF/../lexa-proto"
fi

read_pin() {
  local dir="$1" label="$2" file
  file="$dir/proto.pin"
  if [[ ! -f "$file" ]]; then
    echo "check-proto-pin: no proto.pin at $file ($label)" >&2
    exit 1
  fi
  local n
  n="$(wc -l < "$file" | tr -d '[:space:]')"
  # Allow a file with or without a trailing newline (both count as "one line"
  # of content); reject anything with more than one non-empty line.
  local nonblank
  nonblank="$(grep -vc '^[[:space:]]*$' "$file" || true)"
  if [[ "$nonblank" -ne 1 ]]; then
    echo "check-proto-pin: $file ($label) must contain exactly one non-blank line (a single lexa-proto commit SHA)" >&2
    exit 1
  fi
  local sha
  sha="$(grep -v '^[[:space:]]*$' "$file" | head -n1 | tr -d '[:space:]')"
  if [[ ! "$sha" =~ ^[0-9a-f]{7,40}$ ]]; then
    echo "check-proto-pin: $file ($label) content '$sha' doesn't look like a git commit SHA (expected 7-40 lowercase hex chars)" >&2
    exit 1
  fi
  echo "$sha"
}

SELF_SHA="$(read_pin "$SELF" "self: $(basename "$SELF")")"

FAIL=0

if [[ "$PRODUCT_FOUND" -eq 0 ]]; then
  echo "check-proto-pin: $(basename "$SELF")/proto.pin = $SELF_SHA"
  cat <<EOF
check-proto-pin: no peer consumer repo found at '$PRODUCT' -- skipping the
peer pin comparison (informational only, not a failure).

lexa-hub, the original second peer, was abandoned 2026-08-03 and its
checkout archived off-disk; the remaining peer is lexa-gw. If this is CI:
pass --product explicitly with the checked-out peer path (as the proto-pin
job does). If this is local dev: check out lexa-gw as a sibling (../lexa-gw),
or pass --product <path-to-peer-repo>. $(basename "$SELF")'s own proto.pin
is well-formed regardless of whether a peer was found.
EOF
else
  PRODUCT_SHA="$(read_pin "$PRODUCT" "product: $(basename "$PRODUCT")")"

  echo "check-proto-pin: $(basename "$SELF")/proto.pin    = $SELF_SHA"
  echo "check-proto-pin: $(basename "$PRODUCT")/proto.pin = $PRODUCT_SHA"

  # THE QUESTION IS "THE SAME COMMIT", NOT "THE SAME STRING" (2026-08-15).
  #
  # read_pin accepts 7-40 hex chars, because a proto.pin has always been
  # allowed to hold an abbreviated SHA -- and this comparison was a literal
  # string test, so one repo writing fe483e7 and the other writing
  # fe483e7d40d575725d4e5365214d9a95409966d6 FAILED the gate while pinning the
  # identical commit. That is a false alarm on the one check the release gate
  # treats as ground truth, and a false alarm on a gate is worse than no gate:
  # it trains the next person to wave it through.
  #
  # So when a local lexa-proto checkout is available, both pins are RESOLVED to
  # full commit IDs and those are compared. That is the question AD-003 actually
  # asks. Without a checkout (hosted CI's normal case, since lexa-proto has no
  # remote) the strings are compared as before, with one narrow allowance: if
  # one is a prefix of the other they are treated as naming the same commit and
  # the fact that this was NOT verified is stated. A 7-hex prefix collision is
  # not a realistic accident, but it is not proof either, and the difference is
  # exactly what the (b) check below upgrades when it can run.
  PINS_MATCH=0
  PIN_HOW=""
  if [[ "$SELF_SHA" == "$PRODUCT_SHA" ]]; then
    PINS_MATCH=1
    PIN_HOW="identical"
  elif [[ -d "$PROTO/.git" ]] && [[ "$NO_PROTO_CHECK" -eq 0 ]]; then
    SELF_FULL="$(git -C "$PROTO" rev-parse --verify "${SELF_SHA}^{commit}" 2>/dev/null || true)"
    PRODUCT_FULL="$(git -C "$PROTO" rev-parse --verify "${PRODUCT_SHA}^{commit}" 2>/dev/null || true)"
    if [[ -n "$SELF_FULL" && "$SELF_FULL" == "$PRODUCT_FULL" ]]; then
      PINS_MATCH=1
      PIN_HOW="different abbreviations of $SELF_FULL, resolved against $PROTO"
    fi
  elif [[ "$SELF_SHA" == "$PRODUCT_SHA"* || "$PRODUCT_SHA" == "$SELF_SHA"* ]]; then
    PINS_MATCH=1
    PIN_HOW="one is a prefix of the other, and NO lexa-proto checkout was available to resolve them --
                            treated as the same commit, NOT verified to be"
  fi

  if [[ "$PINS_MATCH" -eq 0 ]]; then
    cat >&2 <<EOF

PIN MISMATCH: $(basename "$SELF") pins lexa-proto @ $SELF_SHA
              $(basename "$PRODUCT") pins lexa-proto @ $PRODUCT_SHA

These are not the same commit. (They are also not two spellings of one: this
gate resolves abbreviated SHAs against a local lexa-proto checkout when one is
available, and falls back to prefix equality when it is not, so a difference
reported here is a real one.)

Both consumer repos must pin the identical lexa-proto commit (AD-003).
Version bumps ship as paired PRs (05 §11) -- bump both proto.pin files (and
regenerate + commit vendor/lexa-proto/ in both, AD-003(e)) in the same
session, never one side alone.
EOF
    FAIL=1
  else
    echo "check-proto-pin: pins match ($PIN_HOW)."
  fi
fi

# (b)/(c): only meaningful with a local lexa-proto checkout, which no hosted
# CI runner has today (lexa-proto isn't hosted -- nothing to fetch it from).
if [[ "$NO_PROTO_CHECK" -eq 1 ]]; then
  echo "check-proto-pin: --no-proto-check set, skipping local lexa-proto verification."
elif [[ ! -d "$PROTO/.git" ]]; then
  cat <<EOF
check-proto-pin: no local lexa-proto checkout at '$PROTO' -- skipping the
HEAD-match / vendor-regeneration checks. This is expected in hosted CI:
lexa-proto has no hosted remote yet, so no CI runner can fetch it (the
committed vendor/lexa-proto/ tree is what lets the build succeed anyway --
AD-003(e)). The proto.pin comparison above is CI's actual ground truth
today; this local check is a desktop/dev-only supplement.
EOF
else
  PROTO="$(cd "$PROTO" && pwd)"
  if ! RESOLVED_SHA="$(git -C "$PROTO" rev-parse --verify "${SELF_SHA}^{commit}" 2>/dev/null)"; then
    echo "check-proto-pin: pinned SHA $SELF_SHA does not resolve to a commit in $PROTO -- typo, or lexa-proto history was rewritten?" >&2
    FAIL=1
  else
    PROTO_HEAD="$(git -C "$PROTO" rev-parse HEAD)"
    if [[ "$PROTO_HEAD" != "$RESOLVED_SHA" ]]; then
      cat >&2 <<EOF
check-proto-pin: local lexa-proto checkout at $PROTO is at HEAD $PROTO_HEAD,
not the pinned commit $SELF_SHA ($RESOLVED_SHA). Check out the pinned SHA
before trusting a local build, or bump proto.pin (both repos, paired PR) if
you meant to move the pin forward.
EOF
      FAIL=1
    else
      echo "check-proto-pin: local lexa-proto checkout is at the pinned commit."
    fi

    if [[ "$VERIFY_VENDOR" -eq 1 ]]; then
      echo "check-proto-pin: --verify-vendor: regenerating vendor/lexa-proto from $SELF_SHA and diffing..."
      TMP_ROOT="$(mktemp -d)"
      trap 'rm -rf "$TMP_ROOT"' EXIT

      TMP_PROTO="$TMP_ROOT/lexa-proto"
      mkdir -p "$TMP_PROTO"
      # Read-only against the real lexa-proto checkout: git archive only
      # reads objects, never touches $PROTO's working tree or .git admin
      # state (unlike `git worktree add`).
      git -C "$PROTO" archive "$RESOLVED_SHA" | tar -x -C "$TMP_PROTO"

      TMP_CONSUMER="$TMP_ROOT/consumer"
      mkdir -p "$TMP_CONSUMER"
      # Full module source tree is needed: `go mod vendor` traces the actual
      # import graph, not just go.mod. vendor/ and .git are excluded (huge,
      # irrelevant, and we're about to regenerate vendor/ from scratch).
      # Also excluded: non-content scratch/output dirs that a live bench
      # session may be writing to concurrently (logs/, cmd/dashboard/logs/,
      # runs/) or that are just build output / fetched deps irrelevant to the
      # go vendor comparison (bin/, cmd/dashboard/ui/node_modules/). Reading a
      # file mid-write here makes `tar -c` report "file changed as we read
      # it" and exit non-zero, failing this check spuriously -- none of
      # these dirs are part of the vendored proto content being verified.
      #
      # runs/ was added to that list on 2026-08-15 and is the one whose absence
      # HURT: it holds this bench's published evidence bundles -- pcaps,
      # keylogs, register dumps -- and had reached 13 GB on this machine, which
      # --verify-vendor was copying in full, twice (tar out, tar in), on every
      # invocation. That is minutes of wall clock and 26 GB of I/O to verify a
      # few hundred KB of vendored Go, and it is also the concurrency hazard
      # above at its worst: a campaign writing a bundle while this runs fails
      # the check for a reason that has nothing to do with the pin. (lexa-gw's
      # copy of this script has a runs/ too, at 4.4 MB, and no exclusion; it
      # should get the same one before it grows.)
      ( cd "$SELF" && tar -c --exclude=./.git --exclude=./vendor \
          --exclude=./logs --exclude=./cmd/dashboard/logs --exclude=./runs \
          --exclude=./bin --exclude=./cmd/dashboard/ui/node_modules \
          . ) | tar -x -C "$TMP_CONSUMER"

      # Point the scratch copy's replace directive at the extracted SHA
      # instead of the developer's real (possibly-ahead-of-pin) ../lexa-proto.
      sed -i.bak "s#^replace lexa-proto => .*#replace lexa-proto => $TMP_PROTO#" "$TMP_CONSUMER/go.mod"
      rm -f "$TMP_CONSUMER/go.mod.bak"

      if ! ( cd "$TMP_CONSUMER" && GOWORK=off GOFLAGS=-mod=mod go mod vendor ) >"$TMP_ROOT/vendor.log" 2>&1; then
        echo "check-proto-pin: 'go mod vendor' failed while regenerating from the pinned SHA:" >&2
        cat "$TMP_ROOT/vendor.log" >&2
        FAIL=1
      else
        # go mod vendor drops _test.go files and non-build sources; ignore
        # the same categories here so we compare what actually ships.
        DIFF_OUT="$(diff -rq \
          -x '*_test.go' \
          "$TMP_CONSUMER/vendor/lexa-proto" "$SELF/vendor/lexa-proto" || true)"
        if [[ -n "$DIFF_OUT" ]]; then
          echo "check-proto-pin: committed vendor/lexa-proto does NOT match a fresh 'go mod vendor' at the pinned SHA:" >&2
          echo "$DIFF_OUT" >&2
          echo "Regenerate: (cd $SELF && GOWORK=off go mod vendor) with ../lexa-proto checked out at $SELF_SHA, then commit." >&2
          FAIL=1
        else
          echo "check-proto-pin: committed vendor/lexa-proto matches a fresh regeneration from the pinned SHA."
        fi
      fi

      rm -rf "$TMP_ROOT"
      trap - EXIT
    fi
  fi
fi

echo
if [[ "$FAIL" -ne 0 ]]; then
  echo "check-proto-pin: FAIL"
  exit 1
fi
echo "check-proto-pin: PASS"
exit 0
