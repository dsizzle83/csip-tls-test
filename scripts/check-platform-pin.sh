#!/bin/bash
# csip-tls-test's lexa-platform version-pinning gate — sibling of
# scripts/check-proto-pin.sh (TASK-024), covering the SECOND pinned shared
# module (lexa-platform; vendor/lexa-platform/, AD-003(c)/(e) same pinning
# mechanism as lexa-proto, just a different module).
#
# Added 2026-08-17: check-proto-pin.sh has never had any platform.pin
# awareness (its own --verify-vendor block touches lexa-platform only far
# enough to make `go mod vendor` resolve while regenerating vendor/lexa-proto
# — see the comment there: "platform coherence is ... platform.pin's job,
# not this script's"). That left a real gap: csip-tls-test commits its own
# platform.pin at repo root and vendors lexa-platform (vendor/lexa-platform/
# bus), exactly the same shape as lexa-proto/proto.pin, but NOTHING checked
# it against the peer. It went unnoticed: as of this writing, csip-tls-test's
# platform.pin (71bb2d5) and lexa-gw's platform.pin (0a61b0d) name two
# DIFFERENT lexa-platform commits (0a61b0d is 71bb2d5's immediate parent in
# the local ~/projects/lexa-platform checkout) — real drift this gate is
# supposed to catch, sitting there the whole time the pin-check job reported
# green, because there was no such gate. See docs/ for the writeup; this
# script's own "run against real local peers" verification below reproduces
# it directly (a genuine platform-pin peer mismatch, not a script bug).
#
# lexa-gw carries its own scripts/check-platform-pin.sh, but that copy's
# header explicitly says lexa-gw is "the sole consumer of platform.pin
# today" and has no peer-consistency check at all — true when it was
# written, false now that csip-tls-test also vendors lexa-platform. This
# script is NOT that one; it is csip-tls-test's own copy, ported the same
# direction check-proto-pin.sh's peer-consistency block (d) was ported onto
# lexa-gw's check-proto-pin.sh: the (b) peer-comparison logic below is
# structurally the same as check-proto-pin.sh's PRODUCT/PRODUCT_FOUND block,
# retargeted from proto.pin to platform.pin; the (c)/(d) local-checkout logic
# is ported from lexa-gw's check-platform-pin.sh.
#
# Checks:
#   (a) platform.pin is well-formed: exactly one line, looks like a git
#       commit SHA. Always runs, including hosted CI, no checkout needed.
#   (b) peer consistency: --product's platform.pin (default: the same
#       ../lexa-gw peer check-proto-pin.sh uses) must name the SAME
#       lexa-platform commit as this repo's. A missing peer is an
#       informational SKIP, not a failure -- unless --require-peer is given,
#       in which case it is a FAILURE. Same semantics, same flag name, as
#       check-proto-pin.sh's --require-peer (2026-08-17).
#   (c) IF a local lexa-platform checkout is available (developer machines;
#       default ../lexa-platform relative to --self, override with
#       --checkout) -- verifies the pinned SHA resolves to a real commit
#       there, and that the checkout's HEAD is actually at it. Also used to
#       resolve abbreviated SHAs to full commit ids when comparing against
#       --product in (b), so a 7-hex-prefix pin and a 40-hex pin naming the
#       same commit don't false-positive as a mismatch (mirrors
#       check-proto-pin.sh's SHA-resolution logic for proto.pin).
#   (d) With --verify-vendor (opt-in: needs a `go` toolchain and a real (c)
#       checkout) -- regenerates vendor/lexa-platform/* from the pinned SHA
#       in a scratch copy and diffs it against the committed
#       vendor/lexa-platform tree. Catches "pin bumped but vendor/ wasn't
#       regenerated" and "vendor/ hand-edited," neither of which (a)/(b)/(c)
#       can see.
#
# Usage:
#   scripts/check-platform-pin.sh [--self <path>] [--product <path>]
#                                  [--require-peer]
#                                  [--checkout <path-to-lexa-platform>]
#                                  [--no-checkout-check] [--verify-vendor]
#                                  [--allow-dirty]
#
# DIRTY-PEER GATE (2026-08-17, F2/cross-repo lockstep audit, ported from
# check-proto-pin.sh's identical fix): a clean pin match (platform.pin
# strings/SHAs agree) says the two repos NAME the same lexa-platform commit
# -- it says NOTHING about whether the peer checkout's OWN files, in the
# paths this gate actually reads or ships (platform.pin itself, go.mod/
# go.sum's require/replace lines, vendor/lexa-platform/), are what is
# actually COMMITTED there. The audit's root cause was exactly this:
# uncommitted source in a peer checkout, certified clean by a pin-match PASS
# that never looked at `git status`. --allow-dirty is the escape hatch for
# local/dev use, off by default so hosted CI (which always checks out the
# peer fresh) treats it as a real failure.
#
#   --self <path>       Path to "this side" of the pin comparison. Default:
#                        this script's own repo root.
#   --product <path>    Path to the peer consumer repo. Default: `../lexa-gw`
#                        if --self's basename isn't "lexa-gw", else
#                        `../csip-tls-test` -- same default-resolution rule as
#                        check-proto-pin.sh. CI always passes this explicitly
#                        (the checked-out peer path). A missing peer is an
#                        informational skip, not a failure -- unless
#                        --require-peer is given.
#   --require-peer      A missing/empty --product peer is a FAILURE, not an
#                        informational skip. CI passes this (see the
#                        2026-08-17 note above and check-proto-pin.sh's
#                        matching flag).
#   --allow-dirty       Downgrade the dirty-peer gate (see the DIRTY-PEER
#                        GATE note above) from a FAILURE to a printed
#                        warning. Off by default; local/dev use only -- CI
#                        never passes it.
#   --checkout <path>   Path to a local lexa-platform checkout, for the
#                        (c)/(d) checks. Default: ../lexa-platform relative
#                        to --self.
#   --no-checkout-check Skip (c)/(d) entirely even if --checkout exists
#                        (fast path: pin-vs-pin only). Also disables SHA
#                        resolution in (b): abbreviated pins fall back to
#                        prefix-equality.
#   --verify-vendor      Run the (d) deep vendor-regeneration diff. Requires
#                        a `go` toolchain and a real --checkout. Slow;
#                        intended for desktop/local runs, not every CI job.
#
# Exit codes: 0 = platform.pin well-formed, peer (if found, or found because
# --require-peer forced it to be looked for) agrees, and, unless
# skipped/unavailable, (c) and any requested (d) check pass too. 1 =
# malformed platform.pin (self or a found peer), peer mismatch, no peer
# found with --require-peer set, the peer's checkout is dirty in the
# consumed module paths and --allow-dirty was not given (see the DIRTY-PEER
# GATE note above), (c) mismatch, or (d) diff found. 2 = usage error.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_SELF="$(cd "$SCRIPT_DIR/.." && pwd)"

SELF="$DEFAULT_SELF"
PRODUCT=""
CHECKOUT=""
NO_CHECKOUT_CHECK=0
VERIFY_VENDOR=0
REQUIRE_PEER=0
ALLOW_DIRTY=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --self)
      [[ $# -ge 2 ]] || { echo "check-platform-pin: --self needs a path argument" >&2; exit 2; }
      SELF="$2"; shift 2 ;;
    --product)
      [[ $# -ge 2 ]] || { echo "check-platform-pin: --product needs a path argument" >&2; exit 2; }
      PRODUCT="$2"; shift 2 ;;
    --require-peer)
      REQUIRE_PEER=1; shift ;;
    --allow-dirty)
      ALLOW_DIRTY=1; shift ;;
    --checkout)
      [[ $# -ge 2 ]] || { echo "check-platform-pin: --checkout needs a path argument" >&2; exit 2; }
      CHECKOUT="$2"; shift 2 ;;
    --no-checkout-check)
      NO_CHECKOUT_CHECK=1; shift ;;
    --verify-vendor)
      VERIFY_VENDOR=1; shift ;;
    -h|--help)
      sed -n '2,111p' "${BASH_SOURCE[0]}"
      exit 0 ;;
    *)
      echo "check-platform-pin: unknown argument: $1" >&2
      exit 2 ;;
  esac
done

[[ -d "$SELF" ]] || { echo "check-platform-pin: --self path not found: $SELF" >&2; exit 2; }
SELF="$(cd "$SELF" && pwd)"

if [[ -z "$PRODUCT" ]]; then
  if [[ "$(basename "$SELF")" == "lexa-gw" ]]; then
    PRODUCT="$SELF/../csip-tls-test"
  else
    PRODUCT="$SELF/../lexa-gw"
  fi
fi

# A missing peer is an INFORMATIONAL skip by default -- same reasoning as
# check-proto-pin.sh's PRODUCT_FOUND handling -- unless --require-peer forces
# it to a failure (2026-08-17; see the header note).
PRODUCT_FOUND=1
if [[ ! -d "$PRODUCT" ]]; then
  PRODUCT_FOUND=0
else
  PRODUCT="$(cd "$PRODUCT" && pwd)"
fi

if [[ -z "$CHECKOUT" ]]; then
  CHECKOUT="$SELF/../lexa-platform"
fi

read_platform_pin() {
  local dir="$1" label="$2" file
  file="$dir/platform.pin"
  if [[ ! -f "$file" ]]; then
    echo "check-platform-pin: no platform.pin at $file ($label)" >&2
    exit 1
  fi
  local nonblank
  nonblank="$(grep -vc '^[[:space:]]*$' "$file" || true)"
  if [[ "$nonblank" -ne 1 ]]; then
    echo "check-platform-pin: $file ($label) must contain exactly one non-blank line (a single lexa-platform commit SHA)" >&2
    exit 1
  fi
  local sha
  sha="$(grep -v '^[[:space:]]*$' "$file" | head -n1 | tr -d '[:space:]')"
  if [[ ! "$sha" =~ ^[0-9a-f]{7,40}$ ]]; then
    echo "check-platform-pin: $file ($label) content '$sha' doesn't look like a git commit SHA (expected 7-40 lowercase hex chars)" >&2
    exit 1
  fi
  echo "$sha"
}

SELF_SHA="$(read_platform_pin "$SELF" "self: $(basename "$SELF")")"

FAIL=0

# ── (b) peer consistency ────────────────────────────────────────────────────
if [[ "$PRODUCT_FOUND" -eq 0 ]]; then
  echo "check-platform-pin: $(basename "$SELF")/platform.pin = $SELF_SHA"
  if [[ "$REQUIRE_PEER" -eq 1 ]]; then
    cat >&2 <<EOF
check-platform-pin: --require-peer set, but no peer consumer repo found at
'$PRODUCT'. Treating this as a FAILURE, not an informational skip -- check
the checkout step (bad token, wrong repo/path, checkout-step failure) before
assuming this is an actual pin mismatch: it isn't one, there was nothing to
compare against.
EOF
    FAIL=1
  else
    cat <<EOF
check-platform-pin: no peer consumer repo found at '$PRODUCT' -- skipping
the peer pin comparison (informational only, not a failure). If this is CI:
pass --product explicitly with the checked-out peer path (as the pin-check
job does). If this is local dev: check out lexa-gw as a sibling
(../lexa-gw), or pass --product <path-to-peer-repo>. $(basename "$SELF")'s
own platform.pin is well-formed regardless of whether a peer was found.
(Pass --require-peer to make a missing peer a failure instead -- CI does.)
EOF
  fi
else
  PRODUCT_SHA="$(read_platform_pin "$PRODUCT" "product: $(basename "$PRODUCT")")"

  echo "check-platform-pin: $(basename "$SELF")/platform.pin    = $SELF_SHA"
  echo "check-platform-pin: $(basename "$PRODUCT")/platform.pin = $PRODUCT_SHA"

  # ── DIRTY-PEER GATE (2026-08-17) ──────────────────────────────────────────
  # Ported from check-proto-pin.sh's identical fix, retargeted from proto.pin
  # to platform.pin -- see that script's own comment at this same point for
  # the full argument. Scoped to platform.pin, go.mod, go.sum, and
  # vendor/lexa-platform: the paths this gate's own conclusions (the
  # PRODUCT_SHA just read, and what a build actually consumes) depend on.
  if [[ ! -d "$PRODUCT/.git" ]]; then
    echo "check-platform-pin: $(basename "$PRODUCT") is not a git checkout (no .git) -- skipping the dirty-peer gate."
  else
    DIRTY_OUT="$(git -C "$PRODUCT" status --porcelain -- platform.pin go.mod go.sum vendor/lexa-platform 2>&1 || true)"
    if [[ -n "$DIRTY_OUT" ]]; then
      if [[ "$ALLOW_DIRTY" -eq 1 ]]; then
        cat <<EOF
check-platform-pin: WARNING -- $(basename "$PRODUCT")'s working tree is dirty
in the consumed module paths (--allow-dirty set, not failing):
$DIRTY_OUT
The platform.pin comparison above reflects what is ON DISK there right now,
which is NOT necessarily what a fresh checkout of $(basename "$PRODUCT")
(e.g. a CI runner) would see. Do not treat this PASS as CI-equivalent.
EOF
      else
        cat >&2 <<EOF
check-platform-pin: FAIL -- $(basename "$PRODUCT")'s working tree is dirty in
the consumed module paths (platform.pin, go.mod, go.sum, vendor/lexa-platform):
$DIRTY_OUT
A pin match against uncommitted peer state is not a real pin match: a fresh
checkout of $(basename "$PRODUCT") (what hosted CI actually builds) would
not see these changes, so this PASS would not reproduce there. This is the
audit's root-cause shape (uncommitted source certified by a clean-pin PASS)
-- commit or stash the changes above in $(basename "$PRODUCT"), or pass
--allow-dirty if this is deliberate local/dev mid-edit state.
EOF
        FAIL=1
      fi
    fi
  fi

  # Same "same commit, not same string" resolution check-proto-pin.sh applies
  # to proto.pin (2026-08-15 there): resolve abbreviated SHAs against a local
  # lexa-platform checkout when one is available, else fall back to prefix
  # equality (stated as unverified), else it's a real mismatch.
  # FINDING 7 (2026-08-17): the prefix-equality fallback below is only a
  # legitimate substitute for checkout-based resolution when at least one
  # side is a genuinely abbreviated (short) pin -- if BOTH sides are already
  # full 40-hex SHAs, there is nothing left to abbreviate, so two distinct
  # full SHAs must never be waved through as "maybe the same commit." (bash's
  # `==` glob on two equal-length 40-char strings can only match on exact
  # equality anyway -- branch 1 below already catches that -- but the
  # explicit guard makes the invariant readable, and the logged PIN_HOW
  # records which mode decided.)
  SELF_IS_FULL=0; [[ ${#SELF_SHA} -eq 40 ]] && SELF_IS_FULL=1
  PRODUCT_IS_FULL=0; [[ ${#PRODUCT_SHA} -eq 40 ]] && PRODUCT_IS_FULL=1

  PINS_MATCH=0
  PIN_HOW=""
  if [[ "$SELF_SHA" == "$PRODUCT_SHA" ]]; then
    PINS_MATCH=1
    PIN_HOW="identical (mode: exact string match)"
  elif [[ -d "$CHECKOUT/.git" ]] && [[ "$NO_CHECKOUT_CHECK" -eq 0 ]]; then
    SELF_FULL="$(git -C "$CHECKOUT" rev-parse --verify "${SELF_SHA}^{commit}" 2>/dev/null || true)"
    PRODUCT_FULL="$(git -C "$CHECKOUT" rev-parse --verify "${PRODUCT_SHA}^{commit}" 2>/dev/null || true)"
    if [[ -n "$SELF_FULL" && "$SELF_FULL" == "$PRODUCT_FULL" ]]; then
      PINS_MATCH=1
      PIN_HOW="different abbreviations of $SELF_FULL, resolved against $CHECKOUT (mode: checkout-resolved)"
    fi
  elif [[ "$SELF_IS_FULL" -eq 1 && "$PRODUCT_IS_FULL" -eq 1 ]]; then
    : # Both are full SHAs and unequal (branch 1 above already ruled out
      # equality) and no checkout was available to resolve further -- a real
      # mismatch. PINS_MATCH stays 0; falls through to the report below.
      # Deliberately NOT eligible for the prefix-fallback branch next: that
      # branch exists only for the short-pin case.
  elif [[ "$SELF_SHA" == "$PRODUCT_SHA"* || "$PRODUCT_SHA" == "$SELF_SHA"* ]]; then
    PINS_MATCH=1
    PIN_HOW="one is a prefix of the other, and NO lexa-platform checkout was available to resolve them --
                               treated as the same commit, NOT verified to be (mode: prefix fallback, unverified)"
  fi

  if [[ "$PINS_MATCH" -eq 0 ]]; then
    cat >&2 <<EOF

PIN MISMATCH: $(basename "$SELF") pins lexa-platform @ $SELF_SHA
              $(basename "$PRODUCT") pins lexa-platform @ $PRODUCT_SHA

These are not the same commit (resolved against a local lexa-platform
checkout when one was available; otherwise compared as literal/prefix
strings, so a difference reported here is a real one).

Both consumer repos must pin the identical lexa-platform commit. Bump both
platform.pin files (and regenerate + commit vendor/lexa-platform in both) in
the same session, never one side alone.
EOF
    FAIL=1
  else
    echo "check-platform-pin: pins match ($PIN_HOW)."
  fi
fi

# ── (c)/(d): local lexa-platform checkout ───────────────────────────────────
# Only meaningful with a local checkout, which no hosted CI runner has today
# (lexa-platform has no hosted remote -- nothing to fetch it from).
if [[ "$NO_CHECKOUT_CHECK" -eq 1 ]]; then
  echo "check-platform-pin: --no-checkout-check set, skipping local lexa-platform verification."
elif [[ ! -d "$CHECKOUT/.git" ]]; then
  cat <<EOF
check-platform-pin: no local lexa-platform checkout at '$CHECKOUT' --
skipping the HEAD-match / vendor-regeneration checks. This is expected in
hosted CI: lexa-platform has no hosted remote yet, so no CI runner can fetch
it (the committed vendor/lexa-platform/ tree is what lets the build succeed
anyway). The platform.pin comparison above is CI's actual ground truth
today; this local check is a desktop/dev-only supplement.
EOF
else
  CHECKOUT="$(cd "$CHECKOUT" && pwd)"
  if ! RESOLVED_SHA="$(git -C "$CHECKOUT" rev-parse --verify "${SELF_SHA}^{commit}" 2>/dev/null)"; then
    echo "check-platform-pin: pinned SHA $SELF_SHA does not resolve to a commit in $CHECKOUT -- typo, or lexa-platform history was rewritten?" >&2
    FAIL=1
  else
    CHECKOUT_HEAD="$(git -C "$CHECKOUT" rev-parse HEAD)"
    if [[ "$CHECKOUT_HEAD" != "$RESOLVED_SHA" ]]; then
      cat >&2 <<EOF
check-platform-pin: local lexa-platform checkout at $CHECKOUT is at HEAD
$CHECKOUT_HEAD, not the pinned commit $SELF_SHA ($RESOLVED_SHA). Check out
the pinned SHA before trusting a local build, or bump platform.pin (paired
across both consumer repos) if you meant to move the pin forward.
EOF
      FAIL=1
    else
      echo "check-platform-pin: local lexa-platform checkout is at the pinned commit."
    fi

    if [[ "$VERIFY_VENDOR" -eq 1 ]]; then
      echo "check-platform-pin: --verify-vendor: regenerating vendor/lexa-platform from $SELF_SHA and diffing..."
      TMP_ROOT="$(mktemp -d)"
      trap 'rm -rf "$TMP_ROOT"' EXIT

      TMP_PLATFORM="$TMP_ROOT/lexa-platform"
      mkdir -p "$TMP_PLATFORM"
      # Read-only against the real lexa-platform checkout: git archive only
      # reads objects, never touches $CHECKOUT's working tree or .git admin
      # state (unlike `git worktree add`).
      git -C "$CHECKOUT" archive "$RESOLVED_SHA" | tar -x -C "$TMP_PLATFORM"

      TMP_CONSUMER="$TMP_ROOT/consumer"
      mkdir -p "$TMP_CONSUMER"
      # Full module source tree is needed: `go mod vendor` traces the actual
      # import graph, not just go.mod. vendor/ and .git are excluded (huge,
      # irrelevant, and we're about to regenerate vendor/ from scratch), same
      # exclusions check-proto-pin.sh applies for the same reasons (concurrent
      # bench writers under logs/, cmd/dashboard/logs/, runs/; build/fetched
      # output under bin/, cmd/dashboard/ui/node_modules/).
      ( cd "$SELF" && tar -c --exclude=./.git --exclude=./vendor \
          --exclude=./logs --exclude=./cmd/dashboard/logs --exclude=./runs \
          --exclude=./bin --exclude=./cmd/dashboard/ui/node_modules \
          . ) | tar -x -C "$TMP_CONSUMER"

      # Point the scratch copy's replace directive at the extracted SHA
      # instead of the developer's real (possibly-ahead-of-pin) ../lexa-platform.
      sed -i.bak "s#^replace lexa-platform => .*#replace lexa-platform => $TMP_PLATFORM#" "$TMP_CONSUMER/go.mod"
      rm -f "$TMP_CONSUMER/go.mod.bak"

      # go.mod also replaces lexa-proto => ../lexa-proto; that require must
      # still resolve for `go mod vendor` to run at all (it vendors the WHOLE
      # module, not just lexa-platform), so point it at whatever the sibling
      # checkout on this machine actually is -- this script only verifies the
      # lexa-platform side of vendor/, so lexa-proto's content here is
      # irrelevant to the diff below (mirrors check-proto-pin.sh's symmetric
      # handling of lexa-platform in its own --verify-vendor).
      if grep -q '^replace lexa-proto => ' "$TMP_CONSUMER/go.mod"; then
        sed -i.bak "s#^replace lexa-proto => .*#replace lexa-proto => $SELF/../lexa-proto#" "$TMP_CONSUMER/go.mod"
        rm -f "$TMP_CONSUMER/go.mod.bak"
      fi

      if ! ( cd "$TMP_CONSUMER" && GOWORK=off GOFLAGS=-mod=mod go mod vendor ) >"$TMP_ROOT/vendor.log" 2>&1; then
        echo "check-platform-pin: 'go mod vendor' failed while regenerating from the pinned SHA:" >&2
        cat "$TMP_ROOT/vendor.log" >&2
        FAIL=1
      else
        # go mod vendor drops _test.go files and non-build sources; ignore
        # the same categories here so we compare what actually ships.
        #
        # FINDING 1 (2026-08-17, adversarial pin-gate review): the old
        # `diff -rq ... || true` captured stdout only -- diff's "No such
        # file or directory" (rc=2) goes to stderr, so a MISSING compared
        # tree left DIFF_OUT empty and this step PASSED. Proven: a planted
        # vendor/lexa-platform/bus/backdoor.go was certified as matching the
        # pin because the comparison directory was absent, not because it
        # matched. Fixed: verify both compared directories exist BEFORE
        # diffing, then test diff's exit status directly (rc=0 match, rc=1
        # mismatch, rc>=2 error) instead of discarding it with `|| true`.
        # ANY nonzero rc is now a FAILURE, not just rc=1.
        if [[ ! -d "$TMP_CONSUMER/vendor/lexa-platform" ]]; then
          echo "check-platform-pin: --verify-vendor: regenerated tree missing at $TMP_CONSUMER/vendor/lexa-platform ('go mod vendor' did not produce it) -- treating as FAILURE, not a pass." >&2
          FAIL=1
        elif [[ ! -d "$SELF/vendor/lexa-platform" ]]; then
          echo "check-platform-pin: --verify-vendor: committed tree missing at $SELF/vendor/lexa-platform -- treating as FAILURE, not a pass." >&2
          FAIL=1
        else
          DIFF_RC=0
          DIFF_OUT="$(diff -rq -x '*_test.go' \
            "$TMP_CONSUMER/vendor/lexa-platform" "$SELF/vendor/lexa-platform" 2>&1)" || DIFF_RC=$?
          if [[ "$DIFF_RC" -ne 0 ]]; then
            if [[ "$DIFF_RC" -ge 2 ]]; then
              echo "check-platform-pin: --verify-vendor: 'diff' itself failed (exit $DIFF_RC), not merely found a difference -- treating as FAILURE, not a pass:" >&2
            else
              echo "check-platform-pin: committed vendor/lexa-platform does NOT match a fresh 'go mod vendor' at the pinned SHA:" >&2
            fi
            echo "$DIFF_OUT" >&2
            echo "Regenerate: (cd $SELF && GOWORK=off go mod vendor) with ../lexa-platform checked out at $SELF_SHA, then commit." >&2
            FAIL=1
          else
            echo "check-platform-pin: committed vendor/lexa-platform matches a fresh regeneration from the pinned SHA."
          fi
        fi
      fi

      rm -rf "$TMP_ROOT"
      trap - EXIT
    fi
  fi
fi

echo
if [[ "$FAIL" -ne 0 ]]; then
  echo "check-platform-pin: FAIL"
  exit 1
fi
echo "check-platform-pin: PASS"
exit 0
