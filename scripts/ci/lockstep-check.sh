#!/bin/bash
# TASK-004: CI lockstep-divergence gate (report-only until Phase 1, W3/D4/AD-003).
#
# Two package trees are intentionally duplicated across this repo
# (csip-tls-test, "bench") and the product repo (lexa-hub) and must change
# in lockstep — audit finding MTR-4: a lone-sided change misreads real
# hardware:
#   - internal/southbound/sunspec   (SunSpec register maps/codecs)
#   - internal/ocppserver           (OCPP 2.0.1 CSMS)
#
# The lockstep rule used to live only as a sentence in the two CLAUDE.md
# files, and it already failed (review W3) before this gate existed. This
# script byte-diffs (`diff -rq`, NOT semantic/gofmt-aware — false positives
# are impossible by construction, false "same" is what kills) both trees
# against a known-divergence allowlist (scripts/ci/lockstep-allowlist.txt):
#
#   - Without --enforce (today's mode, wired into CI as report-only):
#       * A divergence already in the allowlist prints a loud
#         KNOWN-DIVERGENCE warning but does not fail the build.
#       * Any NEW divergence (not in the allowlist) fails the build.
#     i.e. the job's actual job is "no *new* drift", not "no drift" — the
#     existing W3 debt stays loud without blocking every PR.
#
#   - With --enforce: ANY divergence fails the build, allowlist or not.
#     This is what Phase 1 (TASK-019-024) flips CI to once the shared
#     `lexa-proto` module (AD-003) replaces the duplication; TASK-024 then
#     retires this whole script in favor of module version pinning.
#
# This script does NOT fix, reconcile, or judge which side is "right" for
# any divergent file (reconciliation is TASK-020/021, high-risk per RSK-02
# — either side may hold the real fix). It only observes.
#
# Usage:
#   scripts/ci/lockstep-check.sh [--product <path-to-lexa-hub>] [--enforce]
#
#   --product <path>  Path to a lexa-hub checkout. Default: ../lexa-hub
#                      (sibling checkout — the normal local-dev layout, and
#                      what a developer running this before a lockstep
#                      commit gets for free). CI overrides this to the
#                      `lexa-hub/` directory it checks out in-workflow.
#   --enforce          Ignore the allowlist entirely; any divergence fails.
#
# Exit codes: 0 = in lockstep (or only allowlisted divergence, non-enforce
# mode). 1 = new/unallowlisted divergence, or --enforce with any divergence,
# or a setup problem (missing tree, unreadable product checkout, malformed
# diff output).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ALLOWLIST="$SCRIPT_DIR/lockstep-allowlist.txt"

PRODUCT="../lexa-hub"
ENFORCE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --product)
      [[ $# -ge 2 ]] || { echo "lockstep-check: --product needs a path argument" >&2; exit 2; }
      PRODUCT="$2"
      shift 2
      ;;
    --enforce)
      ENFORCE=1
      shift
      ;;
    -h|--help)
      sed -n '2,42p' "${BASH_SOURCE[0]}"
      exit 0
      ;;
    *)
      echo "lockstep-check: unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ ! -d "$PRODUCT" ]]; then
  cat >&2 <<EOF
lockstep-check: product repo not found at '$PRODUCT'.

If this is CI: the default GITHUB_TOKEN cannot read a second private repo.
The 'lockstep' job must checkout dsizzle83/lexa-hub into ./lexa-hub using
the LEXA_HUB_RO_TOKEN secret (fine-grained PAT, read-only contents scope,
lexa-hub repo only) before this script runs — see .github/workflows/ci.yml.

If this is local dev: pass --product <path-to-lexa-hub>, or check out
lexa-hub as a sibling of this repo (../lexa-hub).
EOF
  exit 1
fi
PRODUCT="$(cd "$PRODUCT" && pwd)"

if [[ ! -f "$ALLOWLIST" ]]; then
  echo "lockstep-check: allowlist missing at $ALLOWLIST" >&2
  exit 1
fi

TREES=(
  "internal/southbound/sunspec"
  "internal/ocppserver"
)

declare -a ALL_LINES=()

for tree in "${TREES[@]}"; do
  bench_dir="$REPO_ROOT/$tree"
  product_dir="$PRODUCT/$tree"
  pkg="$(basename "$tree")"

  # TASK-021/022: both trees are retired from both repos once their shared
  # lexa-proto module lands (AD-003) — that is the goal state, not a drift.
  # Only an ASYMMETRIC removal (retired on one side, still present on the
  # other) is a real divergence worth failing the gate over.
  if [[ ! -d "$bench_dir" && ! -d "$product_dir" ]]; then
    echo "lockstep-check: '$tree' retired from both repos (moved to lexa-proto) — nothing to compare."
    continue
  fi
  if [[ ! -d "$bench_dir" ]]; then
    echo "lockstep-check: '$tree' retired from bench but still present in product at $product_dir — asymmetric, review needed." >&2
    exit 1
  fi
  if [[ ! -d "$product_dir" ]]; then
    echo "lockstep-check: '$tree' retired from product but still present in bench at $bench_dir — asymmetric, review needed." >&2
    exit 1
  fi

  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    if [[ "$line" =~ ^Files\ (.*)\ and\ (.*)\ differ$ ]]; then
      a="${BASH_REMATCH[1]}"
      rel="${a#"$bench_dir"/}"
      ALL_LINES+=("$pkg/$rel DIFFER")
    elif [[ "$line" =~ ^Only\ in\ (.*):\ (.*)$ ]]; then
      dir="${BASH_REMATCH[1]}"
      name="${BASH_REMATCH[2]}"
      if [[ "$dir" == "$bench_dir"* ]]; then
        sub="${dir#"$bench_dir"}"
        sub="${sub#/}"
        rel="$name"
        [[ -n "$sub" ]] && rel="$sub/$name"
        ALL_LINES+=("$pkg/$rel BENCH-ONLY")
      elif [[ "$dir" == "$product_dir"* ]]; then
        sub="${dir#"$product_dir"}"
        sub="${sub#/}"
        rel="$name"
        [[ -n "$sub" ]] && rel="$sub/$name"
        ALL_LINES+=("$pkg/$rel PRODUCT-ONLY")
      else
        echo "lockstep-check: unrecognized 'Only in' directory: $dir" >&2
        exit 1
      fi
    else
      echo "lockstep-check: unrecognized diff -rq output line: $line" >&2
      exit 1
    fi
  done < <(diff -rq "$bench_dir" "$product_dir" || true)
done

declare -A ALLOWED=()
while IFS= read -r raw; do
  entry="${raw%%$'\r'}"
  entry="$(printf '%s' "$entry" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
  [[ -z "$entry" || "$entry" == \#* ]] && continue
  ALLOWED["$entry"]=1
done < "$ALLOWLIST"

declare -a VIOLATIONS=()
declare -a KNOWN=()

if [[ ${#ALL_LINES[@]} -eq 0 ]]; then
  echo "lockstep-check: internal/southbound/sunspec and internal/ocppserver are byte-identical between $REPO_ROOT and $PRODUCT."
else
  for entry in "${ALL_LINES[@]}"; do
    if [[ "$ENFORCE" -eq 1 ]]; then
      echo "ENFORCED-DIVERGENCE: $entry"
      VIOLATIONS+=("$entry")
    elif [[ -n "${ALLOWED[$entry]+x}" ]]; then
      KNOWN+=("$entry")
      echo "KNOWN-DIVERGENCE (P1 debt, see TASK-020/021): $entry"
    else
      echo "NEW-DIVERGENCE (fails lockstep gate): $entry"
      VIOLATIONS+=("$entry")
    fi
  done
fi

echo
if [[ ${#ALL_LINES[@]} -eq 0 ]]; then
  echo "lockstep-check: in lockstep (0 divergences)."
elif [[ ${#VIOLATIONS[@]} -eq 0 ]]; then
  echo "lockstep-check: ${#KNOWN[@]} known divergence(s) (allowlisted W3/P1 debt), 0 new. Report-only mode: exiting 0."
  echo "  Reminder: additions to lockstep-allowlist.txt are FORBIDDEN without a paired-PR"
  echo "  justification — the list only shrinks (TASK-020/021) until TASK-024 replaces this"
  echo "  gate with shared-module (lexa-proto, AD-003) version pinning."
else
  echo "lockstep-check: ${#VIOLATIONS[@]} unallowlisted divergence(s) out of ${#ALL_LINES[@]} total."
  if [[ "$ENFORCE" -eq 1 ]]; then
    echo "  (--enforce: allowlist ignored entirely; expected to fail until Phase 1 lands — AD-003/TASK-024.)"
  else
    echo "  This is NEW drift beyond the known W3 divergence. Do not add it to the allowlist to"
    echo "  make this pass — reconcile the drift (TASK-020/021) or get a paired-PR justification"
    echo "  reviewed before extending scripts/ci/lockstep-allowlist.txt."
  fi
fi

[[ ${#VIOLATIONS[@]} -gt 0 ]] && exit 1
exit 0
