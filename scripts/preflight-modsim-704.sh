#!/usr/bin/env bash
# Campaign Phase-0 preflight: the CSIP leg's southbound oracle must have a DER
# to read BEFORE the leg starts (IW14-003).
#
# BASIC-010 and BASIC-013 are the only two CSIP rows whose "the DER's output
# followed the control" criterion is a real PASS/FAIL rather than a SKIP: they
# read the DER's own SunSpec model-704 image through the modsim simapi sidecar
# (internal/invariant.SimAPIDER, GET $MODSIM_API/registers) and compare it
# against what the row itself commanded. Since IW14-003 an oracle that cannot
# read that image FAILS the row instead of skipping it — which is the correct
# posture for a release gate, and which makes a mis-pointed sidecar a campaign
# result rather than a footnote.
#
# So catch it in seconds instead of hours. The harness takes the sidecar's
# address from -modsim-api, defaulting to the compiled-in bench topology
# (certify.DefaultTargets, http://69.0.0.20:6020) — the campaign driver does not
# pass the flag, so the default is what the a78887f run actually used. Point
# this script at the SAME address the leg will use.
#
# Usage: scripts/preflight-modsim-704.sh [MODSIM_API]
#        MODSIM_API=http://69.0.0.20:6020 scripts/preflight-modsim-704.sh
#
# Exit codes: 0 = the sidecar answers and serves a full-length model 704.
#             1 = it does not (unreachable, unparseable, or no 704 block).
set -uo pipefail

API="${1:-${MODSIM_API:-http://69.0.0.20:6020}}"

BODY="$(curl -fsS --max-time 5 "$API/registers" 2>/dev/null)" || {
  echo "preflight-modsim-704: GET $API/registers did not answer — the BASIC-010/013 southbound oracle has no DER to read, and both rows will FAIL" >&2
  exit 1
}

# The sims serve /registers as a JSON object of decimal address -> value (see
# internal/invariant.registerImage). A SunSpec model block is a header pair —
# id at address a, register length at a+1 — followed by that many data
# registers; lexa-proto's L704 layout is 65 registers wide (sunspec/derlayout_
# test.go pins it), so a shorter block is a sidecar serving something else.
echo "$BODY" | python3 -c '
import json, sys
raw = json.load(sys.stdin)
regs = {int(k): int(v) for k, v in raw.items() if str(k).lstrip("-").isdigit()}
for a, v in sorted(regs.items()):
    if v != 704 or (a + 1) not in regs:
        continue
    n = regs[a + 1]
    if n >= 65 and (a + 1 + n) in regs:
        print("model 704 at register %d, %d registers of data" % (a, n))
        sys.exit(0)
print("no full-length model 704 in %d registers" % len(regs), file=sys.stderr)
sys.exit(1)
' || {
  echo "preflight-modsim-704: $API/registers serves no full-length model 704 — this is not the DER sim the CSIP leg's oracle expects, and BASIC-010/013 will FAIL against it" >&2
  exit 1
}

echo "preflight-modsim-704: OK ($API)"
exit 0
