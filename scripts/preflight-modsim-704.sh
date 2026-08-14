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
#             1 = it does not (unreachable, unparseable, no SunSpec chain,
#                 or a chain carrying no full-length model 704).
set -uo pipefail

API="${1:-${MODSIM_API:-http://69.0.0.20:6020}}"

BODY="$(curl -fsS --max-time 5 "$API/registers" 2>/dev/null)" || {
  echo "preflight-modsim-704: GET $API/registers did not answer — the BASIC-010/013 southbound oracle has no DER to read, and both rows will FAIL" >&2
  exit 1
}

# The sims serve /registers as a JSON object of decimal address -> value (see
# internal/invariant.registerImage), and the map is SPARSE: zero-valued
# registers are omitted, and the oracle's own transport reads any unset
# register as zero ("Unset registers read zero", invariant/sources.go's
# memTransport). So a check that demanded the 704 block's DATA registers be
# literally present would false-fail a healthy sim whose 704 data happens to
# hold zeros — which is what the live bench modsim serves before any control
# lands.
#
# But sparseness is not a licence to look for a VALUE. A scan for "some
# register holding 704 with a >= 65 neighbour" passes on any adjacent pair that
# happens to carry those numbers — M103_W = 704 W mid-ramp beside its W_SF, for
# one, and this sim ships a bad_scale fault that parks exactly that shape.
# Presence of a model is a STRUCTURAL fact, so this walks the structure the
# oracle walks (2026-08-14):
#
#   1. find the SunS header (0x5375 0x6e53) at one of the spec-permitted base
#      addresses, in lexa-proto sunspec.probeBases' own order — 40000 first,
#      then 0, then 50000 — and stop at the first base that presents it, which
#      is what ScanProbe does ("Header found: this IS the device's base");
#   2. from base+2, read (model id, length) header pairs, advancing 2 + length
#      each time, up to sunspec.maxScanModels (256) headers, exactly as
#      scanModels does;
#   3. succeed on model id 704 with a declared length >= 65 (lexa-proto's L704
#      layout is 65 registers wide; sunspec/derlayout_test.go pins it), and
#      fail on the 0xFFFF end marker, an over-long chain, or a walk that would
#      run past the 16-bit address space.
#
# A 704 found this way is a model the oracle's own reader will find; a 704
# value sitting anywhere else is not.
echo "$BODY" | python3 -c '
import json, sys

SUNS = (0x5375, 0x6E53)      # "S","u","n","S" — sunspec.SunSMagic0/1
PROBE_BASES = (40000, 0, 50000)  # sunspec.probeBases, in probe order
MAX_MODELS = 256             # sunspec.maxScanModels
END_MARKER = 0xFFFF
L704_LEN = 65

raw = json.load(sys.stdin)
regs = {}
for k, v in raw.items():
    ks = str(k)
    if not ks.lstrip("-").isdigit():
        continue          # a non-address key (a nested object) is not a register
    try:
        addr, val = int(ks), int(v)
    except (TypeError, ValueError):
        continue
    if 0 <= addr <= 0xFFFF:
        regs[addr] = val & 0xFFFF

def reg(a):
    # Unset registers read zero — the sidecar map is sparse and the oracle
    # reads it through memTransport, which zero-fills.
    return regs.get(a, 0)

def fail(msg):
    print(msg, file=sys.stderr)
    sys.exit(1)

base = next((b for b in PROBE_BASES if (reg(b), reg(b + 1)) == SUNS), None)
if base is None:
    fail("no SunS header at any of the bases %s in %d registers: this image has no SunSpec "
         "device on it at all" % (list(PROBE_BASES), len(regs)))

addr = base + 2
for _ in range(MAX_MODELS):
    mid = reg(addr)
    if mid == END_MARKER:
        fail("walked the whole SunSpec chain from base %d and reached the end marker without a model "
             "704" % base)
    n = reg(addr + 1)
    if mid == 704:
        if n < L704_LEN:
            fail("model 704 at register %d declares %d data registers, want >= %d — this block is too "
                 "short to be the DER control model the oracle decodes" % (addr, n, L704_LEN))
        print("model 704 at register %d, %d registers of data (SunSpec chain from base %d)" % (addr, n, base))
        sys.exit(0)
    nxt = addr + 2 + n
    if nxt > 0xFFFF or nxt <= addr:
        fail("the SunSpec chain from base %d is broken at register %d (model %d declares %d registers): "
             "the walk cannot continue" % (base, addr, mid, n))
    addr = nxt
fail("the SunSpec chain from base %d did not end within %d models — a broken or hostile image"
     % (base, MAX_MODELS))
' || {
  echo "preflight-modsim-704: $API/registers serves no full-length model 704 on its SunSpec chain — this is not the DER sim the CSIP leg's oracle expects, and BASIC-010/013 will FAIL against it" >&2
  exit 1
}

echo "preflight-modsim-704: OK ($API)"
exit 0
