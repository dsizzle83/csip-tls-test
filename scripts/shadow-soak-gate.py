#!/usr/bin/env python3
"""shadow-soak-gate.py — evaluate the per-axis flip gate (WS-5.2) against the
soak recorder's data (scripts/shadow-soak-recorder.sh -> logs/shadow-soak/).

Gate spec (docs/refactor/notes/TASK-063-seam-review.md §3, HANDOFF §8 WS-5.2):
  - Compliance axes (solar-ceiling-w, breach, connect, grid): 0 divergences,
    off-cap AND on-cap. Any event here FAILS the gate.
  - Economics residual axes (evse-current-a, battery-setpoint-w): permitted
    ON-CAP ONLY (an active/default CSIP control in state) — the characterized
    irreducible interleave residual that vanishes at the flip. An economics-axis
    event with NO active control in state FAILS the gate (off-cap must be 0).
  - Safety path ("safety:"-prefixed axes / metric): 0. No carve-out.
  - Panic latch: 0 trips.
  - TRIAGE flag (not auto-fail, prints prominently): battery-setpoint-w events
    at SOC <= 15% (the open TASK-061 SOC-10.57%% export-authored finding's
    signature) — these need manual attribution before the export flip.

Usage: python3 scripts/shadow-soak-gate.py [--since ISO8601] [--dir logs/shadow-soak]
Exit 0 = gate PASS, 1 = FAIL, 2 = no data.
"""
import argparse, json, re, sys, collections, datetime, urllib.request

ECON_AXES = {"evse-current-a", "battery-setpoint-w"}
LOW_SOC_TRIAGE = 15.0

def parse_line(line):
    m = re.search(r'diff="(.*)"\s*$', line)
    raw = (m.group(1) if m else line).replace('\\"', '"')
    try:
        return json.loads(raw[raw.index('{'):])
    except Exception:
        return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default="logs/shadow-soak")
    ap.add_argument("--since", default=None, help="ISO8601; only events at/after this ts")
    ap.add_argument("--hub", default="69.0.0.2")
    args = ap.parse_args()
    since = int(datetime.datetime.fromisoformat(args.since).timestamp()) if args.since else 0

    events, skipped = [], 0
    for name in ("divergence-backfill.jsonl", "divergence.jsonl"):
        try:
            for line in open(f"{args.dir}/{name}"):
                d = parse_line(line)
                if d is None:
                    skipped += 1
                elif d.get("ts", 0) >= since:
                    events.append(d)
        except FileNotFoundError:
            pass
    if not events and skipped == 0:
        print("NO DATA — recorder produced no divergence events in window"); return 2

    fail, triage = [], []
    tally = collections.Counter()
    for d in events:
        oncap = "csip" in json.dumps(d.get("state", {}))  # any control incl. default
        state_csip = (d.get("state") or {}).get("csip", "")
        for a in d.get("axes", []):
            ax = a["axis"]; tally[ax] += 1
            if ax.startswith("safety:"):
                fail.append(("SAFETY-PATH", d["ts"], a)); continue
            if ax not in ECON_AXES:
                fail.append(("COMPLIANCE-AXIS", d["ts"], a)); continue
            if not state_csip:  # economics axis but no active control = off-cap
                fail.append(("ECON-OFF-CAP", d["ts"], a)); continue
            if ax == "battery-setpoint-w":
                socs = [b.get("soc", 100) for b in (d.get("state", {}).get("batteries") or [])]
                if socs and min(socs) <= LOW_SOC_TRIAGE:
                    triage.append((d["ts"], a, min(socs), state_csip))

    # Live metrics cross-check
    metrics = {}
    try:
        txt = urllib.request.urlopen(f"http://{args.hub}:9101/metrics", timeout=5).read().decode()
        for pat in ("lexa_constraint_shadow_panic_latched", "lexa_constraint_shadow_panics_total",
                    "lexa_constraint_shadow_safety_divergence_total"):
            m = re.search(rf"^{pat} (\S+)$", txt, re.M)
            if m: metrics[pat] = float(m.group(1))
    except Exception as e:
        print(f"WARN: metrics scrape failed: {e}")

    print(f"events={len(events)} (parse-skipped={skipped})  axis tallies: {dict(tally)}")
    print(f"live metrics: {metrics}")
    ok = True
    if metrics.get("lexa_constraint_shadow_panic_latched", 0) > 0 or metrics.get("lexa_constraint_shadow_panics_total", 0) > 0:
        print("FAIL: panic latch tripped"); ok = False
    if metrics.get("lexa_constraint_shadow_safety_divergence_total", 0) > 0:
        print("FAIL: Tier-1 safety-path divergence (metric)"); ok = False
    for kind, ts, a in fail[:20]:
        print(f"FAIL[{kind}] ts={ts} {a}"); ok = False
    if len(fail) > 20:
        print(f"... and {len(fail)-20} more failing events"); ok = False
    for ts, a, soc, csip in triage[:10]:
        print(f"TRIAGE[low-SOC battery axis] ts={ts} soc={soc} csip={csip} {a}")
    if triage:
        print(f"TRIAGE: {len(triage)} low-SOC battery-setpoint events need manual attribution "
              f"(TASK-061 SOC-10.57% open finding) before the export flip")
    print("GATE:", "PASS" if ok else "FAIL")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
