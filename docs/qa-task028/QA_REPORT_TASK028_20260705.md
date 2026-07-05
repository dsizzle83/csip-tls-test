# TASK-028 — battery reconciler active-mode flip: QA evidence (2026-07-05)

First live write-path change of R1: `lexa-modbus` flipped to
`"reconciler":{"battery":"active"}` on the bench (69.0.0.1), FAST mode,
mqttproxy `:1882` path intact. Legacy battery command topic kept publishing
(belt and braces). Tier-0 interlock verified senior.

Raw logs: `gate-20260705-154918.log` (targeted), `campaign-20260705-155929.log`
(full 51).

## Live verification (journal, real bench)

- `battery reconciler active mode active for 1 device(s)` — flip took.
- `reconciler[active] battery-0: applied SetpointW=-334 (reason=new-desired)` —
  reconciler owns hardware writes through the registry path.
- `legacy battery command ignored (reconciler active) battery-0: SetpointW=-244`
  — legacy stream still arriving, ignored on hardware, logged once per change.
- `reconciler[active] … applied SetpointW=0,Connect=true (reason=reconnect-reassert)`
  after a batsim session drop — **P2 carry-forward #1**: `Reconnected` wired and
  correcting within one poll+readback (the shadow never fed it).
- Retained desired doc on `lexa/desired/battery/battery-0`
  (`setpoint_w:0, connect:true, seq:1`).
- Rollback rehearsed: set `shadow` → restart → `reconciler[shadow]` recorder
  resumes (legacy authoritative again) → set `active` → restart → back.

## Ledger gate — targeted battery set (each PASS or accepted-DEGRADED)

| Scenario | Verdict | Note |
|---|---|---|
| export-cap-full-battery | DEGRADED | accepted (cannot_comply=True; boundary-flaky, task-pinned accepted) |
| battery-wrong-sign | **PASS** | INV-SOC/INV-EXPORT/SAFETY held; **no INV-HUNT/oscillation** — interlock seniority proven |
| battery-soc-refuse | PASS | (flipped D→P vs shadow baseline; the one-poll-faster reaction) |
| battery-charge-disabled | DEGRADED | accepted (cannot_comply=True resource limit) |
| battery-nan-sentinel | **PASS** | 0x8000 sentinel withheld |
| hub-restart-mid-cap | **PASS** | retained-control re-adopt held |
| mqtt-broker-restart | DEGRADED | accepted (cannot_comply=True; INV-EXPORT held; retained-doc re-seed) |

Tally: **3 PASS / 4 DEGRADED / 0 FAIL / 0 BLIND**. No INV-HUNT/oscillation
anywhere; SAFETY held.

## Full 51-scenario FAST campaign

**33 PASS / 18 DEGRADED / 0 FAIL / 0 BLIND / 0 INCONCLUSIVE.**

Within the 34P/17D shadow-gate band: the single net P→D drift is
`export-cap-full-battery` (the documented accepted boundary-flake; task
"must NOT change" pins its accepted DEGRADED). `solar-reboot-forget` held PASS.

Battery family in the full run: battery-wrong-sign **PASS**, battery-reboot
**PASS** (reconnect-reassert end-to-end), battery-nan-sentinel **PASS**;
battery-soc-refuse / battery-charge-disabled / battery-empty-import-cap /
export-cap-full-battery all **DEGRADED with cannot_comply=True** (accepted
resource-limit class, blind=False, errs=0). No FAIL, no BLIND, no SAFETY
violations, no oscillation across the whole campaign.

## Behavior deltas observed (all expected)

1. **One-poll-faster reaction (P2 #3):** battery-wrong-sign and battery-soc-refuse
   reached PASS in the targeted run (legacy's 60 s watchdog vs the reconciler's
   poll+readback). Under full-campaign timing battery-soc-refuse settled back to
   its baseline accepted-DEGRADED — both outcomes are PASS-or-accepted.
2. **Connect-completeness hold (P2 #2):** the battery desired doc carries
   `connect`, and lexa-modbus has no Connect readback register, so Observe-driven
   write-on-diff holds; the fast-correction path for a reverted/rebooted pack is
   the wired `Reconnected` reassert (verified live).
3. **Interlock seniority (L8):** no guard-vs-guard oscillation — battery-wrong-sign
   held INV-SOC clean with the interlock senior to the reconciler.
