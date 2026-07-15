# QA — Standards Build-Out Supplemental Suite (2026-07)

**STATUS: implemented + committed 2026-07-15** — 17 scenarios (tracks B/C/D), sim 7xx surface
(track A), VTN stub, 94 oracle unit tests; catalog-verified (45→62 scenarios). Bench campaign of
the flag-dependent scenarios pending (see Validation).

Covers the lexa-hub standards build-out (17 WPs; see `../lexa-hub/docs/standards-buildout/`).
Extends the Mayhem fault-injection suite (`cmd/dashboard/mayhem.go` scenarios + `qa/scenarios/*.json`,
oracles in `oracleRegistry`) and the `tests/*.go` conformance suite. Invariants live in
`docs/QA_FAULT_INJECTION.md`.

## New invariants

- **INV-REPORT** — the hub PUTs DERCapability/Settings/Status/Availability to the server and
  POSTs LogEvent alarm+RTN pairs; a PIN freeze suspends ALL server egress (PUT/MUP/Response/LogEvent)
  and heal resumes it. Source of truth: gridsim `/admin/derputs`, `/admin/logevents`, `/admin/alerts`.
- **INV-CANNOTCOMPLY-VOCAB** — a forced breach posts IEEE 2030.5 Table 27 Response codes
  (253/8/3/10/13/14), not the legacy vendor 0xF0, when `legacy_cannotcomply_code=false` (product default).
  Source: gridsim `/admin/alerts` `vocab` tag.
- **INV-REDIRECT** — the hub follows 301/302 within `redirect_max`, fails closed (holds LKG, no crash)
  beyond it. Source: gridsim `/admin/redirect` + hub walk success/journal.
- **INV-ADV-READBACK** — advanced-DER curve/PF/energize provisioning trusts *measured readback*, not the
  write/adopt handshake: an inverter that reports AdptCrvRslt=COMPLETED while curve-1 readback stays stale
  must be caught (adopt_state=diverged, not adopted). Shadow mode does ZERO writes. Source: modsim 7xx
  models + hub `lexa/reconcile/adv/+/report`.
- **INV-AUS** — gen-aus/load-aus shadow constraints stay 0-divergence vs the live cascade; when enforced,
  the gross generation/load cap holds with the convergence backstop. Source: real meter + hub metrics.
- **INV-OCPP16** — a 1.6J charger connects, obeys SetChargingProfile, releases on ClearChargingProfile;
  identical hub-side reconciler contract as 2.0.1.
- **INV-PAIRING** — an unknown charger is held Pending (no plant, no transactions) until approved.
- **INV-V2G-CHARGEONLY** — an EV discharge setpoint is clamped to 0 A at actuation (charge-only until a
  V2X path exists), provable at the evsim draw.
- **INV-OPENADR** — the VEN adopts VTN price/limit signals; CSIP wins on conflict; an OpenADR-only cap
  bind does NOT post a 2030.5 CannotComply.

## Scenario matrix (owner track in brackets)

| ID | Invariant | Needs | Track |
|---|---|---|---|
| der-report-roundtrip | INV-REPORT | /admin/derputs | B |
| pin-freeze-egress-halt | INV-REPORT | northbound.json registration_pin | B |
| logevent-alarm-pair | INV-REPORT | modsim 701 Alrm knob (A) | B |
| cannotcomply-table27 | INV-CANNOTCOMPLY-VOCAB | /admin/alerts vocab | B |
| dcap-redirect / redirect-storm | INV-REDIRECT | /admin/redirect | B |
| adv-shadow-no-writes | INV-ADV-READBACK | modsim 7xx (A), reconciler.adv=shadow | C |
| curve-adopt-readback-divergence | INV-ADV-READBACK | modsim curve-adopt-lies fault (A) | C |
| pf-var-measured-convergence | INV-ADV-READBACK | modsim 704 PF/Var (A) | C |
| aus-gen-cap / aus-load-cap | INV-AUS | enforce_aus_limits | C |
| ocpp16-smart-charge | INV-OCPP16 | evsim -proto 1.6 (done) | D |
| pairing-gate-hold | INV-PAIRING | pairing_mode=gated | D |
| clear-profile-release | INV-OCPP16 | evsim | D |
| ev-setpoint-clamp | INV-V2G-CHARGEONLY | ev_storage + evsim | D |
| openadr-limit-adopt / openadr-csip-precedence | INV-OPENADR | VTN stub sim (D) | D |

## Foundational sim gaps (track A — blocks B/C)

- **modsim serves no SunSpec model 701** (bench round-1 finding): state/alarm/measurement fields and adv
  curve adoption are untestable until added.
- 7xx curve models (705/706/711/712) with the read-only-curve-1 + AdptCrvReq/Rslt adopt handshake, plus a
  fault knob that reports COMPLETED while curve-1 readback stays stale (the exact INV-ADV-READBACK defense).
- 704 PF/Var immediate controls with measured effect, and a 701 Alrm-bit injection knob for LogEvent tests.

## Merge discipline

Each track adds scenarios in a NEW file (`mayhem_<track>.go`) exposing
`func (d *mayhemDriver) <track>Scenarios() []*mayScenario` and new oracles in that file; the central
`scenarios()` slice and `oracleRegistry` get one-line appends per track (reviewer-merged to avoid conflicts).
Prefer spec-JSON (`qa/scenarios/*.json`) when an existing oracle fits; Go literal + new oracle otherwise.

## Validation

Per track: `go build ./...`, oracle unit tests, spec-load tests. Full validation = a bench Mayhem
campaign of the new IDs against the dev kit (`scripts/mayhem.py --only <ids>`) after merge — restores the
bench between scenarios, so coordinate with any running soak.
