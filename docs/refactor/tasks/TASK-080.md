# TASK-080 — CSIP curve-functions scope ADR (volt-var / volt-watt: implement or de-scope)

*Status: TODO · Phase: P6 · Effort: M (≈4–6 h) · Difficulty: med · Risk: low*

## Objective
AD-010 is resolved with a written, evidence-based decision: either V1.0
implements closed-loop CSIP-driven curve dispatch (volt-var/volt-watt) —
in which case this task's output includes the follow-up task breakdown —
or V1.0 explicitly de-scopes curve functions in the product claims and
conformance statement. The deliverable is documentation: the AD entry,
the survey evidence, and either follow-up tasks or the de-scope
statement. No product code changes in this task.

## Background
Verified survey starting points (do the full survey as step 1):
- **Southbound write paths EXIST and are tested** (lexa-hub
  internal/southbound/derbase — post-P1 in lexa-proto; verify home):
  `ReadVoltVar`/`WriteVoltVar` (derbase.go:440-466),
  `ReadVoltWatt`/`WriteVoltWatt` (:468-494), voltage/freq trip sets
  (:496-566), all via the SunSpec §3.1.2 adopt workflow — `adoptCurve`
  staging-write → `AdptCrvReq` → poll `AdptCrvRslt` (:390-438); models
  705/706 (`ModelDERVoltVar`/`ModelDERVoltWatt`, capability detection
  :66-67); curve handshake tested in derbase_csip_test.go
  (TestCSIP_VoltVarAdoptWorkflow, :205+ — staging curve isolation
  asserted).
- **Northbound model support EXISTS:** `DERControlBase` carries
  `OpModVoltVar`, `OpModVoltWatt`, `OpModFreqWatt`, `OpModWattPF`, and
  the HFRT/HVRT/LFRT/LVRT trip CurveLinks
  (internal/northbound/model/der.go:238-257; `CurveLink` :101-104;
  `ModeVoltVar` flag :21); the walker fetches DERCurveList
  (walker.go:392) and gridsim serves curves (the curve-attack scenario
  exists; `countProgramsWithCurves`/`curveSummary` publish curve METADATA
  in the schedule message, cmd/northbound/main.go:311-321, 452).
- **The gap [verified]:** nothing DRIVES the derbase curve writers from
  CSIP. `bus.ActiveControl` (internal/bus/messages.go:28-39) carries only
  Connect/ExpLimW/ImpLimW/MaxLimW/FixedW — no curve fields; the
  scheduler's resolved control and lexa-modbus's control applicator have
  no curve path. Review §15: "volt-var/volt-watt already have derbase
  write paths; nothing drives them from CSIP today [Likely]" — CONFIRMED.
- Decision context: CSIP/IEEE 1547 deployments in most US jurisdictions
  REQUIRE autonomous volt-var/volt-watt with utility-updatable curves;
  but many DERMS programs run fixed default curves configured at
  commissioning (device-local autonomy) with the hub only needing
  pass-through updates. De-scope is acceptable for V1.0; silence is not
  (AD-010).

## Why this task exists
02 AD-010 is OPEN; 09 checklist line "Curve-functions scope: implemented
**or** de-scoped in writing" blocks the release gate; §15 flags it as a
commercialization decision needing market/certification input.

## Architecture review sections
§15 (months 9-12) · 02 AD-010 · 09 Conformance & protocol · D4/W3
context (the write paths live in the shared module).

## Prerequisites
None hard (Track F). Useful inputs: TASK-075 progress (vendor fixtures
show which real devices expose 705/706), any utility/market guidance the
project owner can supply — the task must EXPLICITLY request it (step 4)
rather than guess.

## Files
- **Read first:** derbase.go (write paths + adopt workflow + capability
  probe), derbase_csip_test.go; model/der.go (DERControlBase curve
  fields); scheduler.go (what a resolved control exposes);
  internal/bus/messages.go (ActiveControl); cmd/modbus control
  applicator (DERControlBase translation); sim/gridsim curve serving +
  the curve-attack scenario (cmd/dashboard/mayhem.go:2720);
  sim/southbound curve support in the sims (what the bench could
  validate today); CONFORMANCE_REPORT.md (current claims).
- **Modify:** `docs/refactor/02_ARCHITECTURE_DECISIONS.md` (AD-010
  entry), `docs/refactor/10_BACKLOG.md` (if de-scope) or new TASK files
  are NOT minted — follow-ups go to 10_BACKLOG with effort estimates for
  the owner to schedule (04's rule: task IDs are the graph's to assign).
- **Create:** `docs/refactor/adr-inputs/curve-functions-survey.md`
  (the evidence document; location per existing docs conventions — put
  it under docs/refactor/ if adr-inputs/ feels heavy, one file either way).

## Blast radius
Documentation only. The DECISION has product-scope consequences
(conformance claims, certification scope, sales collateral) — which is
why it is an AD, not a code PR.

## Implementation strategy
Survey → gap-size → decision matrix → recommendation → AD entry.
Quantify the implementation gap precisely enough that "implement" has an
honest cost (it is NOT small: bus schema, scheduler resolution of curve
links + curve fetch/cache, modbus-side adopt orchestration with retry/
verify, sim support, new Mayhem scenarios, conformance additions) and
"de-scope" has an honest consequence list (certification limits, target
utility programs excluded).

## Detailed steps
1. Complete the survey (grep beyond the verified anchors):
   `grep -rn "VoltVar\|VoltWatt\|OpModVV\|705\|706\|CurveLink\|
   DERCurve"` across lexa-hub, lexa-proto, csip-tls-test — table:
   layer × capability (model decode / walker fetch / scheduler resolve /
   bus / applicator / derbase write / sim serve / sim device / scenario /
   conformance case), each marked EXISTS(ref)/MISSING.
2. Trace one hypothetical dispatch end-to-end and enumerate every
   missing hop: DERControl with OpModVoltVar → scheduler must resolve
   CurveLink → walker must fetch + cache the DERCurve points → bus needs
   a versioned curve payload (envelope per AD-006) → lexa-modbus
   translates to sunspec.VoltVarCurve → derbase adopt workflow → verify
   via AdptCrvRslt + readback → CannotComply on adopt failure. Estimate
   each hop (S/M/L) — this is the "implement" bill.
3. Bench/validation bill: do the sims implement 705/706 register
   behavior? (check sim/southbound + modsim-conformance device
   expectations); what scenarios would the QA bar require (curve adopt
   under churn, adopt-reject, curve+cap interaction)?
4. Market/certification input: draft the three questions for the owner
   (target utility programs' curve requirements? certification lab scope
   for V1.0 — 1547.1 curve tests in or out? any LOI/pilot contract
   language mentioning volt-var?) and record answers or "unanswered as of
   <date>" in the survey doc. The AD may be conditional
   ("de-scope unless pilot X requires…") but must then name the trigger
   and revisit date.
5. Decision matrix in the survey doc: implement-now / implement-partial
   (pass-through curve update without closed-loop verify — probably
   WORST option, argue why) / de-scope-with-autonomous-default-curves
   (devices keep vendor/commissioned curves; hub neither reads nor
   writes them; document that derbase support exists for post-V1.0).
6. Write AD-010 in 02 per the house format (Problem/Decision/
   Alternatives/Tradeoffs/Migration/Open questions), status 🔶 or ✅.
7. If de-scope: draft the conformance-statement language (explicit list
   of unsupported DERControlBase fields — OpModVoltVar/OpModVoltWatt/
   FreqWatt/WattPF + trip curves as applicable; confirm current behavior
   when a control carries them: verified model-decode exists, so the
   scheduler RESOLVES such controls — what does the hub DO with the
   curve fields today? Trace it: likely silently ignores → the statement
   must say "acknowledged and ignored" or a follow-up makes the hub
   REJECT/flag them — recommend the flag: log + metric on ignored curve
   fields, add to backlog with S estimate). Update CONFORMANCE_REPORT.md
   claims section reference (the report itself regenerates in 081).
8. If implement: write the backlog breakdown with the step-2 hop
   estimates and the QA bill from step 3, sequenced after P5.

## Testing changes
None (docs task). If step 7's trace reveals the hub misbehaves on
curve-bearing controls TODAY (crash/zero-value rather than ignore), file
that as an immediate bug with a reproducing gridsim config — the
curve-attack scenario already probes empty curve LISTS, not curve-bearing
CONTROLS; note the scenario gap in the survey.

## Documentation changes
The task IS documentation: AD-010 entry, survey doc, backlog entries,
conformance-claims language, 00_MASTER_INDEX status.

## Common mistakes to avoid
- Deciding from vibes: every EXISTS/MISSING cell carries a file:line.
- Treating "derbase has write paths" as "mostly done" — the missing hops
  (scheduler curve resolution, bus schema, adopt orchestration, QA) are
  the majority of the work; the write paths are the EASY part.
- De-scoping silently (the 09 line requires the WRITTEN statement and
  conformance-claims alignment).
- Minting TASK-0NN IDs for follow-ups (04 owns the ID space; backlog
  entries with estimates instead).
- Ignoring what the hub does TODAY with curve-bearing controls (step 7's
  trace — an "acknowledged and ignored" claim must be TRUE).

## Things that must NOT change
- No product/bench code in this task.
- derbase curve support stays (whatever the decision — it is shared-
  module capability, tested, and the post-V1.0 path either way).
- Existing conformance evidence remains valid (claims text changes only
  with the decision).

## Acceptance criteria
- [ ] Survey doc: complete layer×capability table with refs; end-to-end
  hop list with estimates; today's-behavior trace for curve-bearing
  controls.
- [ ] Market/certification questions asked and answers (or their
  absence) recorded.
- [ ] AD-010 entry merged with decision + revisit trigger.
- [ ] De-scope statement drafted (or implement breakdown in backlog).
- [ ] 09 checklist curve line satisfiable by pointing at the AD.

## Regression checklist
- [ ] `make test-fast` / `go test -race ./internal/...` untouched-green
  (no code changed — run once as hygiene)
- [ ] Conformance logic tests: none
- [ ] Mayhem: none
- [ ] Docs build/links check (00_MASTER_INDEX references resolve)

## Mayhem scenarios affected
None now. Survey notes the curve-bearing-control scenario gap for the
backlog (curve-attack covers empty lists only).

## Conformance implications
Central: the decision DEFINES the V1.0 CSIP conformance claims for DER
curve function sets. The de-scope path must enumerate ignored
DERControlBase fields in CONFORMANCE_REPORT.md language.

## Suggested commit message
`docs(adr): resolve AD-010 — CSIP curve functions <implemented|de-scoped> for V1.0 (survey attached)`
(+ trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`)

## Suggested PR title & description
**Title:** AD-010: CSIP volt-var/volt-watt scope decision
**Description:** Full-stack survey (write paths exist; dispatch chain
missing — hop table attached); decision + rationale + market input
status; conformance-claims language; backlog entries. Risk: none (docs).
Rollback: n/a (AD supersession process).

## Code review checklist
- Every survey cell spot-checkable via its ref.
- The today's-behavior trace is evidence-based, not assumed.
- Decision consequences (certification, claims) explicit.

## Definition of done
Acceptance criteria + regression checklist + docs updated + status headers
(this file + 00_MASTER_INDEX) updated.

## Possible follow-up tasks
Backlog (not IDs): curve-dispatch implementation hops (if implement);
ignored-curve-field flagging; curve-bearing-control Mayhem scenario;
post-V1.0 revisit at the AD's trigger.
