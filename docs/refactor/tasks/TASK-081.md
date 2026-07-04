# TASK-081 — V1.0 release-gate execution (checklist, conformance evidence, campaigns)

*Status: TODO · Phase: P6 · Effort: L (≈8 h active + multi-day gate wall-clock) · Difficulty: med · Risk: low*

## Objective
`09_RELEASE_CHECKLIST.md` is walked box by box on the release-candidate
builds of both repos: every ◆ hard gate satisfied with linked evidence
(or a written AD-entry waiver — the only escape hatch 09 allows),
conformance evidence regenerated, 10-cycle FAST and 10-cycle STOCK Mayhem
campaigns recorded, the 30-day soak signed off, and V1.0 tags pushed on
lexa-hub, csip-tls-test, and lexa-proto. This task is the program's
definition of done.

## Background
- 09_RELEASE_CHECKLIST.md (read it in full — it IS the work order) has
  eight sections: Process & CI, Safety & control behavior, Security,
  Certificates, Reliability & operations, Observability, Conformance &
  protocol, Performance & endurance, Multi-device & field readiness,
  Documentation & maintainability. ◆ boxes are hard gates ("no waivers
  without an AD entry in 02").
- Campaign machinery (verified): `python3 scripts/mayhem.py --dashboard
  http://69.0.0.20:8080` (exit 0 = no FAIL/BLIND); `scripts/mayhem-100.sh`
  is the loop-runner pattern (100 runs → adapt/trim to 10-cycle; each
  cycle logged + summary TSV); FAST/STOCK via `bash scripts/bench-up.sh
  --fast|--stock` + `scripts/hub-replay-tune.sh`; baseline to beat:
  09 demands 0 FAIL, 0 BLIND, DEGRADEDs ⊆ accepted ledger — note this is
  STRICTER than the V6 0.6-FAIL/cycle defense baseline; the delta closed
  during P5 (066's gate) or it blocks here.
- Conformance: `scripts/run-conformance.sh` (CSIP layers 1-3 evidence),
  `sim/modsim-conformance -device inverter|battery|meter`, updating
  `CONFORMANCE_REPORT.md` (the conformance skill/docs describe the
  procedure — follow the repo's established flow).
- Soak: TASK-078's rig; 09 wants "30-day soak: flat RSS/fd/goroutine,
  zero watchdog fires, netem chaos windows survived" — the run must have
  STARTED ≥30 days before this task can close (schedule awareness:
  confirm the manifest date first; if the soak was invalidated
  (redeploy), this task BLOCKS until a fresh window completes — flag
  early).
- Evidence conventions: campaign reports under `docs/`
  (`QA_REPORT_*` pattern, per-cycle JSON like `logs/qa_cycles_v5/`);
  06 §4: "campaign evidence is versioned … phase-exit reports referenced
  from 00_MASTER_INDEX."
- Tagging: three repos (lexa-hub, csip-tls-test, lexa-proto), annotated
  tags `v1.0.0` on the exact evidence SHAs; both product/bench repos must
  pin the SAME lexa-proto version (the TASK-024 CI gate proves it).

## Why this task exists
09's header: "The definition of 'shippable to a paying utility.'…
Executed as TASK-081." Every phase built toward this walk; the walk
itself is real work: evidence gathering, re-runs, waiver adjudication,
and the discipline not to hand-wave a red box.

## Architecture review sections
§13 (stock-timing hole → item 11) · §15 (the 12-month plan's end state) ·
06 §Mayhem campaign gates · 07 GAP-15 · 08 (walk every Open row at this
boundary) · 02 (waiver ADs) · 09 (all).

## Prerequisites
ALL of TASK-001…080 DONE (04: depends on "all"). Practically: verify via
00_MASTER_INDEX status table; any TODO/IN-PROGRESS row = this task is
blocked (or the box gets a waiver AD — rare by design). Soak clock
started ≥30 days prior. Bench + both repos + lexa-proto releasable.

## Files
- **Read first:** docs/refactor/09_RELEASE_CHECKLIST.md;
  00_MASTER_INDEX.md status; docs/refactor/08_RISK_REGISTER.md;
  CONFORMANCE_REPORT.md; the accepted-DEGRADED ledger (V5/V6 reports +
  P5 updates); TASK-078's soak manifest + weekly reports.
- **Modify:** 09_RELEASE_CHECKLIST.md (check boxes + evidence links),
  00_MASTER_INDEX.md (program status → released), 08_RISK_REGISTER.md
  (phase-boundary walk: close/carry rows with evidence),
  CONFORMANCE_REPORT.md (regenerated results), 02 (any waiver ADs).
- **Create:** `docs/QA_REPORT_V1_0_FAST_<date>.md` +
  `docs/QA_REPORT_V1_0_STOCK_<date>.md` (campaign reports),
  `docs/RELEASE_V1_0.md` (the evidence index: one page linking every
  checked box to its artifact — the doc a due-diligence reviewer opens
  first).

## Blast radius
No code changes authored by this task (any red box spawns a FIX outside
this task, then re-walk the affected section). Bench occupancy: ~2-3
days of campaign wall-clock (10-cycle FAST ≈ overnight; 10-cycle STOCK
is LONGER per cycle — budget accordingly) + re-runs.

## Implementation strategy
Freeze → verify → measure → record → tag. Freeze release-candidate SHAs
on `main` of all three repos (CI green, zero uncommitted — the 09
process gates). Walk the checklist in dependency order: process/CI boxes
first (cheap, and they gate trust in everything else), then the
measurement gates (campaigns, conformance, soak review), then
documentation gates. Every box gets: evidence link + date + SHA. A red
box: file the finding, fix lands as its own reviewed change, re-run the
MINIMAL invalidated evidence set, re-freeze if product code changed.

## Detailed steps
1. Freeze: record candidate SHAs (both repos + lexa-proto); `git status`
   clean everywhere; CI green links; branch protection screenshot/link
   (09 Process ◆).
2. Bench prep: full deploy of the frozen SHAs (hub via deploy-hub-pi.sh,
   sims via update-sim-pis.sh, SAME session — MTR-4), then
   `bash scripts/bench-up.sh --fast` (deploy resets timing: re-tune).
   Verify bench health (probes per BENCH.md) before any measurement.
3. 10-cycle FAST campaign: loop `scripts/mayhem.py` ×10 (mayhem-100.sh
   trimmed, or a `for i in $(seq 1 10)` equivalent capturing per-cycle
   JSON via `--json`); write QA_REPORT_V1_0_FAST: per-cycle table,
   repeat-offender tally, verdict vs accepted ledger. Gate: 0 FAIL,
   0 BLIND, DEGRADEDs ⊆ ledger.
4. 10-cycle STOCK campaign: `bench-up.sh --stock`, confirm hub timing
   stock, run ×10, report as above; restore `--fast` after. (GAP-15
   closure: the shipped timing is the tested timing.)
5. Preservation-ledger spot runs: each ledger scenario individually
   `--only <id>` on the frozen build (09 Safety ◆) — mostly satisfied by
   the campaigns but the ◆ asks for individually-green evidence; script
   the list once, attach outputs.
6. Conformance: `scripts/run-conformance.sh` on the frozen build; all
   three `sim/modsim-conformance` device types; update
   CONFORMANCE_REPORT.md; golden-fixture CI (075) green link; poll-rate
   compliance evidence (071); curve-functions AD pointer (080).
7. Security/cert boxes: broker ACL + `allow_anonymous false` configs
   (013/014 evidence), OCPP wss (074 evidence), cipher-pinning audit
   (grep `RequireClientCert` across servers — rerun the audit fresh, do
   not link a stale one), key-hygiene audit (`git ls-files | grep -i
   key`, deployment perms), cert monitor + rotation runbook + churn soak
   (072/073).
8. Reliability/observability: watchdog wedge-test evidence (007/008),
   restart-safety scenarios (043), journald caps (009), tick-overrun
   counter under mqtt-latency (046), metrics dashboards (044/045),
   journal rotation proof (039/040).
9. Soak sign-off: TASK-078 manifest + 4 weekly reports; final
   `soak-report.py` run over the full window; assert flat trends + zero
   watchdog fires; archive.
10. Multi-device + field boxes: 065 scenario evidence; plant-parameter
    docs (064); field-pilot row — if no pilot completed, this ◆-less box
    is either checked with pilot evidence or explicitly carried as a
    post-tag action item agreed with the owner (it is not marked ◆ —
    record the owner's call in RELEASE_V1_0.md).
11. Documentation boxes: CLAUDE.md invariants current (both repos);
    operator runbook; onboarding doc RSK-11 test (a non-author follows
    it — recruit the reviewer); god-file audit (`wc -l` sweep, 066/068).
12. Risk-register boundary walk (08's cadence): every Open row → closed
    with evidence or carried with a post-V1.0 owner note.
13. Assemble docs/RELEASE_V1_0.md (box → evidence map); update 09 boxes
    + 00_MASTER_INDEX.
14. Tag: annotated `v1.0.0` on all three repos at the evidence SHAs;
    push; verify both repos' go.mod pin the tagged lexa-proto version.
    Commit trailer discipline applies to the release commits.

## Testing changes
None authored; this task RUNS the program's entire test surface and
archives results. Commands as cited in steps 3-9.

## Documentation changes
09 (checked), 00 (status), 08 (walked), CONFORMANCE_REPORT.md,
RELEASE_V1_0.md, QA_REPORT_V1_0_{FAST,STOCK}.

## Common mistakes to avoid
- Evidence by assertion ("we ran it in P5") — every ◆ links artifacts
  produced against the FROZEN SHAs; stale evidence is the whole reason
  09 exists.
- Fixing a red box inline inside this task (bypasses review + campaign
  attribution; fixes are separate changes, then re-walk).
- Running STOCK cycles with the hub accidentally left in FAST (or vice
  versa) — assert timing mode in each cycle's log (hub-replay-tune
  state), the deploy-resets-to-STOCK gotcha cuts both ways.
- Letting DEGRADED drift pass unexamined: a NEW degraded signature is a
  finding (06 §4.4), even at 0 FAIL.
- Tagging before the lexa-proto pin check (a skewed module version in
  the tag is a due-diligence embarrassment and an MTR-4 regression
  vector).
- Bench contention: campaigns, soak tail, and conformance runs
  serialized, not interleaved.

## Things that must NOT change
- The oracles and accepted-verdict ledger (never tuned to pass a release
  — 06 §4.5; a gap found now gets an expected-FAIL pin + waiver AD or
  blocks the release).
- The frozen SHAs once measurement starts (any product change restarts
  the affected evidence).
- 09's ◆ semantics: no unwaivered red ◆ at tag time, period.

## Acceptance criteria
- [ ] Every 09 box checked with a working evidence link, or waived via a
  named AD entry in 02 (list of waivers in RELEASE_V1_0.md — target: 0).
- [ ] QA_REPORT_V1_0_FAST + _STOCK: 10 cycles each, 0 FAIL, 0 BLIND,
  DEGRADEDs ⊆ ledger.
- [ ] CONFORMANCE_REPORT.md regenerated on the frozen build.
- [ ] Soak: 30-day window complete, assertions green.
- [ ] Risk register walked; RELEASE_V1_0.md merged.
- [ ] `v1.0.0` tags on three repos; module pins verified.

## Regression checklist
- [ ] CI green on frozen SHAs, both repos (+ lexa-proto)
- [ ] Conformance: full evidence regenerated (mandatory)
- [ ] Mayhem: 10-cycle FAST + 10-cycle STOCK (mandatory)
- [ ] Bench restored to normal FAST/demo state after the gate

## Mayhem scenarios affected
All — as measurement, not modification. The campaign reports are the
release's primary safety evidence.

## Conformance implications
The release's CSIP/SunSpec/OCPP claims are exactly what the regenerated
evidence + AD-010 statement say. This task produces the certification
pre-audit package (§15).

## Suggested commit message
`release: V1.0 gate — checklist walked, campaigns + conformance + soak evidence, tags`
(+ trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`)

## Suggested PR title & description
**Title:** V1.0 release gate execution
**Description:** 09 walked with evidence index (RELEASE_V1_0.md);
FAST+STOCK 10-cycle reports; conformance regenerated; soak signed off;
risk register walked; waivers: <list or none>. Risk: low (measurement).
Rollback: tags are immutable; a post-tag blocker → v1.0.1 process.

## Code review checklist
- Spot-verify ≥5 random evidence links resolve to artifacts at the
  frozen SHAs.
- Waiver ADs (if any) genuinely argued.
- Timing-mode assertions present in both campaign logs.

## Definition of done
Acceptance criteria + regression checklist + docs updated + status headers
(this file + 00_MASTER_INDEX) updated — and the tags exist.

## Possible follow-up tasks
Post-V1.0: field-pilot completion (if carried), 10_BACKLOG grooming,
third-party certification engagement, v1.1 planning from carried risks.
