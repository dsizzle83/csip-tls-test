# LEXA DERMS V1.0 Refactor — FINAL REPORT (code changes)

*2026-07-10. Closes the R4 constraint-controller program (HANDOFF §8 punch list
+ the shadow→active flip). Scope note from the owner: this is the final report
for **refactor code changes**. Product-release steps (30-day soak, vendor
golden fixtures, hosted `lexa-proto`, branch protection/PAT secrets) remain
open by design and are listed as the deferred remainder — they gate the *tag*,
not the *refactor*.*

## 1. Headline

**The R4 constraint stack is the live control core.** All five constraint axes
(export, gen, import, economics, battery-safety) are `active` on the bench hub;
the legacy `optimizer.go` cascade is present-but-suppressed (its writes to every
axis are dropped and counted — `lexa_constraint_legacy_override_dropped_axis_*`).
Every implementable workstream from the 2026-07-07 audit punch list (WS-1..WS-9)
is code-complete, reviewed, and merged. The flip is proven correct at both
cadences by direct hardware observation, not just campaign verdicts.

Delivered on the `refactor-endgame` branch of `lexa-hub` (deliberately NOT
`main` — `main` carries a concurrent extension program; see §6) and on `main`
of `csip-tls-test`.

## 2. What shipped (HANDOFF §8)

| WS | Item | Where |
|---|---|---|
| WS-1 | Security fail-closed defaults (OCPP SP2 required, lexa-api loopback, MQTT ACL default-on, systemd hardening) | hub `5bb5746` |
| WS-2 | Desired-doc heartbeat re-stamp (150s) + solar seed fail-closed; `consumer-restart-after-quiescence` scenario | hub `621ca0f`, csip `c1d3d5b` |
| WS-3 | Mayhem constraint-aware BLIND (dead judging-sensor → BLIND not vacuous PASS) + run-integrity hardening | csip `c99105c` |
| WS-4 | Snapshot default-on; NB responseTracker NDJSON persistence; real MRID plumbed into desired docs; phantom-episode heal; AD-016 | hub `c2ad03d`/`edb10eb`/`742139b`, csip `912ba62` |
| WS-5 | Shadow panic-latch + per-axis divergence metrics + Tier-1 safety shadow-diff; **FIX-F** active-mode composition + per-constraint mode map | hub `35f0952`, `211341a` |
| WS-7 | CI gates (gofmt, golangci-lint, -race, vendor content-verify) both repos + lexa-proto CI; gofmt sweeps | hub `f1e0d67`, csip `4469545` |
| WS-8 | SOM `tariff_zone` startup assertion + mismatch gauge | hub `a705317` |
| WS-9 | Alive-but-deaf watchdog; paho OrderedMemoryStore + WriteTimeout; journal-drop/cmdDropped metrics | hub `6a0c534` |
| Docs | ~22 stale status headers normalized, index rows, AD-014/016, backlog de-dupe, 2.6k lines clutter untracked | csip `cea80d3` |

## 3. The flip (R4 endgame)

**FIX-F built the machinery that didn't exist.** Before this program the flip
was one global `constraint_shadow` boolean and the wrapper was hard-wired
observe-only. FIX-F added: per-constraint `off|shadow|active` config
(`constraint_modes`, absolute back-compat), per-axis single-author composition
(legacy writes to an active axis dropped + counted), authorship threaded through
the arbiter, and a whole-plan legacy fallback if the candidate panics.

**Gate discipline.** The "≥1-week clean-shadow soak" was cut to 24h at the
owner's direction, justified by the 500+ prior FAST scenario-runs; the report is
explicit that the standing 05 §12 cooling-off was compressed. The "~0 divergence"
gate was **unsatisfiable as written** (the audit was right) — rewritten as the
per-axis carve-out from `notes/TASK-063-seam-review.md §3` (compliance axes 0
off- and on-cap; only the characterized economics evse-current/battery on-cap
residual permitted; safety path + panic-latch 0), made measurable by the new
per-axis metrics and a soak recorder + gate evaluator
(`scripts/shadow-soak-recorder.sh`, `shadow-soak-gate.py`).

**24h soak: GATE PASS.** 1443 divergence events, every one classified — economics
residuals + an author-gated battery-safety cascade artifact (see §4); zero
unexplained compliance-axis events, zero Tier-1 safety divergences, zero panics.

**Per-axis flips, each full-FAST-campaign gated (05 §12), one at a time:**

| Flip | Modes | FAST campaign |
|---|---|---|
| 1 | export active | 43P/18D/**0F/0B** |
| 2 | + gen | 43P/18D/**0F/0B**/1I |
| 3 | + import | 42P/19D/**0F/0B**/1I |
| 4 | + economics + battery-safety (all five) | 43P/18D/**0F/0B**/1I |

Post-flip-4 shadow divergence flatlined to 0 (the harness has nothing left to
disagree about — the candidate is now authoritative). The 1 INCONCLUSIVE every
cycle is `netem-jitter-evse` (single global `LEXA_SSH_USER=root` can't reach
`dmitri@ev-pi` — known harness limitation).

## 4. What the gates caught (the program's discipline working)

The compressed soak + STOCK gate each surfaced a real issue the FAST-only path
would have shipped. All root-caused, none waved through:

1. **Battery-safety shadow-cascade (soak).** The candidate's Tier-1 safety
   demanded idle+disconnect at 62% SOC while legacy TOU-discharged. Proven a
   **shadow artifact** (the wrong-direction debounce reacting to legacy-actuated
   feedback contradicting the candidate's own characterized economics-residual
   charge proposal) — never trips under self-consistent post-flip feedback
   (`TestBatterySafety_SelfConsistentFeedbackNeverTrips`, hub `5a846b5`). Closed
   the 062/063 parity-test gap (no test had composed on-cap + TOU + EVSE through
   the real Wrapper). Author-gated carve-out in the gate.
2. **Legacy export-ceiling slew (STOCK).** `applyExportLimitRule` slew-limited in
   watts-**per-tick**, not wall-clock — 5× slower re-tightening at STOCK's 15s
   tick. Same bug class TASK-036 fixed for expiry. **The candidate constraint
   path was already correct** — legacy was the straggler. Fixed (hub `582ece4`).
3. **Harness malform-arming (STOCK).** `armAfterAdoption` fired the malformed
   resource on the ever-present 5kW bench default before the scenario's 0W event
   was adopted (20s discovery at STOCK), so the hub held the *default* → false
   FAIL. Fixed with target-specific arming (`armAfterCapAdopted`, csip `647a04e`).
   **A live manual hold-proof settled it definitively:** the active stack holds
   the 0W export cap under `huge_activepower` at STOCK — source stays `event`,
   solar ceiling driven to 0.35, 0W output. The hub was correct all along.
4. **MRID parity (review catch).** FIX-F's WS-4b delivery stamped MRID on legacy
   commands but not the candidate Stack's — a composed/appended candidate command
   would have regressed to `MRID:""` and lost its device-evidence path post-flip.
   Caught in review, fixed + tested (hub `277d590`).

## 5. Residual (characterized, flip-independent, out of refactor scope)

At STOCK cadence, `malform-huge-activepower` and `wan-outage-hold` are **marginal**
(fail ~1/3 depending on roll). Determination — grounded in the manual hold-proof
and the instrumented reconciler journal, not inference:
- **Not a hub/flip defect.** The active stack holds every cap correctly at STOCK
  (direct observation). The flip introduces **zero regression** — both scenarios
  fail *identically on the legacy cascade* at STOCK (verified, repeatably).
- **Root cause = oracle-window calibration.** The scenarios count breach samples
  during STOCK's ~20s discovery-adoption + solar-ramp latency — a window where the
  hub physically cannot enforce a control it has not yet walked — against windows
  calibrated for FAST's ~5s latency. This dev-kit bench was never STOCK-baselined
  (the 2026-07-04 STOCK baseline ran on the retired Pi hub; CLAUDE.md notes the
  scenario margins are FAST-tuned).
- **Follow-up (harness, not refactor):** gate each scenario's breach window on
  target-cap adoption (don't count the pre-adoption lag), then re-baseline STOCK
  on the dev kit. Tracked for the QA-harness pass.

## 6. Branch/deploy state

- **lexa-hub `refactor-endgame`** (worktree `~/projects/lexa-hub-wt/endgame`, tip
  `e19dedf`): the complete refactor hub deliverable, forked from the last
  pre-extension point (`f1e0d67`). Deployed to the bench hub (active, all five).
  The concurrent extension program owns `main`; it merges `refactor-endgame` and
  rebases the extension on the flipped world when ready. The extension's own
  uncommitted work was preserved verbatim on `extension-wip @65815f7`.
- **csip-tls-test `main`** (tip `647a04e`): all QA/harness/doc work, deployed
  (dashboard live).
- **Bench:** dev-kit hub `69.0.0.2`, constraint stack **active on all axes**,
  FAST resting timing. `bench-up.sh --stock` before demos as always.

## 7. Deferred remainder (gates the tag, not the refactor)

- **TASK-065** (multi-device: 2nd inverter/EVSE, breach-list) — NOT STARTED;
  hard-blocks TASK-066.
- **TASK-066** (delete the suppressed legacy cascade) — blocked on 065. Until
  then the stack is authoritative and the cascade is dead weight, observably
  suppressed. `optimizer.go` stays until 066; the god-file ◆ box stays OPEN
  (honest, per WS-5's AD).
- **STOCK oracle recalibration** on the dev kit (§5).
- Time/hardware/human: 30-day soak, cert-churn 24h soak, vendor golden fixtures
  (TASK-075), hosted `lexa-proto`, branch protection + PAT secrets.
- Deferred gofmt/CI cosmetics: golangci-lint runs `only-new-issues` over a
  ~130-issue baseline (mostly deferred-Close errcheck) — a cleanup PR, not a gate.
