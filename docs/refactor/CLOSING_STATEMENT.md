# LEXA DERMS V1.0 Refactor — Closing Statement

*2026-07-06. Written at the end of the intensive execution phase, for the
teammates who pick this up next. Companion to `HANDOFF.md` (the operational
"how to resume" guide) — this is the narrative: what we did, what we learned,
and where to go. Read both.*

---

## 1. What was accomplished

We took the codebase from the state the architecture review graded **C+ as a
product / B+ as an effort** to a **validated V1.0 release candidate**. 78 of
82 planned tasks are done and merged across the two hosted repos (`lexa-hub`,
`csip-tls-test`), both now single-`main` and pushed to GitHub.

The review named seven weaknesses (W1–W7) and one #1 critical refactor. All
seven are addressed; the #1 is proven on hardware:

- **W2 / R1 — State convergence (the #1 item): DONE, live on the bench.**
  Four uncoordinated convergence mechanisms collapsed into one per-device
  Reconciler across battery, solar, and EVSE. Legacy machinery deleted
  (−957 LOC). 10-cycle soak: 0.10 FAIL/cycle. This was the review's single
  biggest structural risk and it is retired.

- **W1 / R4 — The 2,289-line optimizer: SPLIT and PROVEN in shadow.** A
  layered constraint controller (safety → compliance → economics, with a
  bounds-intersection arbiter where narrowing is structural) runs alongside
  the legacy cascade and reproduces it at **0 divergence off-cap, bit-faithful
  compliance on-cap**, confirmed on hardware. It is NOT yet the live control
  path (see §3). The economics-below-compliance guarantee is enforced by
  construction — building it caught a real arbiter bug where economics could
  override a compliance cap via a global-min.

- **W3 — Codec divergence: one shared module** (`lexa-proto`), CI-pinned.
- **W4 — Time handling: one owner** (`utilitytime`), monotonic-anchored.
- **W5 — Persistence: journal + breach snapshot**, restart-durable.
- **W6 — Operational blindness: watchdogs (wedge-proven ×6), metrics ×6,
  structured logging, heartbeats.**
- **W7 — Security: broker ACLs, API bearer-token, OCPP Security Profile 2
  (live-flip-tested), cert monitoring + rotation, 0 dependency vulns, fuzzing
  in CI.**

We also ran a full **V1.0 release gate on real hardware** (TASK-081): a clean
campaign (0 unexplained FAIL), OCPP SP2 flipped live and rolled back,
conformance 3/3 CSIP layers + 50/50 Modbus. It found two real bugs — lexa-api
dying permanently on a systemd `Requires=mosquitto` stop-propagation, and a
missing journal `StateDirectory` — **both fixed and re-confirmed on the bench.**

## 2. What was learned

**Technical:**

- **Shadow mode is the right way to de-risk a control-core rewrite.** Running
  the new constraint controller alongside the proven cascade, diffing outputs,
  and discarding the candidate's result gave us complete validation evidence
  at zero risk to physical devices. The "0 divergence off-cap" number is only
  meaningful *because* it was gathered under real fault injection with no way
  to hurt the hardware. Do this for any future control-path change.

- **A layered controller cannot bit-match a cascade that interleaves state,
  and that's OK.** The one residual on-cap divergence (the EV-current axis)
  comes from the cascade mutating shared surplus *between* its economic rules
  — something a clean layered design structurally can't see. We chose to
  document it as irreducible rather than contort the architecture to fake
  parity. It vanishes at the flip. **Honest characterization beat forced
  fidelity.**

- **Bench physics baked into product constants is a real liability (D6).**
  Converting the calibrated constants (`socStepEstimate`, ramp limits, filter
  alpha) into an explicit plant model made the assumptions visible and testable
  — and surfaced that one "20× demo" value was a deliberate conservative
  overestimate, not a bug.

- **The self-confirmation blind spot is the deepest unknown.** Our sims share
  codec lineage with the product, so a register-map misunderstanding is
  bilaterally invisible — green on every test, wrong on real hardware. No
  amount of sim testing closes this. Only golden vendor fixtures (real
  inverters/EVSEs) do. Respect this when reading any "conformance passed."

**Process:**

- **One agent per working tree, always.** Concurrent work must use
  `git worktree`; two writers in one checkout corrupt each other. We proved
  this the hard way (recovered both times, but don't).
- **Be on `main` before merging to main**, and push with
  `git push origin HEAD:main` while *reading* the output — silenced pushes
  hide refusals, and merging from a `task/*` branch strands the local `main`
  ref behind origin.
- **Never `rm -rf` a shared worktree parent** — it deletes other agents' live
  worktrees.
- **After resolving any union-merge conflict, build.** Dropped braces compile-
  fail silently in a text merge.
- **Batch the expensive QA.** A full 51-scenario hardware campaign per task is
  wasteful; unit tests + a targeted subset per change, with a full campaign at
  wave boundaries, is the right cadence. Reserve the full gate for the
  radioactive zone (control-path flips, legacy deletion).

## 3. Where to go next

The remaining work is real but **bounded, and almost entirely gated on time,
hardware, and third parties — not on undone engineering.** In priority order:

1. **The constraint-controller flip (the headline next step).** Keep
   `constraint_shadow=true`, run the bench for **≥1 week**, confirm
   `lexa_constraint_shadow_divergence_total` stays ~0 off-cap (the on-cap
   EV-axis residual is understood). *Then* flip each axis to authoritative
   (compliance first), run a full + STOCK campaign per flip, and finally run
   TASK-066 to delete the legacy cascade — which is what closes the "god-file"
   box (`optimizer.go` is still ~2,289 LOC and LIVE until then). **Do not flip
   without the soak** — it's a safety gate, not a formality. Full runbook in
   `HANDOFF.md` §3.
   - *Recommended variant:* run the shadow in the **field pilot** on real
     hardware and flip only after real-world divergence data. Lower risk than
     a bench-only soak.

2. **Golden vendor fixtures (TASK-075).** Get ≥2 real inverters + 1 EVSE on
   the bench, capture byte-exact register images, and validate against them.
   This is the only thing that closes the self-confirmation blind spot — treat
   it as a top priority, not a checklist item.

3. **Multi-device (TASK-065).** Bring up a 2nd sim instance; validate the
   single-device assumptions (§8.5) against a fleet of two before a real one.

4. **30-day soak (TASK-078)** for fd/goroutine/RSS leaks over weeks (the
   replay is clock-warped ~20h; it is not a substitute).

5. **Fix the ~40s stale-cap export window** the power-cut scenario found
   (SAFETY held, but it is a real compliance breach a utility meter records —
   tighten the retained-control staleness bound / rewalk latency). Do this
   before any field pilot.

6. **The human/commercial gates:** GitHub branch protection + the cross-repo
   CI PAT secrets; **host `lexa-proto`** (see the ⚠ below); third-party
   certification (IEEE 1547.1 / CSIP test lab); the field pilot itself.

**Grade today: B+ product / A− engineering effort.** Ready for a *controlled
single-site pilot* once §3.1–3.3 land; ready for *fleet deployment* only after
the pilot + cert lab + accumulated field hours. The gap from here is the
gap that only real devices and real time can close — which is exactly where a
DERMS should spend its remaining risk budget.

---

## ⚠ One thing that needs a human soon: `lexa-proto` is unhosted

The shared codec module (`~/projects/lexa-proto`) is **local-only by design
(AD-003(f))** — it has no GitHub remote. Its *code* is safe (vendored into
both repos under `vendor/` and pinned by `proto.pin`), but its *git history
lives on this machine only*. A `git bundle` backup has been left at
`docs/refactor/artifacts/lexa-proto.bundle` in this repo as a stopgap. Please
create `dsizzle83/lexa-proto` and run the hosted-flip checklist (AD-003(f))
early — until then, this machine is a single point of failure for the module's
history.

---

*Start here: this file → `HANDOFF.md` → `00_MASTER_INDEX.md`. The bench is
left FAST, reconcilers active, `constraint_shadow=true`, auth+ACL on, all 7
services up. Thank you — it was a genuine pleasure to build this.*
