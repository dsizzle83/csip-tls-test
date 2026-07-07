# LEXA DERMS V1.0 Refactor — HANDOFF

*Written 2026-07-06 by the Principal (Fable) for the successor model. Read
this first, then `docs/refactor/00_MASTER_INDEX.md`. This is the "resume
without prior context" document.*

## 1. Where the program is

The program executes `ARCHITECTURE_REVIEW.MD` via 82 task files in
`docs/refactor/tasks/`. Milestones M0–M2 are **complete and merged**; M3
(P3+P4) is ~95%; M4 (P5 optimizer split) has its **architecture proven in
shadow**; M5 (P6) has most implementables merged. ~70 of 82 tasks done.

**Three repos** (all on `main`, keep them synced):
- `~/projects/lexa-hub` — the product. Hosted: `origin` (GitHub dsizzle83).
- `~/projects/csip-tls-test` — test bench + Mayhem QA. Hosted: `origin`.
- `~/projects/lexa-proto` — shared codec (sunspec/ocppserver/csipmodel/
  derbase). **UNHOSTED by design** (local-only; consumers vendor it +
  pin via `proto.pin`). Hosting it is a human task (AD-003(f)).

## 2. What "done" means here — the crown-jewel facts

- **Reconciler (R1/M2):** all 3 device classes (battery/solar/EVSE) run
  under one Device Reconciler on the bench; 4 convergence mechanisms →
  1; legacy machinery deleted (−957 LOC). 10-cycle soak 0.1 FAIL/cyc.
- **Constraint controller (R4/P5):** the compliance layer (export/import/
  gen constraints) reproduces the legacy cascade at **0 shadow divergence**
  on hardware. IT IS IN SHADOW — `constraint_shadow=true`, legacy cascade
  is still authoritative. See §4 for how to make it live.
- **Utility time (W4):** one `internal/utilitytime` owner. **Shared codec
  (W3):** one `lexa-proto`, CI-pinned. **Security (W7):** broker ACLs +
  API bearer-token + OCPP SP2 all implemented (SP2 flip runbook in
  BENCH.md). **Persistence (W5):** journal + breach snapshot.

## 3. The RESIDUAL — what is NOT done and exactly why (with runbooks)

### Genuinely blocked (external/time — a bigger model cannot shortcut these)
- **Constraint shadow→active flips + TASK-066 (delete cascade):** the
  constraint controller is proven in shadow but must NOT be flipped to
  authoritative without the ≥1-week clean-shadow soak (03 §P5). RUNBOOK:
  keep `constraint_shadow=true` on the bench for ≥1 week, run daily
  campaigns, confirm `lexa_constraint_shadow_divergence_total` stays ~0
  (triage the one known latent export-axis boundary divergence 061 found);
  THEN set the constraint stack authoritative per each constraint (config
  flip per axis, FIX-F single-author suppression must land first — see
  TASK-060/062/063 notes), run a full + STOCK campaign per flip; only
  after all axes flip clean does TASK-066 delete the legacy cascade.
- **TASK-075 golden vendor fixtures:** needs ≥2 real vendor inverters +
  1 EVSE on the bench to capture byte-exact register images. Cannot be
  fabricated. Order hardware; capture procedure is in TASK-075.
- **TASK-078 30-day soak:** 30 days wall-clock. Rig + runbook exist
  (`scripts/cert-churn-soak.sh` sibling; TASK-078). Start it; report at 30d.
- **TASK-073 cert-rotation 24h churn soak:** code done + `scripts/
  cert-churn-soak.sh`; run the 24h churn on the bench watching for
  segfault/fd-leak (§8.6).

### Implementable — status at handoff
- **062 session consolidation: DONE** (all guard state in typed constraint
  Sessions incl. BatterySafetySession w/ Evaluate + arbiter-bypassing
  EvaluateFast; DefaultOptimizer has no undocumented inter-tick state).
  Left ≤1-tick wrong-direction lag for 063 (economic-tick reads this-tick
  plan; pre-arbitration constraint reads last-committed — reserve/critical
  paths are bit-faithful). SHADOW.
- **067 engine consolidation: DONE** (5 mutexes → 1 engineState, single
  writer, atomic pointers + bounded cmdCh; engine_test.go unchanged, -race
  clean; Wake/EvaluateSafety preserved). RADIOACTIVE — needs the FAST
  campaign gate before it's trusted live (batched at the next bench wave).
- **071 poll-rate: DONE** (honor advertised pollRate in STOCK, FAST bench
  keeps override; AD-014). Backlog refinement: per-class scheduling (honor
  mode currently uses the most-conservative class, ~900s — a control-heavy
  utility may want DERControlList's faster rate; the original pollsched.go
  design does this).
- **076 scenarios-as-data engine: DONE** (spec_v:1 JSON + compiler + oracle
  registry; scenarios addable WITHOUT a Go rebuild — this is your tool for
  adding QA cheaply). 077 migrates the ~60 Go scenarios to specs (next).
- **063 economic-layer isolation: DONE + MERGED.** Full constraint stack
  (safety+compliance+economics) now runs in the SHADOW wrapper; economics
  are PointDemand proposals clamped under compliance by a STRUCTURAL arbiter
  tier-fold (fixed a real 058 bug: economics could override a compliance cap
  via global-min). Golden full-stack shadow parity = 0 divergence OFF-CAP.
  Closed 062's ≤1-tick safety lag (post-arbitration safety). ON-CAP
  divergence characterized in `docs/refactor/notes/TASK-063-seam-review.md`
  → owned by 064. SHADOW (legacy cascade still authoritative).
- **064 constants→plant: DONE + MERGED.** Bench constants → 057 plant-model
  params (identical bench behavior; `docs/refactor/notes/TASK-064-plant-
  parameters.md` has the swap map). evSafeCount now has ONE owner
  (EVImportCooldown). Off-cap 0 divergence, compliance ceiling bit-faithful
  on-cap; the residual (economics EV-current axis) is irreducible in a
  layered design and vanishes at the flip. **STOCK caveat:** the inverter
  ramp is now per-wall-second (bit-identical at FAST 3s, cadence-correct at
  STOCK 15s) — needs a STOCK spot-check at the flip gate.

**R4 CONSTRAINT CONTROLLER: architecturally COMPLETE in shadow (058–064).**
Safety+compliance+economics reproduce the live cascade at 0/bit-faithful
divergence. What remains is ONLY the soak-gated flip + 065 (multi-device)
+ 066 (delete cascade). The god-file (`optimizer.go` ~2289 lines) stays
LIVE until the flip — that release-checklist box is correctly still OPEN.
- **065 multi-device: NOT STARTED** — 2nd sim instance (modsim/evsim on a
  free port), breach-list + per-device sessions, nameplate-share split.
- **077 scenario migration: NOT STARTED** — express the ~60 Go scenarios as
  specs (076's format), register remaining oracles, delete the Go twins.

**How to finish the constraint stack (the R4 endgame for a successor):**
062+063+064 complete the SHADOW controller; then the flip sequence in §3
(soak → per-axis active flip → 066 delete cascade) makes it live. Do NOT
flip without the soak. The 057 adaptive detection window is what removes
the battery-charge-disabled boundary flake once active.

## 4. HOW TO WORK HERE — process discipline (learned the hard way)

1. **ONE agent per repo working tree.** A bench/deploy agent owns the
   MAIN checkout of a repo exclusively; every other concurrent agent uses
   `git worktree add`. Two agents in one checkout WILL corrupt each other
   (happened twice; recovered both times, but don't).
2. **Be ON `main` before merging to main.** Committing merges while the
   checkout is on a `task/*` branch leaves the local `main` ref behind
   `origin/main` (pushes go to remote main via `HEAD:main` but local main
   stagnates). Always `git checkout main`, verify `git branch --show-current`,
   then merge. Push with `git push origin HEAD:main` and CHECK the output
   (don't `-q ... 2>/dev/null` — refusals matter).
3. **Merge the agent's `task/NNN-*` branch, NOT `worktree-agent-<id>`.**
   The auto-created worktree branch sits at the base commit; the agent's
   work is on `task/NNN`. Verify content landed after merging.
4. **Never `rm -rf` a shared worktree parent** (e.g. `~/projects/lexa-hub-wt`)
   — it deletes other agents' worktrees. Use `git worktree remove <exact-path>`.
5. **Union-merge conflicts drop braces.** After resolving a `<<<<<<<`
   conflict by stripping markers, ALWAYS build — a lost `}` compiles-fails.
6. **QA gating (per deadline amendment, 05 §12):** full 51-scenario campaign
   for reconciler flips / legacy deletion / optimizer-constraint FLIPS
   (active, not shadow) / phase exits. Everything else: unit tests + a
   targeted `--only` subset; batch a subset campaign at wave boundaries.
   Shadow/additive/unwired code needs NO campaign (cite 05 §12 exception).
7. **Agents stall on monitor-and-exit.** If an agent arms a Monitor/
   background wait and ends its turn, it won't reliably resume — re-send it
   a "poll synchronously in a bounded foreground loop" message. Every
   long-campaign agent hit this.

## 5. BENCH — state + gotchas (full topology: docs/BENCH.md)

- hub Pi 69.0.0.1 (root, passwordless sudo, ssh dmitri@); sims .10/.11/.12/
  .14; desktop 69.0.0.20 (gridsim :11111/:11112, dashboard :8080).
- Current state: FAST (engine 3s/poll 2s), all reconcilers ACTIVE,
  `constraint_shadow=true`, broker ACL + API auth ON, mqttproxy on :1882.
- **`deploy-hub-pi.sh` RESETS timing to STOCK + overwrites configs +
  resets metrics_addr/reconciler/mqttproxy Pi-side enables** — after ANY
  hub deploy re-run `scripts/hub-replay-tune.sh fast` AND re-set the
  reconciler/constraint_shadow/metrics_addr configs. The security flips
  are opt-in flags: `--enable-api-auth --enable-mqtt-acl [--enable-ocpp-sp2]`.
- **mosquitto passwd MUST be `root:mosquitto 0640`** (the privilege-dropped
  broker reads it) — NOT root:root 0600 (I got this wrong once; strace-proven).
- **ACL'd broker DROPS unauthorized publishes silently (PUBACK still
  arrives!)** — verify delivery by SUBSCRIPTION, never publish success.
  `lexa/desired/*` grants are per-class in mosquitto-lexa.acl.
- `csip-dashboard` unit execs `bin/dashboard` — `go build -o bin/dashboard
  ./cmd/dashboard` before restarting it.
- QA baselines to defend: FAST ~34P/16D/0F/0B; STOCK M0 0.8F/cyc; M2 soak
  0.1F/cyc. `battery-charge-disabled` is a known ~1/10 oracle-boundary
  flake (export-detection latency; designed out by 057 plant model + the
  R4 adaptive window when the constraints flip active — NOT a regression).

## 6. Human action items (need credentials/hardware I don't have)
- Enable GitHub branch protection on both repos (AD-012 has the command).
- Create `LEXA_HUB_RO_TOKEN` + `CSIP_TLS_TEST_RO_TOKEN` PAT secrets for the
  cross-repo CI lockstep/pin gates.
- Host `dsizzle83/lexa-proto` + run the hosted-flip checklist (AD-003(f)).
- Order vendor hardware for TASK-075.

## 7. Key decisions (docs/refactor/02_ARCHITECTURE_DECISIONS.md)
AD-001 distributed topology · AD-002 reconciler · AD-003 shared module +
(e) vendoring + (f) hosted-flip + (g/h) fork disposal · AD-004 utilitytime
· AD-005 journal · AD-006 bus envelope · AD-007 constraint controller +
plant model · AD-008 security · AD-009 keep+harden httpwire (chunked
added; net.Conn shim backlogged) · AD-010 curve functions DE-SCOPED for
V1.0 · AD-012 GitHub hosting · AD-013 desired-state schema.
